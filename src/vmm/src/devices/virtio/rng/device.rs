// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ops::Deref;
use std::sync::Arc;

use aws_lc_rs::rand;
use vm_memory::GuestMemoryError;
use vmm_sys_util::eventfd::EventFd;

use super::metrics::METRICS;
use super::{RNG_NUM_QUEUES, RNG_QUEUE};
use crate::devices::DeviceError;
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::iov_deque::IovDequeError;
use crate::devices::virtio::iovec::IoVecBufferMut;
use crate::devices::virtio::queue::{FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::impl_device_type;
use crate::logger::{IncMetric, debug, error};
use crate::rate_limiter::{RateLimiter, TokenType};
use crate::vstate::memory::GuestMemoryMmap;

pub const ENTROPY_DEV_ID: &str = "rng";

/// Maximum number of bytes `handle_one()` will serve per request.
///
/// Overlapping descriptors within a single chain can cause `buffer.len()` to
/// exceed the amount of distinct guest memory actually backing the request.
/// Capping the per-request allocation to 64 KiB keeps host memory usage
/// bounded regardless of how the descriptor chain is constructed.
const MAX_ENTROPY_BYTES: u32 = 64 * 1024;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EntropyError {
    /// Error while handling an Event file descriptor: {0}
    EventFd(#[from] io::Error),
    /// Bad guest memory buffer: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Could not get random bytes: {0}
    Random(#[from] aws_lc_rs::error::Unspecified),
    /// Underlying IovDeque error: {0}
    IovDeque(#[from] IovDequeError),
}

#[derive(Debug)]
pub struct Entropy {
    // VirtIO fields
    avail_features: u64,
    acked_features: u64,
    activate_event: EventFd,

    // Transport fields
    device_state: DeviceState,
    pub(crate) queues: Vec<Queue>,
    queue_events: Vec<EventFd>,

    // Device specific fields
    rate_limiter: RateLimiter,

    buffer: IoVecBufferMut,
}

impl Entropy {
    pub fn new(rate_limiter: RateLimiter) -> Result<Self, EntropyError> {
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); RNG_NUM_QUEUES];
        Self::new_with_queues(queues, rate_limiter)
    }

    pub fn new_with_queues(
        queues: Vec<Queue>,
        rate_limiter: RateLimiter,
    ) -> Result<Self, EntropyError> {
        let activate_event = EventFd::new(libc::EFD_NONBLOCK)?;
        let queue_events = (0..RNG_NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<Result<Vec<EventFd>, io::Error>>()?;

        Ok(Self {
            avail_features: 1 << VIRTIO_F_VERSION_1,
            acked_features: 0u64,
            activate_event,
            device_state: DeviceState::Inactive,
            queues,
            queue_events,
            rate_limiter,
            buffer: IoVecBufferMut::new()?,
        })
    }

    fn signal_used_queue(&self) -> Result<(), DeviceError> {
        self.interrupt_trigger()
            .trigger(VirtioInterruptType::Queue(RNG_QUEUE.try_into().unwrap()))
            .map_err(DeviceError::FailedSignalingIrq)
    }

    fn rate_limit_request(&mut self, bytes: u64) -> bool {
        if !self.rate_limiter.consume(1, TokenType::Ops) {
            return false;
        }

        if !self.rate_limiter.consume(bytes, TokenType::Bytes) {
            self.rate_limiter.manual_replenish(1, TokenType::Ops);
            return false;
        }

        true
    }

    fn rate_limit_replenish_request(rate_limiter: &mut RateLimiter, bytes: u64) {
        rate_limiter.manual_replenish(1, TokenType::Ops);
        rate_limiter.manual_replenish(bytes, TokenType::Bytes);
    }

    fn handle_one(&mut self) -> Result<u32, EntropyError> {
        // If guest provided us with an empty buffer just return directly
        if self.buffer.is_empty() {
            return Ok(0);
        }

        // Cap the number of bytes we actually generate so that the host-side
        // allocation stays bounded even when buffer.len() is inflated by
        // overlapping descriptors in the chain.
        let len = std::cmp::min(self.buffer.len(), MAX_ENTROPY_BYTES);

        let mut rand_bytes = vec![0; len as usize];
        rand::fill(&mut rand_bytes).inspect_err(|_| {
            METRICS.host_rng_fails.inc();
        })?;

        // It is ok to unwrap here. We are writing `len` bytes at offset 0.
        self.buffer.write_all_volatile_at(&rand_bytes, 0).unwrap();
        Ok(len)
    }

    fn process_entropy_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let mut used_any = false;
        while let Some(desc) = self.queues[RNG_QUEUE].pop()? {
            // This is safe since we checked in the event handler that the device is activated.
            let mem = &self.device_state.active_state().unwrap().mem;
            let index = desc.index;
            METRICS.entropy_event_count.inc();

            // SAFETY: This descriptor chain points to a single `DescriptorChain` memory buffer,
            // no other `IoVecBufferMut` object points to the same `DescriptorChain` at the same
            // time and we clear the `iovec` after we process the request.
            let bytes = match unsafe { self.buffer.load_descriptor_chain(mem, desc) } {
                Ok(()) => {
                    debug!(
                        "entropy: guest request for {} bytes of entropy",
                        self.buffer.len()
                    );

                    // Check for available rate limiting budget.
                    // If not enough budget is available, leave the request descriptor in the queue
                    // to handle once we do have budget.
                    if !self.rate_limit_request(u64::from(self.buffer.len())) {
                        debug!("entropy: throttling entropy queue");
                        METRICS.entropy_rate_limiter_throttled.inc();
                        self.queues[RNG_QUEUE].undo_pop();
                        break;
                    }

                    self.handle_one().unwrap_or_else(|err| {
                        error!("entropy: {err}");
                        METRICS.entropy_event_fails.inc();
                        0
                    })
                }
                Err(err) => {
                    error!("entropy: Could not parse descriptor chain: {err}");
                    METRICS.entropy_event_fails.inc();
                    0
                }
            };

            match self.queues[RNG_QUEUE].add_used(index, bytes) {
                Ok(_) => {
                    used_any = true;
                    METRICS.entropy_bytes.add(bytes.into());
                }
                Err(err) => {
                    error!("entropy: Could not add used descriptor to queue: {err}");
                    Self::rate_limit_replenish_request(&mut self.rate_limiter, bytes.into());
                    METRICS.entropy_event_fails.inc();
                    // If we are not able to add a buffer to the used queue, something
                    // is probably seriously wrong, so just stop processing additional
                    // buffers
                    break;
                }
            }
        }
        self.queues[RNG_QUEUE].advance_used_ring_idx();

        if used_any {
            self.signal_used_queue().unwrap_or_else(|err| {
                error!("entropy: {err:?}");
                METRICS.entropy_event_fails.inc()
            });
        }

        Ok(())
    }

    pub(crate) fn process_entropy_queue_event(&mut self) {
        if let Err(err) = self.queue_events[RNG_QUEUE].read() {
            error!("Failed to read entropy queue event: {err}");
            METRICS.entropy_event_fails.inc();
        } else if !self.rate_limiter.is_blocked() {
            // We are not throttled, handle the entropy queue
            self.process_entropy_queue().unwrap()
        } else {
            METRICS.rate_limiter_event_count.inc();
        }
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        METRICS.rate_limiter_event_count.inc();
        match self.rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to process entropy requests.
                self.process_entropy_queue().unwrap()
            }
            Err(err) => {
                error!("entropy: Failed to handle rate-limiter event: {err:?}");
                METRICS.entropy_event_fails.inc();
            }
        }
    }

    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        self.process_entropy_queue()
    }

    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    pub(crate) fn set_avail_features(&mut self, features: u64) {
        self.avail_features = features;
    }

    pub(crate) fn set_acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    pub(crate) fn set_activated(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) {
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
    }

    pub(crate) fn activate_event(&self) -> &EventFd {
        &self.activate_event
    }
}

impl VirtioDevice for Entropy {
    impl_device_type!(VirtioDeviceType::Rng);

    fn id(&self) -> &str {
        ENTROPY_DEV_ID
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn config_as_bytes(&self) -> &[u8] {
        &[]
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        assert!(!self.is_activated());

        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        self.activate_event.write(1).map_err(|_| {
            METRICS.activate_fails.inc();
            ActivateError::EventFd
        })?;
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }
}
