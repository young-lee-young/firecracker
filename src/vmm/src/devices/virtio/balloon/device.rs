// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use utils::time::TimerFd;
use vmm_sys_util::eventfd::EventFd;

use super::super::ActivateError;
use super::super::device::{DeviceState, VirtioDevice};
use super::super::queue::Queue;
use super::metrics::METRICS;
use super::util::compact_page_frame_numbers;
use super::{
    BALLOON_DEV_ID, BALLOON_MIN_NUM_QUEUES, BALLOON_QUEUE_SIZE, DEFLATE_INDEX, FREE_PAGE_HINT_DONE,
    FREE_PAGE_HINT_STOP, INFLATE_INDEX, MAX_PAGE_COMPACT_BUFFER, MAX_PAGES_IN_DESC,
    MIB_TO_4K_PAGES, STATS_INDEX, VIRTIO_BALLOON_F_DEFLATE_ON_OOM,
    VIRTIO_BALLOON_F_FREE_PAGE_HINTING, VIRTIO_BALLOON_F_FREE_PAGE_REPORTING,
    VIRTIO_BALLOON_F_STATS_VQ, VIRTIO_BALLOON_PFN_SHIFT, VIRTIO_BALLOON_S_ALLOC_STALL,
    VIRTIO_BALLOON_S_ASYNC_RECLAIM, VIRTIO_BALLOON_S_ASYNC_SCAN, VIRTIO_BALLOON_S_AVAIL,
    VIRTIO_BALLOON_S_CACHES, VIRTIO_BALLOON_S_DIRECT_RECLAIM, VIRTIO_BALLOON_S_DIRECT_SCAN,
    VIRTIO_BALLOON_S_HTLB_PGALLOC, VIRTIO_BALLOON_S_HTLB_PGFAIL, VIRTIO_BALLOON_S_MAJFLT,
    VIRTIO_BALLOON_S_MEMFREE, VIRTIO_BALLOON_S_MEMTOT, VIRTIO_BALLOON_S_MINFLT,
    VIRTIO_BALLOON_S_OOM_KILL, VIRTIO_BALLOON_S_SWAP_IN, VIRTIO_BALLOON_S_SWAP_OUT,
};
use crate::devices::virtio::balloon::BalloonError;
use crate::devices::virtio::device::{ActiveState, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::queue::InvalidAvailIdx;
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{IncMetric, debug, error, info, log_dev_preview_warning, warn};
use crate::utils::u64_to_usize;
use crate::vstate::memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemoryExtension, GuestMemoryMmap,
};
use crate::{impl_device_type, mem_size_mib};

const SIZE_OF_U32: usize = std::mem::size_of::<u32>();
const SIZE_OF_STAT: usize = std::mem::size_of::<BalloonStat>();
/// Upper bound on the number of stats tags a guest may report.
/// The VirtIO spec currently defines 16, but newer kernel versions can
/// add more (e.g. Linux 6.12 added several, see 74c025c5d7e4). We use a
/// generous limit that still bounds computation without breaking on future
/// kernels.
const MAX_STATS_TAGS: u32 = 256;
/// Maximum valid stats descriptor length in bytes.
/// Descriptors exceeding this are rejected to prevent unbounded iteration.
#[allow(clippy::cast_possible_truncation)]
const MAX_STATS_DESC_LEN: u32 = MAX_STATS_TAGS * std::mem::size_of::<BalloonStat>() as u32;

fn mib_to_pages(amount_mib: u32) -> Result<u32, BalloonError> {
    amount_mib
        .checked_mul(MIB_TO_4K_PAGES)
        .ok_or(BalloonError::TooMuchMemoryRequested(
            u32::MAX / MIB_TO_4K_PAGES,
        ))
}

fn pages_to_mib(amount_pages: u32) -> u32 {
    amount_pages / MIB_TO_4K_PAGES
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct ConfigSpace {
    pub num_pages: u32,
    pub actual_pages: u32,
    pub free_page_hint_cmd_id: u32,
}

// SAFETY: Safe because ConfigSpace only contains plain data.
unsafe impl ByteValued for ConfigSpace {}

/// Holds state of the free page hinting run
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct HintingState {
    /// The command requested by us. Set to STOP by default.
    pub host_cmd: u32,
    /// The last command supplied by guest.
    pub last_cmd_id: u32,
    /// The command supplied by guest.
    pub guest_cmd: Option<u32>,
    /// Whether or not to automatically ack on STOP.
    pub acknowledge_on_finish: bool,
}

/// By default hinting will ack on stop
fn default_ack_on_stop() -> bool {
    true
}

/// Command received from the API to start a hinting run
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct StartHintingCmd {
    /// If we should automatically acknowledge end of the run after stop.
    #[serde(default = "default_ack_on_stop")]
    pub acknowledge_on_stop: bool,
}

impl Default for StartHintingCmd {
    fn default() -> Self {
        Self {
            acknowledge_on_stop: true,
        }
    }
}

/// Returned to the API for get hinting status
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default, Serialize)]
pub struct HintingStatus {
    /// The command requested by us. Set to STOP by default.
    pub host_cmd: u32,
    /// The command supplied by guest.
    pub guest_cmd: Option<u32>,
}

// This structure needs the `packed` attribute, otherwise Rust will assume
// the size to be 16 bytes.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct BalloonStat {
    pub tag: u16,
    pub val: u64,
}

// SAFETY: Safe because BalloonStat only contains plain data.
unsafe impl ByteValued for BalloonStat {}

/// Holds configuration details for the balloon device.
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize)]
pub struct BalloonConfig {
    /// Target size.
    pub amount_mib: u32,
    /// Whether or not to ask for pages back.
    pub deflate_on_oom: bool,
    /// Interval of time in seconds at which the balloon statistics are updated.
    pub stats_polling_interval_s: u16,
    /// Free page hinting enabled
    #[serde(default)]
    pub free_page_hinting: bool,
    /// Free page reporting enabled
    #[serde(default)]
    pub free_page_reporting: bool,
}

/// BalloonStats holds statistics returned from the stats_queue.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalloonStats {
    /// The target size of the balloon, in 4K pages.
    pub target_pages: u32,
    /// The number of 4K pages the device is currently holding.
    pub actual_pages: u32,
    /// The target size of the balloon, in MiB.
    pub target_mib: u32,
    /// The number of MiB the device is currently holding.
    pub actual_mib: u32,
    /// Amount of memory swapped in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_in: Option<u64>,
    /// Amount of memory swapped out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_out: Option<u64>,
    /// Number of major faults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major_faults: Option<u64>,
    /// Number of minor faults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor_faults: Option<u64>,
    /// The amount of memory not being used for any
    /// purpose (in bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_memory: Option<u64>,
    /// Total amount of memory available (in bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_memory: Option<u64>,
    /// An estimate of how much memory is available (in
    /// bytes) for starting new applications, without pushing the system to swap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_memory: Option<u64>,
    /// The amount of memory, in bytes, that can be
    /// quickly reclaimed without additional I/O. Typically these pages are used for
    /// caching files from disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_caches: Option<u64>,
    /// The number of successful hugetlb page
    /// allocations in the guest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugetlb_allocations: Option<u64>,
    /// The number of failed hugetlb page allocations
    /// in the guest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugetlb_failures: Option<u64>,
    /// OOM killer invocations. since linux v6.12.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_kill: Option<u64>,
    /// Stall count of memory allocatoin. since linux v6.12.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc_stall: Option<u64>,
    /// Amount of memory scanned asynchronously. since linux v6.12.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub async_scan: Option<u64>,
    /// Amount of memory scanned directly. since linux v6.12.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_scan: Option<u64>,
    /// Amount of memory reclaimed asynchronously. since linux v6.12.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub async_reclaim: Option<u64>,
    /// Amount of memory reclaimed directly. since linux v6.12.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_reclaim: Option<u64>,
}

impl BalloonStats {
    fn update_with_stat(&mut self, stat: &BalloonStat) {
        let val = Some(stat.val);
        match stat.tag {
            VIRTIO_BALLOON_S_SWAP_IN => self.swap_in = val,
            VIRTIO_BALLOON_S_SWAP_OUT => self.swap_out = val,
            VIRTIO_BALLOON_S_MAJFLT => self.major_faults = val,
            VIRTIO_BALLOON_S_MINFLT => self.minor_faults = val,
            VIRTIO_BALLOON_S_MEMFREE => self.free_memory = val,
            VIRTIO_BALLOON_S_MEMTOT => self.total_memory = val,
            VIRTIO_BALLOON_S_AVAIL => self.available_memory = val,
            VIRTIO_BALLOON_S_CACHES => self.disk_caches = val,
            VIRTIO_BALLOON_S_HTLB_PGALLOC => self.hugetlb_allocations = val,
            VIRTIO_BALLOON_S_HTLB_PGFAIL => self.hugetlb_failures = val,
            VIRTIO_BALLOON_S_OOM_KILL => self.oom_kill = val,
            VIRTIO_BALLOON_S_ALLOC_STALL => self.alloc_stall = val,
            VIRTIO_BALLOON_S_ASYNC_SCAN => self.async_scan = val,
            VIRTIO_BALLOON_S_DIRECT_SCAN => self.direct_scan = val,
            VIRTIO_BALLOON_S_ASYNC_RECLAIM => self.async_reclaim = val,
            VIRTIO_BALLOON_S_DIRECT_RECLAIM => self.direct_reclaim = val,
            tag => {
                METRICS.stats_update_fails.inc();
                debug!("balloon: unknown stats update tag: {tag}");
            }
        }
    }
}

/// Virtio balloon device.
#[derive(Debug)]
pub struct Balloon {
    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) config_space: ConfigSpace,
    pub(crate) activate_evt: EventFd,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) stats_polling_interval_s: u16,
    pub(crate) stats_timer: TimerFd,
    // The index of the previous stats descriptor is saved because
    // it is acknowledged after the stats queue is processed.
    pub(crate) stats_desc_index: Option<u16>,
    pub(crate) latest_stats: BalloonStats,
    // A buffer used as pfn accumulator during descriptor processing.
    pub(crate) pfn_buffer: [u32; MAX_PAGE_COMPACT_BUFFER],

    // Holds state for free page hinting
    pub(crate) hinting_state: HintingState,
}

impl Balloon {
    /// Instantiate a new balloon device.
    pub fn new(
        amount_mib: u32,
        deflate_on_oom: bool,
        stats_polling_interval_s: u16,
        free_page_hinting: bool,
        free_page_reporting: bool,
    ) -> Result<Balloon, BalloonError> {
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

        if deflate_on_oom {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
        };

        // The VirtIO specification states that the statistics queue should
        // not be present at all if the statistics are not enabled.
        let mut queue_count = BALLOON_MIN_NUM_QUEUES;
        if stats_polling_interval_s > 0 {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_STATS_VQ;
            queue_count += 1;
        }

        if free_page_hinting {
            log_dev_preview_warning("Free Page Hinting", None);
            avail_features |= 1u64 << VIRTIO_BALLOON_F_FREE_PAGE_HINTING;
            queue_count += 1;
        }

        if free_page_reporting {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_FREE_PAGE_REPORTING;
            queue_count += 1;
        }

        let queues: Vec<Queue> = (0..queue_count)
            .map(|_| Queue::new(BALLOON_QUEUE_SIZE))
            .collect();
        let queue_evts = (0..queue_count)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK).map_err(BalloonError::EventFd))
            .collect::<Result<Vec<_>, _>>()?;

        let stats_timer = TimerFd::new();

        Ok(Balloon {
            avail_features,
            acked_features: 0u64,
            config_space: ConfigSpace {
                num_pages: mib_to_pages(amount_mib)?,
                actual_pages: 0,
                free_page_hint_cmd_id: FREE_PAGE_HINT_STOP,
            },
            queue_evts,
            queues,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(BalloonError::EventFd)?,
            stats_polling_interval_s,
            stats_timer,
            stats_desc_index: None,
            latest_stats: BalloonStats::default(),
            pfn_buffer: [0u32; MAX_PAGE_COMPACT_BUFFER],
            hinting_state: Default::default(),
        })
    }

    pub(crate) fn process_inflate_queue_event(&mut self) -> Result<(), BalloonError> {
        self.queue_evts[INFLATE_INDEX]
            .read()
            .map_err(BalloonError::EventFd)?;
        self.process_inflate()
    }

    pub(crate) fn process_deflate_queue_event(&mut self) -> Result<(), BalloonError> {
        self.queue_evts[DEFLATE_INDEX]
            .read()
            .map_err(BalloonError::EventFd)?;
        self.process_deflate_queue()
    }

    pub(crate) fn process_stats_queue_event(&mut self) -> Result<(), BalloonError> {
        self.queue_evts[STATS_INDEX]
            .read()
            .map_err(BalloonError::EventFd)?;
        self.process_stats_queue()
    }

    pub(crate) fn process_stats_timer_event(&mut self) -> Result<(), BalloonError> {
        _ = self.stats_timer.read();
        self.trigger_stats_update()
    }

    pub(crate) fn process_free_page_hinting_queue_event(&mut self) -> Result<(), BalloonError> {
        self.queue_evts[self.free_page_hinting_idx()]
            .read()
            .map_err(BalloonError::EventFd)?;
        self.process_free_page_hinting_queue()
    }

    pub(crate) fn process_free_page_reporting_queue_event(&mut self) -> Result<(), BalloonError> {
        self.queue_evts[self.free_page_reporting_idx()]
            .read()
            .map_err(BalloonError::EventFd)?;
        self.process_free_page_reporting_queue()
    }

    pub(crate) fn process_inflate(&mut self) -> Result<(), BalloonError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = &self
            .device_state
            .active_state()
            .ok_or(BalloonError::DeviceNotActive)?
            .mem;
        METRICS.inflate_count.inc();

        let queue = &mut self.queues[INFLATE_INDEX];
        // The pfn buffer index used during descriptor processing.
        let mut pfn_buffer_idx = 0;
        let mut needs_interrupt = false;
        let mut valid_descs_found = true;

        // Loop until there are no more valid DescriptorChains.
        while valid_descs_found {
            valid_descs_found = false;
            // Internal loop processes descriptors and acummulates the pfns in `pfn_buffer`.
            // Breaks out when there is not enough space in `pfn_buffer` to completely process
            // the next descriptor.
            while let Some(head) = queue.pop()? {
                let len = head.len as usize;
                let max_len = MAX_PAGES_IN_DESC * SIZE_OF_U32;
                valid_descs_found = true;

                if !head.is_write_only() && len.is_multiple_of(SIZE_OF_U32) {
                    // Check descriptor pfn count.
                    if len > max_len {
                        error!(
                            "Inflate descriptor has bogus page count {} > {}, skipping.",
                            len / SIZE_OF_U32,
                            MAX_PAGES_IN_DESC
                        );

                        // Skip descriptor.
                        continue;
                    }
                    // Break loop if `pfn_buffer` will be overrun by adding all pfns from current
                    // desc.
                    if MAX_PAGE_COMPACT_BUFFER - pfn_buffer_idx < len / SIZE_OF_U32 {
                        queue.undo_pop();
                        break;
                    }

                    // This is safe, `len` was validated above.
                    for index in (0..len).step_by(SIZE_OF_U32) {
                        let addr = head
                            .addr
                            .checked_add(index as u64)
                            .ok_or(BalloonError::MalformedDescriptor)?;

                        let page_frame_number = mem
                            .read_obj::<u32>(addr)
                            .map_err(|_| BalloonError::MalformedDescriptor)?;

                        self.pfn_buffer[pfn_buffer_idx] = page_frame_number;
                        pfn_buffer_idx += 1;
                    }
                }

                // Acknowledge the receipt of the descriptor.
                // 0 is number of bytes the device has written to memory.
                queue.add_used(head.index, 0)?;
                needs_interrupt = true;
            }

            // Compact pages into ranges.
            let page_ranges = compact_page_frame_numbers(&mut self.pfn_buffer[..pfn_buffer_idx]);
            pfn_buffer_idx = 0;

            // Remove the page ranges.
            for (page_frame_number, range_len) in page_ranges {
                let guest_addr =
                    GuestAddress(u64::from(page_frame_number) << VIRTIO_BALLOON_PFN_SHIFT);

                if let Err(err) = mem.discard_range(
                    guest_addr,
                    usize::try_from(range_len).unwrap() << VIRTIO_BALLOON_PFN_SHIFT,
                ) {
                    error!("Error removing memory range: {:?}", err);
                }
            }
        }
        queue.advance_used_ring_idx();

        if needs_interrupt {
            self.signal_used_queue(INFLATE_INDEX)?;
        }

        Ok(())
    }

    pub(crate) fn process_deflate_queue(&mut self) -> Result<(), BalloonError> {
        METRICS.deflate_count.inc();

        let queue = &mut self.queues[DEFLATE_INDEX];
        let mut needs_interrupt = false;

        while let Some(head) = queue.pop()? {
            queue.add_used(head.index, 0)?;
            needs_interrupt = true;
        }
        queue.advance_used_ring_idx();

        if needs_interrupt {
            self.signal_used_queue(DEFLATE_INDEX)
        } else {
            Ok(())
        }
    }

    pub(crate) fn process_stats_queue(&mut self) -> Result<(), BalloonError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = &self.device_state.active_state().unwrap().mem;
        METRICS.stats_updates_count.inc();

        while let Some(head) = self.queues[STATS_INDEX].pop()? {
            if let Some(prev_stats_desc) = self.stats_desc_index {
                // We shouldn't ever have an extra buffer if the driver follows
                // the protocol, but return it if we find one.
                error!("balloon: driver is not compliant, more than one stats buffer received");
                self.queues[STATS_INDEX].add_used(prev_stats_desc, 0)?;
                self.queues[STATS_INDEX].advance_used_ring_idx();
                self.signal_used_queue(STATS_INDEX)?;
            }

            // Reject oversized descriptors to prevent a guest from causing
            // excessive iteration on the VMM event loop.
            // We still hold onto the descriptor (via stats_desc_index below)
            // so that the stats request/response protocol is preserved and
            // trigger_stats_update can return it to the guest later.
            if head.len > MAX_STATS_DESC_LEN {
                warn!(
                    "balloon: stats descriptor too large: {} > {}, skipping",
                    head.len, MAX_STATS_DESC_LEN
                );
                self.stats_desc_index = Some(head.index);
                continue;
            }

            for index in (0..head.len).step_by(SIZE_OF_STAT) {
                // Read the address at position `index`. The only case
                // in which this fails is if there is overflow,
                // in which case this descriptor is malformed,
                // so we ignore the rest of it.
                let addr = head
                    .addr
                    .checked_add(u64::from(index))
                    .ok_or(BalloonError::MalformedDescriptor)?;
                let stat = mem
                    .read_obj::<BalloonStat>(addr)
                    .map_err(|_| BalloonError::MalformedDescriptor)?;
                self.latest_stats.update_with_stat(&stat);
            }

            self.stats_desc_index = Some(head.index);
        }

        Ok(())
    }

    pub(crate) fn process_free_page_hinting_queue(&mut self) -> Result<(), BalloonError> {
        let mem = &self
            .device_state
            .active_state()
            .ok_or(BalloonError::DeviceNotActive)?
            .mem;

        let idx = self.free_page_hinting_idx();
        let queue = &mut self.queues[idx];
        let host_cmd = self.hinting_state.host_cmd;
        let mut needs_interrupt = false;
        let mut complete = false;

        while let Some(head) = queue.pop()? {
            let head_index = head.index;

            let mut last_desc = Some(head);
            while let Some(desc) = last_desc {
                last_desc = desc.next_descriptor();

                // Updated cmd_ids are always of length 4
                if desc.len == 4 {
                    complete = false;

                    let cmd = mem
                        .read_obj::<u32>(desc.addr)
                        .map_err(|_| BalloonError::MalformedDescriptor)?;
                    self.hinting_state.guest_cmd = Some(cmd);
                    if cmd == FREE_PAGE_HINT_STOP {
                        complete = true;
                    }

                    // We don't expect this from the driver, but lets treat as a stop
                    if cmd == FREE_PAGE_HINT_DONE {
                        warn!("balloon hinting: Unexpected cmd from guest: {cmd}");
                        complete = true;
                    }

                    continue;
                }

                // If we've requested done we have to discard any in-flight hints
                if host_cmd == FREE_PAGE_HINT_DONE || host_cmd == FREE_PAGE_HINT_STOP {
                    continue;
                }

                let Some(chain_cmd) = self.hinting_state.guest_cmd else {
                    warn!("balloon hinting: received range with no command id.");
                    continue;
                };

                if chain_cmd != host_cmd {
                    info!("balloon hinting: Received chain from previous command ignoring.");
                    continue;
                }

                METRICS.free_page_hint_count.inc();
                if let Err(err) = mem.discard_range(desc.addr, desc.len as usize) {
                    METRICS.free_page_hint_fails.inc();
                    error!("balloon hinting: failed to remove range: {err:?}");
                } else {
                    METRICS.free_page_hint_freed.add(desc.len as u64);
                }
            }

            queue.add_used(head.index, 0)?;
            needs_interrupt = true;
        }

        queue.advance_used_ring_idx();

        if needs_interrupt {
            self.signal_used_queue(idx)?;
        }

        if complete && self.hinting_state.acknowledge_on_finish {
            self.update_free_page_hint_cmd(FREE_PAGE_HINT_DONE);
        }

        Ok(())
    }

    pub(crate) fn process_free_page_reporting_queue(&mut self) -> Result<(), BalloonError> {
        let mem = &self
            .device_state
            .active_state()
            .ok_or(BalloonError::DeviceNotActive)?
            .mem;

        let idx = self.free_page_reporting_idx();
        let queue = &mut self.queues[idx];
        let mut needs_interrupt = false;

        while let Some(head) = queue.pop()? {
            let head_index = head.index;

            let mut last_desc = Some(head);
            while let Some(desc) = last_desc {
                METRICS.free_page_report_count.inc();
                if let Err(err) = mem.discard_range(desc.addr, desc.len as usize) {
                    METRICS.free_page_report_fails.inc();
                    error!("balloon: failed to remove range: {err:?}");
                } else {
                    METRICS.free_page_report_freed.add(desc.len as u64);
                }
                last_desc = desc.next_descriptor();
            }

            queue.add_used(head.index, 0)?;
            needs_interrupt = true;
        }

        queue.advance_used_ring_idx();

        if needs_interrupt {
            self.signal_used_queue(idx)?;
        }

        Ok(())
    }

    pub(crate) fn signal_used_queue(&self, qidx: usize) -> Result<(), BalloonError> {
        self.interrupt_trigger()
            .trigger(VirtioInterruptType::Queue(
                qidx.try_into()
                    .unwrap_or_else(|_| panic!("balloon: invalid queue id: {qidx}")),
            ))
            .map_err(|err| {
                METRICS.event_fails.inc();
                BalloonError::InterruptError(err)
            })
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        if let Err(BalloonError::InvalidAvailIdx(err)) = self.process_inflate() {
            return Err(err);
        }
        if let Err(BalloonError::InvalidAvailIdx(err)) = self.process_deflate_queue() {
            return Err(err);
        }

        if self.free_page_hinting()
            && let Err(BalloonError::InvalidAvailIdx(err)) = self.process_free_page_hinting_queue()
        {
            return Err(err);
        }

        if self.free_page_reporting()
            && let Err(BalloonError::InvalidAvailIdx(err)) =
                self.process_free_page_reporting_queue()
        {
            return Err(err);
        }

        // Under fuzzing, also process the stats queue since we can't use the timer-driven path.
        #[cfg(feature = "fuzzing")]
        if self.stats_enabled() {
            _ = self.process_stats_queue();
        }

        Ok(())
    }

    fn trigger_stats_update(&mut self) -> Result<(), BalloonError> {
        // The communication is driven by the device by using the buffer
        // and sending a used buffer notification
        if let Some(index) = self.stats_desc_index.take() {
            self.queues[STATS_INDEX].add_used(index, 0)?;
            self.queues[STATS_INDEX].advance_used_ring_idx();
            self.signal_used_queue(STATS_INDEX)
        } else {
            error!("Failed to update balloon stats, missing descriptor.");
            Ok(())
        }
    }

    /// Update the target size of the balloon.
    pub fn update_size(&mut self, amount_mib: u32) -> Result<(), BalloonError> {
        if self.is_activated() {
            let mem = &self.device_state.active_state().unwrap().mem;
            // The balloon cannot have a target size greater than the size of
            // the guest memory.
            if u64::from(amount_mib) > mem_size_mib(mem) {
                return Err(BalloonError::TooMuchMemoryRequested(amount_mib));
            }

            // 修改 balloon 设备的配置
            self.config_space.num_pages = mib_to_pages(amount_mib)?;
            // 触发中断，终端会被内核中的 virtio balloon driver 驱动来处理
            self.interrupt_trigger()
                .trigger(VirtioInterruptType::Config)
                .map_err(BalloonError::InterruptError)
        } else {
            Err(BalloonError::DeviceNotActive)
        }
    }

    pub fn free_page_hinting(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BALLOON_F_FREE_PAGE_HINTING) != 0
    }

    pub fn free_page_hinting_idx(&self) -> usize {
        let mut idx = BALLOON_MIN_NUM_QUEUES;

        if self.stats_polling_interval_s > 0 {
            idx += 1;
        }

        idx
    }

    pub fn free_page_reporting(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BALLOON_F_FREE_PAGE_REPORTING) != 0
    }

    pub fn free_page_reporting_idx(&self) -> usize {
        let mut idx = BALLOON_MIN_NUM_QUEUES;

        if self.stats_polling_interval_s > 0 {
            idx += 1;
        }

        if self.free_page_hinting() {
            idx += 1;
        }

        idx
    }

    /// Update the statistics polling interval.
    pub fn update_stats_polling_interval(&mut self, interval_s: u16) -> Result<(), BalloonError> {
        if self.stats_polling_interval_s == interval_s {
            return Ok(());
        }

        if self.stats_polling_interval_s == 0 || interval_s == 0 {
            return Err(BalloonError::StatisticsStateChange);
        }

        self.trigger_stats_update()?;

        self.stats_polling_interval_s = interval_s;
        self.update_timer_state();
        Ok(())
    }

    pub fn update_timer_state(&mut self) {
        let duration = Duration::from_secs(self.stats_polling_interval_s as u64);
        self.stats_timer.arm(duration, Some(duration));
    }

    /// Obtain the number of 4K pages the device is currently holding.
    pub fn num_pages(&self) -> u32 {
        self.config_space.num_pages
    }

    /// Obtain the size of 4K pages the device is currently holding in MIB.
    pub fn size_mb(&self) -> u32 {
        pages_to_mib(self.config_space.num_pages)
    }

    pub fn deflate_on_oom(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM) != 0
    }

    pub fn stats_polling_interval_s(&self) -> u16 {
        self.stats_polling_interval_s
    }

    /// Retrieve latest stats for the balloon device.
    pub fn latest_stats(&mut self) -> Result<BalloonStats, BalloonError> {
        if self.stats_enabled() {
            self.latest_stats.target_pages = self.config_space.num_pages;
            self.latest_stats.actual_pages = self.config_space.actual_pages;
            self.latest_stats.target_mib = pages_to_mib(self.latest_stats.target_pages);
            self.latest_stats.actual_mib = pages_to_mib(self.latest_stats.actual_pages);
            Ok(self.latest_stats)
        } else {
            Err(BalloonError::StatisticsDisabled)
        }
    }

    /// Update the free page hinting cmd
    pub fn update_free_page_hint_cmd(&mut self, cmd_id: u32) -> Result<(), BalloonError> {
        if !self.is_activated() {
            return Err(BalloonError::DeviceNotActive);
        }

        self.hinting_state.host_cmd = cmd_id;
        self.config_space.free_page_hint_cmd_id = cmd_id;
        self.interrupt_trigger()
            .trigger(VirtioInterruptType::Config)
            .map_err(BalloonError::InterruptError)
    }

    /// Starts a hinting run by setting the cmd_id to a new value.
    pub(crate) fn start_hinting(&mut self, cmd: StartHintingCmd) -> Result<(), BalloonError> {
        if !self.free_page_hinting() {
            return Err(BalloonError::HintingNotEnabled);
        }

        let mut cmd_id = self.hinting_state.last_cmd_id.wrapping_add(1);
        // 0 and 1 are reserved and cannot be used to start a hinting run
        if cmd_id <= 1 {
            cmd_id = 2;
        }

        self.hinting_state.acknowledge_on_finish = cmd.acknowledge_on_stop;
        self.hinting_state.last_cmd_id = cmd_id;
        self.update_free_page_hint_cmd(cmd_id)
    }

    /// Return the status of the hinting including the last command we sent to the driver
    /// and the last cmd sent from the driver
    pub(crate) fn get_hinting_status(&self) -> Result<HintingStatus, BalloonError> {
        if !self.free_page_hinting() {
            return Err(BalloonError::HintingNotEnabled);
        }

        Ok(HintingStatus {
            host_cmd: self.hinting_state.host_cmd,
            guest_cmd: self.hinting_state.guest_cmd,
        })
    }

    /// Stops the hinting run allowing the guest to reclaim hinted pages
    pub(crate) fn stop_hinting(&mut self) -> Result<(), BalloonError> {
        if !self.free_page_hinting() {
            Err(BalloonError::HintingNotEnabled)
        } else {
            self.update_free_page_hint_cmd(FREE_PAGE_HINT_DONE)
        }
    }

    /// Return the config of the balloon device.
    pub fn config(&self) -> BalloonConfig {
        BalloonConfig {
            amount_mib: self.size_mb(),
            deflate_on_oom: self.deflate_on_oom(),
            stats_polling_interval_s: self.stats_polling_interval_s(),
            free_page_hinting: self.free_page_hinting(),
            free_page_reporting: self.free_page_reporting(),
        }
    }

    pub(crate) fn stats_enabled(&self) -> bool {
        self.stats_polling_interval_s > 0
    }

    pub(crate) fn set_stats_desc_index(&mut self, stats_desc_index: Option<u16>) {
        self.stats_desc_index = stats_desc_index;
    }
}

impl VirtioDevice for Balloon {
    impl_device_type!(VirtioDeviceType::Balloon);

    fn id(&self) -> &str {
        BALLOON_DEV_ID
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

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not activated")
            .interrupt
            .deref()
    }

    fn config_as_bytes(&self) -> &[u8] {
        self.config_space.as_slice()
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let config_space_bytes = self.config_space.as_mut_slice();
        let start = usize::try_from(offset).ok();
        let end = start.and_then(|s| s.checked_add(data.len()));
        let Some(dst) = start
            .zip(end)
            .and_then(|(start, end)| config_space_bytes.get_mut(start..end))
        else {
            error!("Failed to write config space");
            return;
        };

        dst.copy_from_slice(data);
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

        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        if self.activate_evt.write(1).is_err() {
            METRICS.activate_fails.inc();
            self.device_state = DeviceState::Inactive;
            return Err(ActivateError::EventFd);
        }

        if self.stats_enabled() {
            self.update_timer_state();
        }

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn kick(&mut self) {
        if self.is_activated() {
            if self.free_page_hinting() {
                info!(
                    "[{:?}:{}] resetting free page hinting to DONE",
                    self.device_type(),
                    self.id()
                );
                self.update_free_page_hint_cmd(FREE_PAGE_HINT_DONE);
            }
            self.notify_queue_events();
        }
    }
}
