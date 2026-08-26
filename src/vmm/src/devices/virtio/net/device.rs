// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::VecDeque;
use std::mem::{self};
use std::net::Ipv4Addr;
use std::num::Wrapping;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use libc::{EAGAIN, iovec};
use vmm_sys_util::eventfd::EventFd;

use super::NET_QUEUE_MAX_SIZE;
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_net::{
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_TSO6, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_MTU, virtio_net_hdr_v1,
};
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::iovec::{
    IoVecBuffer, IoVecBufferMut, IoVecError, ParsedDescriptorChain,
};
use crate::devices::virtio::net::metrics::{NetDeviceMetrics, NetMetricsPerDevice};
use crate::devices::virtio::net::tap::Tap;
use crate::devices::virtio::net::{
    MAX_BUFFER_SIZE, NET_QUEUE_SIZES, NetError, NetQueue, RX_INDEX, TX_INDEX, generated,
};
use crate::devices::virtio::queue::{DescriptorChain, InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::{DeviceError, report_net_event_fail};
use crate::dumbo::pdu::arp::ETH_IPV4_FRAME_LEN;
use crate::dumbo::pdu::ethernet::{EthernetFrame, PAYLOAD_OFFSET};
use crate::impl_device_type;
use crate::logger::{IncMetric, METRICS, error, warn};
use crate::mmds::data_store::Mmds;
use crate::mmds::ns::MmdsNetworkStack;
use crate::rate_limiter::{BucketUpdate, RateLimiter, TokenType};
use crate::utils::net::mac::MacAddr;
use crate::utils::u64_to_usize;
use crate::vstate::memory::{ByteValued, GuestMemoryMmap};

const FRAME_HEADER_MAX_LEN: usize = PAYLOAD_OFFSET + ETH_IPV4_FRAME_LEN;

pub(crate) const fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// This returns the maximum frame header length. This includes the VNET header plus
// the maximum L2 frame header bytes which includes the ethernet frame header plus
// the header IPv4 ARP header which is 28 bytes long.
const fn frame_hdr_len() -> usize {
    vnet_hdr_len() + FRAME_HEADER_MAX_LEN
}

// Frames being sent/received through the network device model have a VNET header. This
// function returns a slice which holds the L2 frame bytes without this header.
fn frame_bytes_from_buf(buf: &[u8]) -> Result<&[u8], NetError> {
    if buf.len() < vnet_hdr_len() {
        Err(NetError::VnetHeaderMissing)
    } else {
        Ok(&buf[vnet_hdr_len()..])
    }
}

fn frame_bytes_from_buf_mut(buf: &mut [u8]) -> Result<&mut [u8], NetError> {
    if buf.len() < vnet_hdr_len() {
        Err(NetError::VnetHeaderMissing)
    } else {
        Ok(&mut buf[vnet_hdr_len()..])
    }
}

// This initializes to all 0 the VNET hdr part of a buf.
fn init_vnet_hdr(buf: &mut [u8]) {
    // The buffer should be larger than vnet_hdr_len.
    buf[0..vnet_hdr_len()].fill(0);
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct ConfigSpace {
    pub guest_mac: MacAddr,
    // Padding fields to match the virtio_net_config layout:
    // offset 6: status (u16, not advertised)
    _status: u16,
    // offset 8: max_virtqueue_pairs (u16, not advertised)
    _max_virtqueue_pairs: u16,
    // offset 10: mtu (u16, advertised via VIRTIO_NET_F_MTU)
    pub mtu: u16,
}

// SAFETY: `ConfigSpace` contains only PODs in `repr(C)` or `repr(transparent)`, without padding.
unsafe impl ByteValued for ConfigSpace {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum AddRxBufferError {
    /// Error while parsing new buffer: {0}
    Parsing(#[from] IoVecError),
    /// RX buffer is too small
    BufferTooSmall,
}

/// A map of all the memory the guest has provided us with for performing RX
#[derive(Debug)]
pub struct RxBuffers {
    // minimum size of a usable buffer for doing RX
    pub min_buffer_size: u32,
    // An [`IoVecBufferMut`] covering all the memory we have available for receiving network
    // frames.
    pub iovec: IoVecBufferMut<NET_QUEUE_MAX_SIZE>,
    // A map of which part of the memory belongs to which `DescriptorChain` object
    pub parsed_descriptors: VecDeque<ParsedDescriptorChain>,
    // Buffers that we have used and they are ready to be given back to the guest.
    pub used_descriptors: u16,
    pub used_bytes: u32,
}

impl RxBuffers {
    /// Create a new [`RxBuffers`] object for storing guest memory for performing RX
    fn new() -> Result<Self, IoVecError> {
        Ok(Self {
            min_buffer_size: 0,
            iovec: IoVecBufferMut::new()?,
            parsed_descriptors: VecDeque::with_capacity(NET_QUEUE_MAX_SIZE.into()),
            used_descriptors: 0,
            used_bytes: 0,
        })
    }

    /// Add a new `DescriptorChain` that we received from the RX queue in the buffer.
    ///
    /// SAFETY: The `DescriptorChain` cannot be referencing the same memory location as any other
    /// `DescriptorChain`. (See also related comment in
    /// [`IoVecBufferMut::append_descriptor_chain`]).
    unsafe fn add_buffer(
        &mut self,
        mem: &GuestMemoryMmap,
        head: DescriptorChain,
    ) -> Result<(), AddRxBufferError> {
        // SAFETY: descriptor chain cannot be referencing the same memory location as another chain
        let parsed_dc = unsafe { self.iovec.append_descriptor_chain(mem, head)? };
        if parsed_dc.length < self.min_buffer_size {
            self.iovec.drop_chain_back(&parsed_dc);
            return Err(AddRxBufferError::BufferTooSmall);
        }
        self.parsed_descriptors.push_back(parsed_dc);
        Ok(())
    }

    /// Returns the total size of available space in the buffer.
    #[inline(always)]
    fn capacity(&self) -> u32 {
        self.iovec.len()
    }

    /// Mark the first `size` bytes of available memory as used.
    ///
    /// # Safety:
    ///
    /// * The `RxBuffers` should include at least one parsed `DescriptorChain`.
    /// * `size` needs to be smaller or equal to total length of the first `DescriptorChain` stored
    ///   in the `RxBuffers`.
    unsafe fn mark_used(&mut self, mut bytes_written: u32, rx_queue: &mut Queue) {
        self.used_bytes = bytes_written;

        let mut used_heads: u16 = 0;
        for parsed_dc in self.parsed_descriptors.iter() {
            let used_bytes = bytes_written.min(parsed_dc.length);
            // Safe because we know head_index isn't out of bounds
            rx_queue
                .write_used_element(self.used_descriptors, parsed_dc.head_index, used_bytes)
                .unwrap();
            bytes_written -= used_bytes;
            self.used_descriptors += 1;
            used_heads += 1;

            if bytes_written == 0 {
                break;
            }
        }

        // We need to set num_buffers before dropping chains from `self.iovec`. Otherwise
        // when we set headers, we will iterate over new, yet unused chains instead of the ones
        // we need.
        self.header_set_num_buffers(used_heads);
        for _ in 0..used_heads {
            let parsed_dc = self
                .parsed_descriptors
                .pop_front()
                .expect("This should never happen if write to the buffer succeeded.");
            self.iovec.drop_chain_front(&parsed_dc);
        }
    }

    /// Write the number of descriptors used in VirtIO header
    fn header_set_num_buffers(&mut self, nr_descs: u16) {
        // We can unwrap here, because we have checked before that the `IoVecBufferMut` holds at
        // least one buffer with the proper size, depending on the feature negotiation. In any
        // case, the buffer holds memory of at least `std::mem::size_of::<virtio_net_hdr_v1>()`
        // bytes.
        self.iovec
            .write_all_volatile_at(
                &nr_descs.to_le_bytes(),
                std::mem::offset_of!(virtio_net_hdr_v1, num_buffers),
            )
            .unwrap()
    }

    /// This will let the guest know that about all the `DescriptorChain` object that has been
    /// used to receive a frame from the TAP.
    fn finish_frame(&mut self, rx_queue: &mut Queue) {
        rx_queue.advance_next_used(self.used_descriptors);
        self.used_descriptors = 0;
        self.used_bytes = 0;
    }

    /// Return a slice of iovecs for the first slice in the buffer.
    /// Panics if there are no parsed descriptors.
    fn single_chain_slice_mut(&mut self) -> &mut [iovec] {
        let nr_iovecs = self.parsed_descriptors[0].nr_iovecs as usize;
        &mut self.iovec.as_iovec_mut_slice()[..nr_iovecs]
    }

    /// Return a slice of iovecs for all descriptor chains in the buffer.
    fn all_chains_slice_mut(&mut self) -> &mut [iovec] {
        self.iovec.as_iovec_mut_slice()
    }
}

/// VirtIO network device.
///
/// It emulates a network device able to exchange L2 frames between the guest
/// and a host-side tap device.
#[derive(Debug)]
pub struct Net {
    pub(crate) id: String,

    /// The backend for this device: a tap.
    pub tap: Tap,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,

    pub(crate) rx_rate_limiter: RateLimiter,
    pub(crate) tx_rate_limiter: RateLimiter,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],

    tx_frame_headers: [u8; frame_hdr_len()],

    pub(crate) config_space: ConfigSpace,
    pub(crate) guest_mac: Option<MacAddr>,

    pub(crate) device_state: DeviceState,
    pub(crate) activate_evt: EventFd,

    /// The MMDS stack corresponding to this interface.
    /// Only if MMDS transport has been associated with it.
    pub mmds_ns: Option<MmdsNetworkStack>,
    pub(crate) metrics: Arc<NetDeviceMetrics>,

    tx_buffer: IoVecBuffer,
    pub(crate) rx_buffer: RxBuffers,
}

impl Net {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(
        id: String,
        tap: Tap,
        guest_mac: Option<MacAddr>,
        rx_rate_limiter: RateLimiter,
        tx_rate_limiter: RateLimiter,
        mtu: Option<u16>,
    ) -> Result<Self, NetError> {
        let mut avail_features = (1 << VIRTIO_NET_F_GUEST_CSUM)
            | (1 << VIRTIO_NET_F_CSUM)
            | (1 << VIRTIO_NET_F_GUEST_TSO4)
            | (1 << VIRTIO_NET_F_GUEST_TSO6)
            | (1 << VIRTIO_NET_F_GUEST_UFO)
            | (1 << VIRTIO_NET_F_HOST_TSO4)
            | (1 << VIRTIO_NET_F_HOST_TSO6)
            | (1 << VIRTIO_NET_F_HOST_UFO)
            | (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_NET_F_MRG_RXBUF)
            | (1 << VIRTIO_RING_F_EVENT_IDX);

        let mut config_space = ConfigSpace::default();
        if let Some(mtu) = mtu {
            if !(68..=65535).contains(&mtu) {
                return Err(NetError::InvalidMtu(mtu));
            }
            avail_features |= 1 << VIRTIO_NET_F_MTU;
            config_space.mtu = mtu;
        }
        if let Some(mac) = guest_mac {
            config_space.guest_mac = mac;
            // Enabling feature for MAC address configuration
            // If not set, the driver will generates a random MAC address
            avail_features |= 1 << VIRTIO_NET_F_MAC;
        }

        let mut queue_evts = Vec::new();
        let mut queues = Vec::new();
        for size in NET_QUEUE_SIZES {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(NetError::EventFd)?);
            queues.push(Queue::new(size));
        }

        Ok(Net {
            id: id.clone(),
            tap,
            avail_features,
            acked_features: 0u64,
            queues,
            queue_evts,
            rx_rate_limiter,
            tx_rate_limiter,
            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_headers: [0u8; frame_hdr_len()],
            config_space,
            guest_mac,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(NetError::EventFd)?,
            mmds_ns: None,
            metrics: NetMetricsPerDevice::alloc(id),
            tx_buffer: Default::default(),
            rx_buffer: RxBuffers::new()?,
        })
    }

    /// Create a new virtio network device given the interface name.
    pub fn new(
        id: String,
        tap_if_name: &str,
        guest_mac: Option<MacAddr>,
        rx_rate_limiter: RateLimiter,
        tx_rate_limiter: RateLimiter,
        mtu: Option<u16>,
    ) -> Result<Self, NetError> {
        let tap = Tap::open_named(tap_if_name).map_err(NetError::TapOpen)?;

        let vnet_hdr_size = i32::try_from(vnet_hdr_len()).unwrap();
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(NetError::TapSetVnetHdrSize)?;

        Self::new_with_tap(id, tap, guest_mac, rx_rate_limiter, tx_rate_limiter, mtu)
    }

    /// Provides the MAC of this net device.
    pub fn guest_mac(&self) -> Option<&MacAddr> {
        self.guest_mac.as_ref()
    }

    /// Provides the host IFACE name of this net device.
    pub fn iface_name(&self) -> String {
        self.tap.if_name_as_str().to_string()
    }

    /// Returns the configured MTU if `VIRTIO_NET_F_MTU` is advertised, otherwise `None`.
    pub fn mtu(&self) -> Option<u16> {
        if self.avail_features & (1 << VIRTIO_NET_F_MTU) != 0 {
            Some(self.config_space.mtu)
        } else {
            None
        }
    }

    /// Provides the MmdsNetworkStack of this net device.
    pub fn mmds_ns(&self) -> Option<&MmdsNetworkStack> {
        self.mmds_ns.as_ref()
    }

    /// Configures the `MmdsNetworkStack` to allow device to forward MMDS requests.
    /// If the device already supports MMDS, updates the IPv4 address.
    pub fn configure_mmds_network_stack(&mut self, ipv4_addr: Ipv4Addr, mmds: Arc<Mutex<Mmds>>) {
        if let Some(mmds_ns) = self.mmds_ns.as_mut() {
            mmds_ns.set_ipv4_addr(ipv4_addr);
        } else {
            self.mmds_ns = Some(MmdsNetworkStack::new_with_defaults(Some(ipv4_addr), mmds))
        }
    }

    /// Disables the `MmdsNetworkStack` to prevent device to forward MMDS requests.
    pub fn disable_mmds_network_stack(&mut self) {
        self.mmds_ns = None
    }

    /// Provides a reference to the configured RX rate limiter.
    pub fn rx_rate_limiter(&self) -> &RateLimiter {
        &self.rx_rate_limiter
    }

    /// Provides a reference to the configured TX rate limiter.
    pub fn tx_rate_limiter(&self) -> &RateLimiter {
        &self.tx_rate_limiter
    }

    /// Trigger queue notification for the guest if we used enough descriptors
    /// for the notification to be enabled.
    /// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-320005
    /// 2.6.7.1 Driver Requirements: Used Buffer Notification Suppression
    fn try_signal_queue(&mut self, queue_type: NetQueue) -> Result<(), DeviceError> {
        let qidx = match queue_type {
            NetQueue::Rx => RX_INDEX,
            NetQueue::Tx => TX_INDEX,
        };
        self.queues[qidx].advance_used_ring_idx();

        if self.queues[qidx].prepare_kick() {
            self.interrupt_trigger()
                .trigger(VirtioInterruptType::Queue(qidx.try_into().unwrap()))
                .map_err(|err| {
                    self.metrics.event_fails.inc();
                    DeviceError::FailedSignalingIrq(err)
                })?;
        }

        Ok(())
    }

    // Helper function to consume one op with `size` bytes from a rate limiter
    fn rate_limiter_consume_op(rate_limiter: &mut RateLimiter, size: u64) -> bool {
        if !rate_limiter.consume(1, TokenType::Ops) {
            return false;
        }

        if !rate_limiter.consume(size, TokenType::Bytes) {
            rate_limiter.manual_replenish(1, TokenType::Ops);
            return false;
        }

        true
    }

    // Helper function to replenish one operation with `size` bytes from a rate limiter
    fn rate_limiter_replenish_op(rate_limiter: &mut RateLimiter, size: u64) {
        rate_limiter.manual_replenish(1, TokenType::Ops);
        rate_limiter.manual_replenish(size, TokenType::Bytes);
    }

    // Attempts to copy a single frame into the guest if there is enough
    // rate limiting budget.
    // Returns true on successful frame delivery.
    pub fn rate_limited_rx_single_frame(&mut self, frame_size: u32) -> bool {
        let rx_queue = &mut self.queues[RX_INDEX];
        if !Self::rate_limiter_consume_op(&mut self.rx_rate_limiter, frame_size as u64) {
            self.metrics.rx_rate_limiter_throttled.inc();
            return false;
        }

        self.rx_buffer.finish_frame(rx_queue);
        true
    }

    /// Returns the minimum size of buffer we expect the guest to provide us depending on the
    /// features we have negotiated with it
    fn minimum_rx_buffer_size(&self) -> u32 {
        if !self.has_feature(VIRTIO_NET_F_MRG_RXBUF as u64) {
            if self.has_feature(VIRTIO_NET_F_GUEST_TSO4 as u64)
                || self.has_feature(VIRTIO_NET_F_GUEST_TSO6 as u64)
                || self.has_feature(VIRTIO_NET_F_GUEST_UFO as u64)
            {
                MAX_BUFFER_SIZE.try_into().unwrap()
            } else {
                1526
            }
        } else {
            vnet_hdr_len().try_into().unwrap()
        }
    }

    /// Parse available RX `DescriptorChains` from the queue
    pub fn parse_rx_descriptors(&mut self) -> Result<(), InvalidAvailIdx> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = &self.device_state.active_state().unwrap().mem;
        let queue = &mut self.queues[RX_INDEX];
        while let Some(head) = queue.pop_or_enable_notification()? {
            let index = head.index;
            // SAFETY: we are only using this `DescriptorChain` here.
            if let Err(err) = unsafe { self.rx_buffer.add_buffer(mem, head) } {
                self.metrics.rx_fails.inc();

                // If guest uses dirty tricks to make us add more descriptors than
                // we can hold, just stop processing.
                if matches!(err, AddRxBufferError::Parsing(IoVecError::IovDequeOverflow)) {
                    error!("net: Could not add an RX descriptor: {err}");
                    queue.undo_pop();
                    break;
                }

                error!("net: Could not parse an RX descriptor: {err}");

                // Add this broken chain to the used_ring. It will be
                // reported to the quest on the next `rx_buffer.finish_frame` call.
                // SAFETY:
                // index is verified on `DescriptorChain` creation.
                queue
                    .write_used_element(self.rx_buffer.used_descriptors, index, 0)
                    .unwrap();
                self.rx_buffer.used_descriptors += 1;
            }
        }

        Ok(())
    }

    // Tries to detour the frame to MMDS and if MMDS doesn't accept it, sends it on the host TAP.
    //
    // Returns whether MMDS consumed the frame.
    fn write_to_mmds_or_tap(
        mmds_ns: Option<&mut MmdsNetworkStack>,
        rate_limiter: &mut RateLimiter,
        headers: &mut [u8],
        frame_iovec: &IoVecBuffer,
        tap: &mut Tap,
        guest_mac: Option<MacAddr>,
        net_metrics: &NetDeviceMetrics,
    ) -> Result<bool, NetError> {
        // There is a potential for a TOCTOU race condition here where,
        // when MMDS is enabled, the guest can rewrite packet headers between
        // the time that we check that a packet should be detoured to MMDS,
        // and the time that we forward it to the TAP.
        //
        // The implication of this is that a malicious guest can construct a
        // packet destined for the TAP (i.e., dest_ip != 169.254.169.254), then race
        // to overwrite the destination IP to 169.254.169.254. the packet will
        // then be sent over the TAP towards the host's IMDS store.
        //
        // We do not plan to fix this for a few reasons:
        //
        // 1. Without MMDS enabled, packets with destination IP 169.254.169.254
        //    will be forwarded to the TAP without filtering. Operators should
        //    not rely on MMDS for IMDS access control.
        // 2. Guest originated traffic is treated as untrusted and Firecracker
        //    does not filter IPv4 packets. Operators deploying Firecracker
        //    based services should implement host-level firewall rules to
        //    restrict guest egress traffic.
        // 3. Preventing this TOCTOU by copying packets to to a host buffer
        //    before routing decisions would significantly reduce guest-to-host
        //    TCP throughput, which is not justifiable given the mitigations
        //    available at host-level.

        // Read the frame headers from the IoVecBuffer
        let max_header_len = headers.len();
        let header_len = frame_iovec
            .read_volatile_at(&mut &mut *headers, 0, max_header_len)
            .map_err(|err| {
                error!("Received malformed TX buffer: {:?}", err);
                net_metrics.tx_malformed_frames.inc();
                NetError::VnetHeaderMissing
            })?;

        let headers = frame_bytes_from_buf(&headers[..header_len]).inspect_err(|_| {
            error!("VNET headers missing in TX frame");
            net_metrics.tx_malformed_frames.inc();
        })?;

        if let Some(ns) = mmds_ns
            && ns.is_mmds_frame(headers)
        {
            let mut frame = vec![0u8; frame_iovec.len() as usize - vnet_hdr_len()];
            // Ok to unwrap here, because we are passing a buffer that has the exact size
            // of the `IoVecBuffer` minus the VNET headers.
            frame_iovec
                .read_exact_volatile_at(&mut frame, vnet_hdr_len())
                .unwrap();
            let _ = ns.detour_frame(&frame);
            METRICS.mmds.rx_accepted.inc();

            // MMDS frames are not accounted by the rate limiter.
            Self::rate_limiter_replenish_op(rate_limiter, u64::from(frame_iovec.len()));

            // MMDS consumed the frame.
            return Ok(true);
        }

        // This frame goes to the TAP.

        // Check for guest MAC spoofing.
        if let Some(guest_mac) = guest_mac {
            let _ = EthernetFrame::from_bytes(headers).map(|eth_frame| {
                if guest_mac != eth_frame.src_mac() {
                    net_metrics.tx_spoofed_mac_count.inc();
                }
            });
        }

        let _metric = net_metrics.tap_write_agg.record_latency_metrics();
        match Self::write_tap(tap, frame_iovec) {
            Ok(_) => {
                let len = u64::from(frame_iovec.len());
                net_metrics.tx_bytes_count.add(len);
                net_metrics.tx_packets_count.inc();
                net_metrics.tx_count.inc();
            }
            Err(err) => {
                error!("Failed to write to tap: {:?}", err);
                net_metrics.tap_write_fails.inc();
            }
        };
        Ok(false)
    }

    // We currently prioritize packets from the MMDS over regular network packets.
    fn read_from_mmds_or_tap(&mut self) -> Result<Option<u32>, NetError> {
        // We only want to read from TAP (or mmds) if we have at least 64K of available capacity as
        // this is the max size of 1 packet.
        // SAFETY:
        // * MAX_BUFFER_SIZE is constant and fits into u32
        #[allow(clippy::cast_possible_truncation)]
        if self.rx_buffer.capacity() < MAX_BUFFER_SIZE as u32 {
            self.parse_rx_descriptors()?;

            // If after parsing the RX queue we still don't have enough capacity, stop processing RX
            // frames.
            if self.rx_buffer.capacity() < MAX_BUFFER_SIZE as u32 {
                return Ok(None);
            }
        }

        if let Some(ns) = self.mmds_ns.as_mut()
            && let Some(len) =
                ns.write_next_frame(frame_bytes_from_buf_mut(&mut self.rx_frame_buf)?)
        {
            let len = len.get();
            METRICS.mmds.tx_frames.inc();
            METRICS.mmds.tx_bytes.add(len as u64);
            init_vnet_hdr(&mut self.rx_frame_buf);
            self.rx_buffer
                .iovec
                .write_all_volatile_at(&self.rx_frame_buf[..vnet_hdr_len() + len], 0)?;
            // SAFETY:
            // * len will never be bigger that u32::MAX because mmds is bound
            // by the size of `self.rx_frame_buf` which is MAX_BUFFER_SIZE size.
            let len: u32 = (vnet_hdr_len() + len).try_into().unwrap();

            // SAFETY:
            // * We checked that `rx_buffer` includes at least one `DescriptorChain`
            // * `rx_frame_buf` has size of `MAX_BUFFER_SIZE` and all `DescriptorChain` objects are
            //   at least that big.
            unsafe {
                self.rx_buffer.mark_used(len, &mut self.queues[RX_INDEX]);
            }
            return Ok(Some(len));
        }

        // SAFETY:
        // * We ensured that `self.rx_buffer` has at least one DescriptorChain parsed in it.
        let len = unsafe { self.read_tap().map_err(NetError::IO) }?;
        // SAFETY:
        // * len will never be bigger that u32::MAX
        let len: u32 = len.try_into().unwrap();

        // SAFETY:
        // * `rx_buffer` has at least one `DescriptorChain`
        // * `read_tap` passes the first `DescriptorChain` to `readv` so we can't have read more
        //   bytes than its capacity.
        unsafe {
            self.rx_buffer.mark_used(len, &mut self.queues[RX_INDEX]);
        }
        Ok(Some(len))
    }

    /// Read as many frames as possible.
    fn process_rx(&mut self) -> Result<(), DeviceError> {
        loop {
            match self.read_from_mmds_or_tap() {
                Ok(None) => {
                    self.metrics.no_rx_avail_buffer.inc();
                    break;
                }
                Ok(Some(bytes)) => {
                    self.metrics.rx_count.inc();
                    self.metrics.rx_bytes_count.add(bytes as u64);
                    self.metrics.rx_packets_count.inc();
                    if !self.rate_limited_rx_single_frame(bytes) {
                        break;
                    }
                }
                Err(NetError::IO(err)) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    match err.raw_os_error() {
                        Some(err) if err == EAGAIN => (),
                        _ => {
                            error!("Failed to read tap: {:?}", err);
                            self.metrics.tap_read_fails.inc();
                            return Err(DeviceError::FailedReadTap);
                        }
                    };
                    break;
                }
                Err(NetError::InvalidAvailIdx(err)) => {
                    return Err(DeviceError::InvalidAvailIdx(err));
                }
                Err(err) => {
                    error!("Spurious error in network RX: {:?}", err);
                }
            }
        }

        self.try_signal_queue(NetQueue::Rx)
    }

    fn resume_rx(&mut self) -> Result<(), DeviceError> {
        // First try to handle any deferred frame
        if self.rx_buffer.used_bytes != 0 {
            // If can't finish sending this frame, re-set it as deferred and return; we can't
            // process any more frames from the TAP.
            if !self.rate_limited_rx_single_frame(self.rx_buffer.used_bytes) {
                return Ok(());
            }
        }

        self.process_rx()
    }

    fn process_tx(&mut self) -> Result<(), DeviceError> {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = &self.device_state.active_state().unwrap().mem;

        // The MMDS network stack works like a state machine, based on synchronous calls, and
        // without being added to any event loop. If any frame is accepted by the MMDS, we also
        // trigger a process_rx() which checks if there are any new frames to be sent, starting
        // with the MMDS network stack.
        let mut process_rx_for_mmds = false;
        let mut used_any = false;
        let tx_queue = &mut self.queues[TX_INDEX];

        while let Some(head) = tx_queue.pop_or_enable_notification()? {
            self.metrics
                .tx_remaining_reqs_count
                .add(tx_queue.len().into());
            let head_index = head.index;
            // Parse IoVecBuffer from descriptor head
            // SAFETY: This descriptor chain is only loaded once
            // virtio requests are handled sequentially so no two IoVecBuffers
            // are live at the same time, meaning this has exclusive ownership over the memory
            if unsafe { self.tx_buffer.load_descriptor_chain(mem, head).is_err() } {
                self.metrics.tx_fails.inc();
                tx_queue.add_used(head_index, 0)?;
                continue;
            };

            // We only handle frames that are up to MAX_BUFFER_SIZE
            if self.tx_buffer.len() as usize > MAX_BUFFER_SIZE {
                error!("net: received too big frame from driver");
                self.metrics.tx_malformed_frames.inc();
                tx_queue.add_used(head_index, 0)?;
                continue;
            }

            if !Self::rate_limiter_consume_op(
                &mut self.tx_rate_limiter,
                u64::from(self.tx_buffer.len()),
            ) {
                tx_queue.undo_pop();
                self.metrics.tx_rate_limiter_throttled.inc();
                break;
            }

            let frame_consumed_by_mmds = Self::write_to_mmds_or_tap(
                self.mmds_ns.as_mut(),
                &mut self.tx_rate_limiter,
                &mut self.tx_frame_headers,
                &self.tx_buffer,
                &mut self.tap,
                self.guest_mac,
                &self.metrics,
            )
            .unwrap_or(false);
            if frame_consumed_by_mmds && self.rx_buffer.used_bytes == 0 {
                // MMDS consumed this frame/request, let's also try to process the response.
                process_rx_for_mmds = true;
            }

            tx_queue.add_used(head_index, 0)?;
            used_any = true;
        }

        if !used_any {
            self.metrics.no_tx_avail_buffer.inc();
        }

        // Cleanup tx_buffer to ensure no two buffers point at the same memory
        self.tx_buffer.clear();
        self.try_signal_queue(NetQueue::Tx)?;

        // An incoming frame for the MMDS may trigger the transmission of a new message.
        if process_rx_for_mmds {
            self.process_rx()
        } else {
            Ok(())
        }
    }

    /// Builds the offload features we will setup on the TAP device based on the features that the
    /// guest supports.
    pub fn build_tap_offload_features(guest_supported_features: u64) -> u32 {
        let add_if_supported =
            |tap_features: &mut u32, supported_features: u64, tap_flag: u32, virtio_flag: u32| {
                if supported_features & (1 << virtio_flag) != 0 {
                    *tap_features |= tap_flag;
                }
            };

        let mut tap_features: u32 = 0;

        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            generated::TUN_F_CSUM,
            VIRTIO_NET_F_GUEST_CSUM,
        );
        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            generated::TUN_F_UFO,
            VIRTIO_NET_F_GUEST_UFO,
        );
        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            generated::TUN_F_TSO4,
            VIRTIO_NET_F_GUEST_TSO4,
        );
        add_if_supported(
            &mut tap_features,
            guest_supported_features,
            generated::TUN_F_TSO6,
            VIRTIO_NET_F_GUEST_TSO6,
        );

        tap_features
    }

    /// Updates the parameters for the rate limiters
    pub fn patch_rate_limiters(
        &mut self,
        rx_bytes: BucketUpdate,
        rx_ops: BucketUpdate,
        tx_bytes: BucketUpdate,
        tx_ops: BucketUpdate,
    ) {
        self.rx_rate_limiter.update_buckets(rx_bytes, rx_ops);
        self.tx_rate_limiter.update_buckets(tx_bytes, tx_ops);
    }

    /// Reads a frame from the TAP device inside the first descriptor held by `self.rx_buffer`.
    ///
    /// # Safety
    ///
    /// `self.rx_buffer` needs to have at least one descriptor chain parsed
    pub unsafe fn read_tap(&mut self) -> std::io::Result<usize> {
        let slice = if self.has_feature(VIRTIO_NET_F_MRG_RXBUF as u64) {
            self.rx_buffer.all_chains_slice_mut()
        } else {
            self.rx_buffer.single_chain_slice_mut()
        };
        self.tap.read_iovec(slice)
    }

    fn write_tap(tap: &mut Tap, buf: &IoVecBuffer) -> std::io::Result<usize> {
        tap.write_iovec(buf)
    }

    /// Process a single RX queue event.
    ///
    /// This is called by the event manager responding to the guest adding a new
    /// buffer in the RX queue.
    pub fn process_rx_queue_event(&mut self) {
        self.metrics.rx_queue_event_count.inc();

        if let Err(err) = self.queue_evts[RX_INDEX].read() {
            // rate limiters present but with _very high_ allowed rate
            error!("Failed to get rx queue event: {:?}", err);
            self.metrics.event_fails.inc();
            return;
        } else {
            self.parse_rx_descriptors().unwrap();
        }

        if self.rx_rate_limiter.is_blocked() {
            self.metrics.rx_rate_limiter_throttled.inc();
        } else {
            // If the limiter is not blocked, resume the receiving of bytes.
            self.resume_rx()
                .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
        }
    }

    pub fn process_tap_rx_event(&mut self) {
        // This is safe since we checked in the event handler that the device is activated.
        self.metrics.rx_tap_event_count.inc();

        // While limiter is blocked, don't process any more incoming.
        if self.rx_rate_limiter.is_blocked() {
            self.metrics.rx_rate_limiter_throttled.inc();
            return;
        }

        self.resume_rx()
            .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
    }

    /// Process a single TX queue event.
    ///
    /// This is called by the event manager responding to the guest adding a new
    /// buffer in the TX queue.
    pub fn process_tx_queue_event(&mut self) {
        self.metrics.tx_queue_event_count.inc();
        if let Err(err) = self.queue_evts[TX_INDEX].read() {
            error!("Failed to get tx queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if !self.tx_rate_limiter.is_blocked()
        // If the limiter is not blocked, continue transmitting bytes.
        {
            self.process_tx()
                .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
        } else {
            self.metrics.tx_rate_limiter_throttled.inc();
        }
    }

    pub fn process_rx_rate_limiter_event(&mut self) {
        self.metrics.rx_event_rate_limiter_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.

        match self.rx_rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to receive the frame.
                self.resume_rx()
                    .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
            }
            Err(err) => {
                error!("Failed to get rx rate-limiter event: {:?}", err);
                self.metrics.event_fails.inc();
            }
        }
    }

    pub fn process_tx_rate_limiter_event(&mut self) {
        self.metrics.tx_rate_limiter_event_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        match self.tx_rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to send the frame.
                self.process_tx()
                    .unwrap_or_else(|err| report_net_event_fail(&self.metrics, err));
            }
            Err(err) => {
                error!("Failed to get tx rate-limiter event: {:?}", err);
                self.metrics.event_fails.inc();
            }
        }
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        if let Err(DeviceError::InvalidAvailIdx(err)) = self.resume_rx() {
            return Err(err);
        }
        if let Err(DeviceError::InvalidAvailIdx(err)) = self.process_tx() {
            return Err(err);
        }

        Ok(())
    }
}

impl VirtioDevice for Net {
    impl_device_type!(VirtioDeviceType::Net);

    fn id(&self) -> &str {
        &self.id
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
            .expect("Device is not implemented")
            .interrupt
            .deref()
    }

    fn config_as_bytes(&self) -> &[u8] {
        self.config_space.as_slice()
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.metrics.cfg_fails.inc();
        warn!(
            "virtio-net: guest driver attempted to write device config (offset={:#x}, len={:#x})",
            offset,
            data.len()
        );
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

        let event_idx = self.has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX));
        if event_idx {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        let supported_flags: u32 = Net::build_tap_offload_features(self.acked_features);
        self.tap
            .set_offload(supported_flags)
            .map_err(super::super::ActivateError::TapSetOffload)?;

        self.rx_buffer.min_buffer_size = self.minimum_rx_buffer_size();

        if self.activate_evt.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    /// Prepare saving state
    fn prepare_save(&mut self) {
        // We shouldn't be messing with the queue if the device is not activated.
        // Anyways, if it isn't there's nothing to prepare; we haven't parsed any
        // descriptors yet from it and we can't have a deferred frame.
        if !self.is_activated() {
            return;
        }

        // Give potential deferred RX frame to guest
        self.rx_buffer.finish_frame(&mut self.queues[RX_INDEX]);
        // Reset the parsed available descriptors, so we will re-parse them
        self.queues[RX_INDEX].next_avail -=
            Wrapping(u16::try_from(self.rx_buffer.parsed_descriptors.len()).unwrap());
        self.rx_buffer.parsed_descriptors.clear();
        self.rx_buffer.iovec.clear();
        self.rx_buffer.used_bytes = 0;
        self.rx_buffer.used_descriptors = 0;
    }
}
