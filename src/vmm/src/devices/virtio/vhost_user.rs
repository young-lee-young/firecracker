// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use vhost::vhost_user::message::*;
use vhost::vhost_user::{Frontend, VhostUserFrontend};
use vhost::{Error as VhostError, VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{Address, GuestMemory, GuestMemoryError, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::vstate::memory::GuestMemoryMmap;

/// vhost-user error.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VhostUserError {
    /// Invalid available address
    AvailAddress(GuestMemoryError),
    /// Failed to connect to UDS Unix stream: {0}
    Connect(#[from] std::io::Error),
    /// Invalid descriptor table address
    DescriptorTableAddress(GuestMemoryError),
    /// Get features failed: {0}
    VhostUserGetFeatures(VhostError),
    /// Get protocol features failed: {0}
    VhostUserGetProtocolFeatures(VhostError),
    /// Set owner failed: {0}
    VhostUserSetOwner(VhostError),
    /// Set features failed: {0}
    VhostUserSetFeatures(VhostError),
    /// Set protocol features failed: {0}
    VhostUserSetProtocolFeatures(VhostError),
    /// Set mem table failed: {0}
    VhostUserSetMemTable(VhostError),
    /// Set vring num failed: {0}
    VhostUserSetVringNum(VhostError),
    /// Set vring addr failed: {0}
    VhostUserSetVringAddr(VhostError),
    /// Set vring base failed: {0}
    VhostUserSetVringBase(VhostError),
    /// Set vring call failed: {0}
    VhostUserSetVringCall(VhostError),
    /// Set vring kick failed: {0}
    VhostUserSetVringKick(VhostError),
    /// Set vring enable failed: {0}
    VhostUserSetVringEnable(VhostError),
    /// Failed to read vhost eventfd: No memory region found
    VhostUserNoMemoryRegion,
    /// Invalid used address
    UsedAddress(GuestMemoryError),
}

// Trait with all methods we use from `Frontend` from vhost crate.
// It allows us to create a mock implementation of the `Frontend`
// to verify calls to the backend.
// All methods have default impl in order to simplify mock impls.
pub trait VhostUserHandleBackend: Sized {
    /// Constructor of `Frontend`
    fn from_stream(_sock: UnixStream, _max_queue_num: u64) -> Self {
        unimplemented!()
    }

    fn set_hdr_flags(&self, _flags: VhostUserHeaderFlag) {
        unimplemented!()
    }

    /// Get from the underlying vhost implementation the feature bitmask.
    fn get_features(&self) -> Result<u64, vhost::Error> {
        unimplemented!()
    }

    /// Enable features in the underlying vhost implementation using a bitmask.
    fn set_features(&self, _features: u64) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the current Frontend as an owner of the session.
    fn set_owner(&self) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the memory map regions on the slave so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    fn set_mem_table(&self, _regions: &[VhostUserMemoryRegionInfo]) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the size of the queue.
    fn set_vring_num(&self, _queue_index: usize, _num: u16) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Sets the addresses of the different aspects of the vring.
    fn set_vring_addr(
        &self,
        _queue_index: usize,
        _config_data: &VringConfigData,
    ) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Sets the base offset in the available vring.
    fn set_vring_base(&self, _queue_index: usize, _base: u16) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the event file descriptor to signal when buffers are used.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// will be used instead of waiting for the call.
    fn set_vring_call(&self, _queue_index: usize, _fd: &EventFd) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the event file descriptor for adding buffers to the vring.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// should be used instead of waiting for a kick.
    fn set_vring_kick(&self, _queue_index: usize, _fd: &EventFd) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures, vhost::Error> {
        unimplemented!()
    }

    fn set_protocol_features(
        &mut self,
        _features: VhostUserProtocolFeatures,
    ) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    fn set_vring_enable(&mut self, _queue_index: usize, _enable: bool) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    fn get_config(
        &mut self,
        _offset: u32,
        _size: u32,
        _flags: VhostUserConfigFlags,
        _buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
        unimplemented!()
    }

    fn set_config(
        &mut self,
        _offset: u32,
        _flags: VhostUserConfigFlags,
        _buf: &[u8],
    ) -> Result<(), vhost::Error> {
        unimplemented!()
    }
}

impl VhostUserHandleBackend for Frontend {
    fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
        Frontend::from_stream(sock, max_queue_num)
    }

    fn set_hdr_flags(&self, flags: VhostUserHeaderFlag) {
        self.set_hdr_flags(flags)
    }

    /// Get from the underlying vhost implementation the feature bitmask.
    fn get_features(&self) -> Result<u64, vhost::Error> {
        <Frontend as VhostBackend>::get_features(self)
    }

    /// Enable features in the underlying vhost implementation using a bitmask.
    fn set_features(&self, features: u64) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_features(self, features)
    }

    /// Set the current Frontend as an owner of the session.
    fn set_owner(&self) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_owner(self)
    }

    /// Set the memory map regions on the slave so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_mem_table(self, regions)
    }

    /// Set the size of the queue.
    fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_num(self, queue_index, num)
    }

    /// Sets the addresses of the different aspects of the vring.
    fn set_vring_addr(
        &self,
        queue_index: usize,
        config_data: &VringConfigData,
    ) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_addr(self, queue_index, config_data)
    }

    /// Sets the base offset in the available vring.
    fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_base(self, queue_index, base)
    }

    /// Set the event file descriptor to signal when buffers are used.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// will be used instead of waiting for the call.
    fn set_vring_call(&self, queue_index: usize, fd: &EventFd) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_call(self, queue_index, fd)
    }

    /// Set the event file descriptor for adding buffers to the vring.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// should be used instead of waiting for a kick.
    fn set_vring_kick(&self, queue_index: usize, fd: &EventFd) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_kick(self, queue_index, fd)
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures, vhost::Error> {
        <Frontend as VhostUserFrontend>::get_protocol_features(self)
    }

    fn set_protocol_features(
        &mut self,
        features: VhostUserProtocolFeatures,
    ) -> Result<(), vhost::Error> {
        <Frontend as VhostUserFrontend>::set_protocol_features(self, features)
    }

    fn set_vring_enable(&mut self, queue_index: usize, enable: bool) -> Result<(), vhost::Error> {
        <Frontend as VhostUserFrontend>::set_vring_enable(self, queue_index, enable)
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
        <Frontend as VhostUserFrontend>::get_config(self, offset, size, flags, buf)
    }

    fn set_config(
        &mut self,
        offset: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(), vhost::Error> {
        <Frontend as VhostUserFrontend>::set_config(self, offset, flags, buf)
    }
}

pub type VhostUserHandle = VhostUserHandleImpl<Frontend>;

/// vhost-user socket handle
#[derive(Clone)]
pub struct VhostUserHandleImpl<T: VhostUserHandleBackend> {
    pub vu: T,
    pub socket_path: String,
}

impl<T: VhostUserHandleBackend> std::fmt::Debug for VhostUserHandleImpl<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserHandle")
            .field("socket_path", &self.socket_path)
            .finish()
    }
}

impl<T: VhostUserHandleBackend> VhostUserHandleImpl<T> {
    /// Connect to the vhost-user backend socket and mark self as an
    /// owner of the session.
    pub fn new(socket_path: &str, num_queues: u64) -> Result<Self, VhostUserError> {
        let stream = UnixStream::connect(socket_path).map_err(VhostUserError::Connect)?;

        let vu = T::from_stream(stream, num_queues);
        vu.set_owner().map_err(VhostUserError::VhostUserSetOwner)?;

        Ok(Self {
            vu,
            socket_path: socket_path.to_string(),
        })
    }

    /// Set vhost-user features to the backend.
    pub fn set_features(&self, features: u64) -> Result<(), VhostUserError> {
        self.vu
            .set_features(features)
            .map_err(VhostUserError::VhostUserSetFeatures)
    }

    /// Set vhost-user protocol features to the backend.
    pub fn set_protocol_features(
        &mut self,
        acked_features: u64,
        acked_protocol_features: u64,
    ) -> Result<(), VhostUserError> {
        if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0
            && let Some(acked_protocol_features) =
                VhostUserProtocolFeatures::from_bits(acked_protocol_features)
        {
            self.vu
                .set_protocol_features(acked_protocol_features)
                .map_err(VhostUserError::VhostUserSetProtocolFeatures)?;

            if acked_protocol_features.contains(VhostUserProtocolFeatures::REPLY_ACK) {
                self.vu.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
            }
        }

        Ok(())
    }

    /// Negotiate virtio and protocol features with the backend.
    pub fn negotiate_features(
        &mut self,
        avail_features: u64,
        avail_protocol_features: VhostUserProtocolFeatures,
    ) -> Result<(u64, u64), VhostUserError> {
        // Get features from backend, do negotiation to get a feature collection which
        // both VMM and backend support.
        let backend_features = self
            .vu
            .get_features()
            .map_err(VhostUserError::VhostUserGetFeatures)?;
        let acked_features = avail_features & backend_features;

        let acked_protocol_features =
            // If frontend can negotiate protocol features.
            if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
                let backend_protocol_features = self
                    .vu
                    .get_protocol_features()
                    .map_err(VhostUserError::VhostUserGetProtocolFeatures)?;

                let acked_protocol_features = avail_protocol_features & backend_protocol_features;

                self.vu
                    .set_protocol_features(acked_protocol_features)
                    .map_err(VhostUserError::VhostUserSetProtocolFeatures)?;

                acked_protocol_features
            } else {
                VhostUserProtocolFeatures::empty()
            };

        if acked_protocol_features.contains(VhostUserProtocolFeatures::REPLY_ACK) {
            self.vu.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
        }

        Ok((acked_features, acked_protocol_features.bits()))
    }

    /// Update guest memory table to the backend.
    fn update_mem_table(&self, mem: &GuestMemoryMmap) -> Result<(), VhostUserError> {
        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();

        for region in mem.iter() {
            let (mmap_handle, mmap_offset) = match region.file_offset() {
                Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
                None => {
                    return Err(VhostUserError::VhostUserNoMemoryRegion);
                }
            };

            let vhost_user_net_reg = VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len(),
                userspace_addr: region.inner.as_ptr() as u64,
                mmap_offset,
                mmap_handle,
            };
            regions.push(vhost_user_net_reg);
        }

        self.vu
            .set_mem_table(regions.as_slice())
            .map_err(VhostUserError::VhostUserSetMemTable)?;

        Ok(())
    }

    /// Set up vhost-user backend. This includes updating memory table,
    /// sending information about virtio rings and enabling them.
    pub fn setup_backend(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: &[(usize, &Queue, &EventFd)],
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), VhostUserError> {
        // Provide the memory table to the backend.
        self.update_mem_table(mem)?;

        // Send set_vring_num here, since it could tell backends, like SPDK,
        // how many virt queues to be handled, which backend required to know
        // at early stage.
        for (queue_index, queue, _) in queues.iter() {
            self.vu
                .set_vring_num(*queue_index, queue.size)
                .map_err(VhostUserError::VhostUserSetVringNum)?;
        }

        for (queue_index, queue, queue_evt) in queues.iter() {
            let config_data = VringConfigData {
                queue_max_size: queue.max_size,
                queue_size: queue.size,
                flags: 0u32,
                desc_table_addr: mem
                    .get_host_address(queue.desc_table_address)
                    .map_err(VhostUserError::DescriptorTableAddress)?
                    as u64,
                used_ring_addr: mem
                    .get_host_address(queue.used_ring_address)
                    .map_err(VhostUserError::UsedAddress)? as u64,
                avail_ring_addr: mem
                    .get_host_address(queue.avail_ring_address)
                    .map_err(VhostUserError::AvailAddress)? as u64,
                log_addr: None,
            };

            self.vu
                .set_vring_addr(*queue_index, &config_data)
                .map_err(VhostUserError::VhostUserSetVringAddr)?;
            self.vu
                .set_vring_base(*queue_index, queue.avail_ring_idx_get())
                .map_err(VhostUserError::VhostUserSetVringBase)?;

            // No matter the queue, we set irq_evt for signaling the guest that buffers were
            // consumed.
            self.vu
                .set_vring_call(
                    *queue_index,
                    interrupt
                        .notifier(VirtioInterruptType::Queue(
                            (*queue_index).try_into().unwrap_or_else(|_| {
                                panic!("vhost-user: invalid queue index: {}", *queue_index)
                            }),
                        ))
                        .as_ref()
                        .unwrap(),
                )
                .map_err(VhostUserError::VhostUserSetVringCall)?;

            self.vu
                .set_vring_kick(*queue_index, queue_evt)
                .map_err(VhostUserError::VhostUserSetVringKick)?;

            self.vu
                .set_vring_enable(*queue_index, true)
                .map_err(VhostUserError::VhostUserSetVringEnable)?;
        }

        Ok(())
    }
}
