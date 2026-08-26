// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring block devices.

use device::ConfigSpace;
use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

use super::device::DiskProperties;
use super::*;
use crate::devices::virtio::block::persist::BlockConstructorArgs;
use crate::devices::virtio::block::virtio::device::FileEngineType;
use crate::devices::virtio::block::virtio::metrics::BlockMetricsPerDevice;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_F_RO;
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;

/// Holds info about block's file engine type. Gets saved in snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileEngineTypeState {
    /// Sync File Engine.
    // If the snap version does not contain the `FileEngineType`, it must have been snapshotted
    // on a VM using the Sync backend.
    #[default]
    Sync,
    /// Async File Engine.
    Async,
}

impl From<FileEngineType> for FileEngineTypeState {
    fn from(file_engine_type: FileEngineType) -> Self {
        match file_engine_type {
            FileEngineType::Sync => FileEngineTypeState::Sync,
            FileEngineType::Async => FileEngineTypeState::Async,
        }
    }
}

impl From<FileEngineTypeState> for FileEngineType {
    fn from(file_engine_type_state: FileEngineTypeState) -> Self {
        match file_engine_type_state {
            FileEngineTypeState::Sync => FileEngineType::Sync,
            FileEngineTypeState::Async => FileEngineType::Async,
        }
    }
}

/// Holds info about the block device. Gets saved in snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioBlockState {
    id: String,
    partuuid: Option<String>,
    cache_type: CacheType,
    root_device: bool,
    disk_path: String,
    pub virtio_state: VirtioDeviceState,
    rate_limiter_state: RateLimiterState,
    file_engine_type: FileEngineTypeState,
}

impl Persist<'_> for VirtioBlock {
    type State = VirtioBlockState;
    type ConstructorArgs = BlockConstructorArgs;
    type Error = VirtioBlockError;

    fn save(&self) -> Self::State {
        // Save device state.
        VirtioBlockState {
            id: self.id.clone(),
            partuuid: self.partuuid.clone(),
            cache_type: self.cache_type,
            root_device: self.root_device,
            disk_path: self.disk.file_path.clone(),
            virtio_state: VirtioDeviceState::from_device(self),
            rate_limiter_state: self.rate_limiter.save(),
            file_engine_type: FileEngineTypeState::from(self.file_engine_type()),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let is_read_only = state.virtio_state.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0;
        let rate_limiter = RateLimiter::restore((), &state.rate_limiter_state)
            .map_err(VirtioBlockError::RateLimiter)?;

        let disk_properties = DiskProperties::new(
            state.disk_path.clone(),
            is_read_only,
            state.file_engine_type.into(),
        )?;

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?];

        let queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                VirtioDeviceType::Block,
                BLOCK_NUM_QUEUES,
                FIRECRACKER_MAX_QUEUE_SIZE,
            )
            .map_err(VirtioBlockError::Persist)?;

        let avail_features = state.virtio_state.avail_features;
        let acked_features = state.virtio_state.acked_features;

        let config_space = ConfigSpace {
            capacity: disk_properties.nsectors.to_le(),
        };

        Ok(VirtioBlock {
            avail_features,
            acked_features,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,

            queues,
            queue_evts,
            device_state: DeviceState::Inactive,

            id: state.id.clone(),
            partuuid: state.partuuid.clone(),
            cache_type: state.cache_type,
            root_device: state.root_device,
            read_only: is_read_only,

            disk: disk_properties,
            rate_limiter,
            is_io_engine_throttled: false,
            metrics: BlockMetricsPerDevice::alloc(state.id.clone()),
        })
    }
}
