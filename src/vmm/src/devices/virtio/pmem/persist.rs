// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

use super::device::{ConfigSpace, Pmem, PmemError};
use crate::devices::virtio::device::{DeviceState, VirtioDeviceType};
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::pmem::{PMEM_NUM_QUEUES, PMEM_QUEUE_SIZE};
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;
use crate::vmm_config::pmem::PmemConfig;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmap};
use crate::vstate::vm::{KvmVm, VmError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmemState {
    pub virtio_state: VirtioDeviceState,
    pub config_space: ConfigSpace,
    pub config: PmemConfig,
    pub rate_limiter_state: RateLimiterState,
}

#[derive(Debug)]
pub struct PmemConstructorArgs<'a> {
    pub mem: &'a GuestMemoryMmap,
    pub vm: Arc<KvmVm>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PmemPersistError {
    /// Error resetting VirtIO state: {0}
    VirtioState(#[from] VirtioStateError),
    /// Error creating Pmem devie: {0}
    Pmem(#[from] PmemError),
    /// Error registering memory region: {0}
    KvmVm(#[from] VmError),
    /// Error restoring rate limiter: {0}
    RateLimiter(std::io::Error),
}

impl<'a> Persist<'a> for Pmem {
    type State = PmemState;
    type ConstructorArgs = PmemConstructorArgs<'a>;
    type Error = PmemPersistError;

    fn save(&self) -> Self::State {
        PmemState {
            virtio_state: VirtioDeviceState::from_device(self),
            config_space: self.guest_region.config_space,
            config: self.config.clone(),
            rate_limiter_state: self.rate_limiter.save(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let queues = state.virtio_state.build_queues_checked(
            constructor_args.mem,
            VirtioDeviceType::Pmem,
            PMEM_NUM_QUEUES,
            PMEM_QUEUE_SIZE,
        )?;

        let mut pmem = Pmem::new_with_queues(
            constructor_args.vm,
            state.config.clone(),
            queues,
            state.virtio_state.acked_features,
            Some(state.config_space),
        )?;
        pmem.rate_limiter = RateLimiter::restore((), &state.rate_limiter_state)
            .map_err(PmemPersistError::RateLimiter)?;

        Ok(pmem)
    }
}
