// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring entropy devices.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::devices::virtio::device::VirtioDeviceType;
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::devices::virtio::rng::{Entropy, EntropyError, RNG_NUM_QUEUES};
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyState {
    pub virtio_state: VirtioDeviceState,
    rate_limiter_state: RateLimiterState,
}

#[derive(Debug)]
pub struct EntropyConstructorArgs {
    pub mem: GuestMemoryMmap,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EntropyPersistError {
    /// Create entropy: {0}
    CreateEntropy(#[from] EntropyError),
    /// Virtio state: {0}
    VirtioState(#[from] VirtioStateError),
    /// Restore rate limiter: {0}
    RestoreRateLimiter(#[from] std::io::Error),
}

impl Persist<'_> for Entropy {
    type State = EntropyState;
    type ConstructorArgs = EntropyConstructorArgs;
    type Error = EntropyPersistError;

    fn save(&self) -> Self::State {
        EntropyState {
            virtio_state: VirtioDeviceState::from_device(self),
            rate_limiter_state: self.rate_limiter().save(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let queues = state.virtio_state.build_queues_checked(
            &constructor_args.mem,
            VirtioDeviceType::Rng,
            RNG_NUM_QUEUES,
            FIRECRACKER_MAX_QUEUE_SIZE,
        )?;

        let rate_limiter = RateLimiter::restore((), &state.rate_limiter_state)?;
        let mut entropy = Entropy::new_with_queues(queues, rate_limiter)?;
        entropy.set_avail_features(state.virtio_state.avail_features);
        entropy.set_acked_features(state.virtio_state.acked_features);

        Ok(entropy)
    }
}
