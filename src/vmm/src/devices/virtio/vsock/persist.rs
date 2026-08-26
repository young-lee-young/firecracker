// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state and support structures for persisting Vsock devices and backends.

use std::fmt::Debug;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::*;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDeviceType};
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;

/// The Vsock serializable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockState {
    /// The vsock backend state.
    pub backend: VsockBackendState,
    /// The vsock frontend state.
    pub frontend: VsockFrontendState,
}

/// The Vsock frontend serializable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockFrontendState {
    /// Context Identifier.
    pub cid: u64,
    pub virtio_state: VirtioDeviceState,
}

/// The Vsock Unix Backend serializable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockBackendState {
    /// The path for the UDS socket.
    pub uds_path: String,
    /// The last used host-side port.
    pub local_port_last: u32,
}

/// A helper structure that holds the constructor arguments for VsockUnixBackend
#[derive(Debug)]
pub struct VsockConstructorArgs<B> {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
    /// The vsock Unix Backend.
    pub backend: B,
}

/// A helper structure that holds the constructor arguments for VsockUnixBackend
#[derive(Debug)]
pub struct VsockUdsConstructorArgs {
    /// cid available in VsockFrontendState.
    pub cid: u64,
}

impl Persist<'_> for VsockUnixBackend {
    type State = VsockBackendState;
    type ConstructorArgs = VsockUdsConstructorArgs;
    type Error = VsockUnixBackendError;

    fn save(&self) -> Self::State {
        VsockBackendState {
            uds_path: self.host_sock_path.clone(),
            local_port_last: self.local_port_last,
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mut backend = Self::new(constructor_args.cid, state.uds_path.clone())?;
        backend.local_port_last = state.local_port_last;
        Ok(backend)
    }
}

impl<B> Persist<'_> for Vsock<B>
where
    B: VsockBackend + 'static + Debug,
{
    type State = VsockFrontendState;
    type ConstructorArgs = VsockConstructorArgs<B>;
    type Error = VsockError;

    fn save(&self) -> Self::State {
        VsockFrontendState {
            cid: self.cid(),
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        // Restore queues.
        let queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                VirtioDeviceType::Vsock,
                defs::VSOCK_NUM_QUEUES,
                FIRECRACKER_MAX_QUEUE_SIZE,
            )
            .map_err(VsockError::VirtioState)?;
        let mut vsock = Self::with_queues(state.cid, constructor_args.backend, queues)?;

        vsock.acked_features = state.virtio_state.acked_features;
        vsock.avail_features = state.virtio_state.avail_features;
        vsock.device_state = DeviceState::Inactive;
        Ok(vsock)
    }
}
