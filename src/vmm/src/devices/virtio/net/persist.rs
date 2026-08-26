// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the structures needed for saving/restoring net devices.

use std::io;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::device::{Net, RxBuffers};
use super::{NET_NUM_QUEUES, NET_QUEUE_MAX_SIZE, RX_INDEX, TapError};
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDeviceType};
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::mmds::data_store::Mmds;
use crate::mmds::ns::MmdsNetworkStack;
use crate::mmds::persist::MmdsNetworkStackState;
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;
use crate::utils::net::mac::MacAddr;
use crate::vstate::memory::GuestMemoryMmap;

/// Information about the network config's that are saved
/// at snapshot.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetConfigSpaceState {
    guest_mac: Option<MacAddr>,
    #[serde(default)]
    mtu: Option<u16>,
}

/// Information about the network device that are saved
/// at snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetState {
    pub id: String,
    pub tap_if_name: String,
    rx_rate_limiter_state: RateLimiterState,
    tx_rate_limiter_state: RateLimiterState,
    /// The associated MMDS network stack.
    pub mmds_ns: Option<MmdsNetworkStackState>,
    config_space: NetConfigSpaceState,
    pub virtio_state: VirtioDeviceState,
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct NetConstructorArgs {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
    /// Pointer to the MMDS data store.
    pub mmds: Option<Arc<Mutex<Mmds>>>,
}

/// Errors triggered when trying to construct a network device at resume time.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum NetPersistError {
    /// Failed to create a network device: {0}
    CreateNet(#[from] super::NetError),
    /// Failed to create a rate limiter: {0}
    CreateRateLimiter(#[from] io::Error),
    /// Failed to re-create the virtio state (i.e queues etc): {0}
    VirtioState(#[from] VirtioStateError),
    /// Indicator that no MMDS is associated with this device.
    NoMmdsDataStore,
    /// Setting tap interface offload flags failed: {0}
    TapSetOffload(TapError),
}

impl Persist<'_> for Net {
    type State = NetState;
    type ConstructorArgs = NetConstructorArgs;
    type Error = NetPersistError;

    fn save(&self) -> Self::State {
        NetState {
            id: self.id.clone(),
            tap_if_name: self.iface_name(),
            rx_rate_limiter_state: self.rx_rate_limiter.save(),
            tx_rate_limiter_state: self.tx_rate_limiter.save(),
            mmds_ns: self.mmds_ns.as_ref().map(|mmds| mmds.save()),
            config_space: NetConfigSpaceState {
                guest_mac: self.guest_mac,
                mtu: self.mtu(),
            },
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        // RateLimiter::restore() can fail at creating a timerfd.
        let rx_rate_limiter = RateLimiter::restore((), &state.rx_rate_limiter_state)?;
        let tx_rate_limiter = RateLimiter::restore((), &state.tx_rate_limiter_state)?;
        let mut net = Net::new(
            state.id.clone(),
            &state.tap_if_name,
            state.config_space.guest_mac,
            rx_rate_limiter,
            tx_rate_limiter,
            state.config_space.mtu,
        )?;

        // We trust the MMIODeviceManager::restore to pass us an MMDS data store reference if
        // there is at least one net device having the MMDS NS present and/or the mmds version was
        // persisted in the snapshot.
        if let Some(mmds_ns) = &state.mmds_ns {
            // We're safe calling unwrap() to discard the error, as MmdsNetworkStack::restore()
            // always returns Ok.
            net.mmds_ns = Some(
                MmdsNetworkStack::restore(
                    constructor_args
                        .mmds
                        .map_or_else(|| Err(NetPersistError::NoMmdsDataStore), Ok)?,
                    mmds_ns,
                )
                .unwrap(),
            );
        }

        net.queues = state.virtio_state.build_queues_checked(
            &constructor_args.mem,
            VirtioDeviceType::Net,
            NET_NUM_QUEUES,
            NET_QUEUE_MAX_SIZE,
        )?;
        net.avail_features = state.virtio_state.avail_features;
        net.acked_features = state.virtio_state.acked_features;

        Ok(net)
    }
}
