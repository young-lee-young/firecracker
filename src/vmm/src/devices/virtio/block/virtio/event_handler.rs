// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use super::io::FileEngine;
use crate::devices::virtio::block::virtio::device::VirtioBlock;
use crate::devices::virtio::device::VirtioDevice;
use crate::logger::{error, warn};

impl VirtioBlock {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_QUEUE: u32 = 1;
    const PROCESS_RATE_LIMITER: u32 = 2;
    const PROCESS_ASYNC_COMPLETION: u32 = 3;

    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_evts[0],
            Self::PROCESS_QUEUE,
            EventSet::IN,
        )) {
            error!("Failed to register queue event: {}", err);
        }
        if let Err(err) = ops.add(Events::with_data(
            &self.rate_limiter,
            Self::PROCESS_RATE_LIMITER,
            EventSet::IN,
        )) {
            error!("Failed to register ratelimiter event: {}", err);
        }
        if let FileEngine::Async(ref engine) = self.disk.file_engine
            && let Err(err) = ops.add(Events::with_data(
                engine.completion_evt(),
                Self::PROCESS_ASYNC_COMPLETION,
                EventSet::IN,
            ))
        {
            error!("Failed to register IO engine completion event: {}", err);
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.activate_evt,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("Failed to register activate event: {}", err);
        }
    }

    fn process_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = self.activate_evt.read() {
            error!("Failed to consume block activate event: {:?}", err);
        }
        self.register_runtime_events(ops);
        if let Err(err) = ops.remove(Events::with_data(
            &self.activate_evt,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("Failed to un-register activate event: {}", err);
        }
    }
}

impl MutEventSubscriber for VirtioBlock {
    // Handle an event for queue or rate limiter.
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.data();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "Block: Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            match source {
                Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
                Self::PROCESS_QUEUE => self.process_queue_event(),
                Self::PROCESS_RATE_LIMITER => self.process_rate_limiter_event(),
                Self::PROCESS_ASYNC_COMPLETION => self.process_async_completion_event(),
                _ => warn!("Block: Spurious event received: {:?}", source),
            }
        } else {
            warn!(
                "Block: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if self.is_activated() {
            self.register_runtime_events(ops);
        } else {
            self.register_activate_event(ops);
        }
    }
}
