// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::Debug;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

use vmm_sys_util::eventfd::EventFd;

use super::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::device_status;
use crate::devices::virtio::queue::Queue;
use crate::logger::{IncMetric, METRICS, error, warn};
use crate::utils::byte_order;
use crate::vstate::bus::BusDevice;
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

// TODO crosvm uses 0 here, but IIRC virtio specified some other vendor id that should be used
const VENDOR_ID: u32 = 0;

/// Interrupt flags (re: interrupt status & acknowledge registers).
/// See linux/virtio_mmio.h.
pub const VIRTIO_MMIO_INT_VRING: u32 = 0x01;
pub const VIRTIO_MMIO_INT_CONFIG: u32 = 0x02;

// required by the virtio mmio device register layout at offset 0 from base
const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;

// current version specified by the mmio standard (legacy devices used 1 here)
const MMIO_VERSION: u32 = 2;

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOTIFY_REG_OFFSET` offset from the MMIO
///    base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
///    is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
#[derive(Debug, Clone)]
pub struct MmioTransport {
    device: Arc<Mutex<dyn VirtioDevice>>,
    // The register where feature bits are stored.
    pub(crate) features_select: u32,
    // The register where features page is selected.
    pub(crate) acked_features_select: u32,
    pub(crate) queue_select: u32,
    pub(crate) device_status: u32,
    pub(crate) config_generation: u32,
    mem: GuestMemoryMmap,
    pub(crate) interrupt: Arc<IrqTrigger>,
    pub is_vhost_user: bool,
}

impl MmioTransport {
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new(
        mem: GuestMemoryMmap,
        interrupt: Arc<IrqTrigger>,
        device: Arc<Mutex<dyn VirtioDevice>>,
        is_vhost_user: bool,
    ) -> MmioTransport {
        MmioTransport {
            device,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            device_status: device_status::INIT,
            config_generation: 0,
            mem,
            interrupt,
            is_vhost_user,
        }
    }

    /// Gets the encapsulated locked VirtioDevice.
    pub fn locked_device(&self) -> MutexGuard<'_, dyn VirtioDevice + 'static> {
        self.device.lock().expect("Poisoned lock")
    }

    /// Gets the encapsulated VirtioDevice.
    pub fn device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.device.clone()
    }

    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status & (set | clr) == set
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
        U: Debug,
    {
        match self
            .locked_device()
            .queues()
            .get(self.queue_select as usize)
        {
            Some(queue) => f(queue),
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        if let Some(queue) = self
            .locked_device()
            .queues_mut()
            .get_mut(self.queue_select as usize)
        {
            f(queue);
            true
        } else {
            false
        }
    }

    fn update_queue_field<F: FnOnce(&mut Queue)>(&mut self, f: F) {
        if self.check_device_status(
            device_status::FEATURES_OK,
            device_status::DRIVER_OK | device_status::FAILED,
        ) {
            self.with_queue_mut(f);
        } else {
            warn!(
                "update virtio queue in invalid state {:#x}",
                self.device_status
            );
        }
    }

    fn reset(&mut self) {
        if self.locked_device().is_activated() {
            warn!("reset device while it's still in active state");
        }
        self.features_select = 0;
        self.acked_features_select = 0;
        self.queue_select = 0;
        self.interrupt.irq_status.store(0, Ordering::SeqCst);
        self.device_status = device_status::INIT;
        // . Keep interrupt_evt and queue_evts as is. There may be pending notifications in those
        //   eventfds, but nothing will happen other than supurious wakeups.
        // . Do not reset config_generation and keep it monotonically increasing
        for queue in self.locked_device().queues_mut() {
            *queue = Queue::new(queue.max_size);
        }
    }

    /// Update device status according to the state machine defined by VirtIO Spec 1.0.
    /// Please refer to VirtIO Spec 1.0, section 2.1.1 and 3.1.1.
    ///
    /// The driver MUST update device status, setting bits to indicate the completed steps
    /// of the driver initialization sequence specified in 3.1. The driver MUST NOT clear
    /// a device status bit. If the driver sets the FAILED bit, the driver MUST later reset
    /// the device before attempting to re-initialize.
    #[allow(unused_assignments)]
    fn set_device_status(&mut self, status: u32) {
        use device_status::*;

        const VALID_TRANSITIONS: &[(u32, u32)] = &[
            (INIT, ACKNOWLEDGE),
            (ACKNOWLEDGE, ACKNOWLEDGE | DRIVER),
            (ACKNOWLEDGE | DRIVER, ACKNOWLEDGE | DRIVER | FEATURES_OK),
            (
                ACKNOWLEDGE | DRIVER | FEATURES_OK,
                ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
            ),
        ];

        if (status & FAILED) != 0 {
            // TODO: notify backend driver to stop the device
            self.device_status |= FAILED;
        } else if status == INIT {
            {
                let mut locked_device = self.device.lock().expect("Poisoned lock");
                if locked_device.is_activated() {
                    let mut device_status = self.device_status;
                    let reset_result = locked_device.reset();
                    match reset_result {
                        Some((_interrupt_evt, mut _queue_evts)) => {}
                        None => {
                            device_status |= FAILED;
                        }
                    }
                    self.device_status = device_status;
                }
            }

            // If the backend device driver doesn't support reset,
            // just leave the device marked as FAILED.
            if self.device_status & FAILED == 0 {
                self.reset();
            }
        } else if VALID_TRANSITIONS
            .iter()
            .any(|&(from, to)| self.device_status == from && status == to)
        {
            self.device_status = status;

            // Activate the device when transitioning to DRIVER_OK.
            if status == (ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK) {
                let mut locked_device = self.device.lock().expect("Poisoned lock");
                if !locked_device.is_activated() {
                    let activate_result =
                        locked_device.activate(self.mem.clone(), self.interrupt.clone());
                    if let Err(err) = activate_result {
                        self.device_status |= DEVICE_NEEDS_RESET;

                        // Section 2.1.2 of the specification states that we need to send a device
                        // configuration change interrupt
                        let _ = self.interrupt.trigger(VirtioInterruptType::Config);

                        error!("Failed to activate virtio device: {}", err)
                    }
                }
            }
        } else {
            warn!(
                "invalid virtio driver status transition: {:#x} -> {:#x}",
                self.device_status, status
            );
        }
    }
}

impl BusDevice for MmioTransport {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = match offset {
                    0x0 => MMIO_MAGIC_VALUE,
                    0x04 => MMIO_VERSION,
                    0x08 => self.locked_device().device_type() as u32,
                    0x0c => VENDOR_ID, // vendor id
                    0x10 => {
                        let mut features = self
                            .locked_device()
                            .avail_features_by_page(self.features_select);
                        if self.features_select == 1 {
                            features |= 0x1; // enable support of VirtIO Version 1
                        }
                        features
                    }
                    0x34 => self.with_queue(0, |q| u32::from(q.max_size)),
                    0x44 => self.with_queue(0, |q| u32::from(q.ready)),
                    0x60 => {
                        // For vhost-user backed devices we need some additional
                        // logic to differentiate between `VIRTIO_MMIO_INT_VRING`
                        // and `VIRTIO_MMIO_INT_CONFIG` statuses.
                        // Because backend cannot propagate any interrupt status
                        // changes to the FC we always try to serve the `VIRTIO_MMIO_INT_VRING`
                        // status. But in case when backend changes the configuration and
                        // user triggers the manual notification, FC needs to send
                        // `VIRTIO_MMIO_INT_CONFIG`. We know that for vhost-user devices the
                        // interrupt status can only be 0 (no one set any bits) or
                        // `VIRTIO_MMIO_INT_CONFIG`. Based on this knowledge we can simply
                        // check if the current interrupt_status is equal to the
                        // `VIRTIO_MMIO_INT_CONFIG` or not to understand if we need to send
                        // `VIRTIO_MMIO_INT_CONFIG` or
                        // `VIRTIO_MMIO_INT_VRING`.
                        let is = self.interrupt.irq_status.load(Ordering::SeqCst);
                        if !self.is_vhost_user {
                            is
                        } else if is == VIRTIO_MMIO_INT_CONFIG {
                            VIRTIO_MMIO_INT_CONFIG
                        } else {
                            VIRTIO_MMIO_INT_VRING
                        }
                    }
                    0x70 => self.device_status,
                    0xfc => self.config_generation,
                    _ => {
                        warn!("unknown virtio mmio register read: {:#x}", offset);
                        return;
                    }
                };
                byte_order::write_le_u32(data, v);
            }
            0x100..=0xfff => self.locked_device().read_config(offset - 0x100, data),
            _ => {
                warn!(
                    "invalid virtio mmio read: {base:#x}:{offset:#x}:{:#x}",
                    data.len()
                );
            }
        };
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x)
        }

        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                match offset {
                    0x14 => self.features_select = v,
                    0x20 => {
                        if self.check_device_status(
                            device_status::DRIVER,
                            device_status::FEATURES_OK
                                | device_status::FAILED
                                | device_status::DEVICE_NEEDS_RESET,
                        ) {
                            self.locked_device()
                                .ack_features_by_page(self.acked_features_select, v);
                        } else {
                            warn!(
                                "ack virtio features in invalid state {:#x}",
                                self.device_status
                            );
                        }
                    }
                    0x24 => self.acked_features_select = v,
                    0x30 => self.queue_select = v,
                    0x38 => self.update_queue_field(|q| q.size = (v & 0xffff) as u16),
                    0x44 => self.update_queue_field(|q| q.ready = v == 1),
                    0x64 => {
                        if self.check_device_status(device_status::DRIVER_OK, 0) {
                            self.interrupt.irq_status.fetch_and(!v, Ordering::SeqCst);
                        }
                    }
                    0x70 => self.set_device_status(v),
                    0x80 => self.update_queue_field(|q| lo(&mut q.desc_table_address, v)),
                    0x84 => self.update_queue_field(|q| hi(&mut q.desc_table_address, v)),
                    0x90 => self.update_queue_field(|q| lo(&mut q.avail_ring_address, v)),
                    0x94 => self.update_queue_field(|q| hi(&mut q.avail_ring_address, v)),
                    0xa0 => self.update_queue_field(|q| lo(&mut q.used_ring_address, v)),
                    0xa4 => self.update_queue_field(|q| hi(&mut q.used_ring_address, v)),
                    _ => {
                        warn!("unknown virtio mmio register write: {:#x}", offset);
                    }
                }
            }
            0x100..=0xfff => {
                if self.check_device_status(
                    device_status::DRIVER,
                    device_status::FAILED | device_status::DEVICE_NEEDS_RESET,
                ) {
                    self.locked_device().write_config(offset - 0x100, data)
                } else {
                    warn!("can not write to device config data area before driver is ready");
                }
            }
            _ => {
                warn!(
                    "invalid virtio mmio write: {base:#x}:{offset:#x}:{:#x}",
                    data.len()
                );
            }
        }
        None
    }
}

/// The 2 types of interrupt sources in MMIO transport.
#[derive(Debug)]
pub enum IrqType {
    /// Interrupt triggered by change in config.
    Config,
    /// Interrupt triggered by used vring buffers.
    Vring,
}

impl From<VirtioInterruptType> for IrqType {
    fn from(interrupt_type: VirtioInterruptType) -> Self {
        match interrupt_type {
            VirtioInterruptType::Config => IrqType::Config,
            VirtioInterruptType::Queue(_) => IrqType::Vring,
        }
    }
}

/// Helper struct that is responsible for triggering guest IRQs
#[derive(Debug)]
pub struct IrqTrigger {
    pub(crate) irq_status: Arc<AtomicU32>,
    pub(crate) irq_evt: EventFd, // 用来通知 KVM
}

impl Default for IrqTrigger {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioInterrupt for IrqTrigger {
    fn trigger(&self, interrupt_type: VirtioInterruptType) -> Result<(), InterruptError> {
        METRICS.interrupts.triggers.inc();
        match interrupt_type {
            VirtioInterruptType::Config => self.trigger_irq(IrqType::Config),
            VirtioInterruptType::Queue(_) => self.trigger_irq(IrqType::Vring),
        }
    }

    fn trigger_queues(&self, queues: &[u16]) -> Result<(), InterruptError> {
        if queues.is_empty() {
            Ok(())
        } else {
            METRICS.interrupts.triggers.inc();
            self.trigger_irq(IrqType::Vring)
        }
    }

    fn notifier(&self, _interrupt_type: VirtioInterruptType) -> Option<&EventFd> {
        Some(&self.irq_evt)
    }

    fn status(&self) -> Arc<AtomicU32> {
        self.irq_status.clone()
    }

    #[cfg(test)]
    fn has_pending_interrupt(&self, interrupt_type: VirtioInterruptType) -> bool {
        if let Ok(num_irqs) = self.irq_evt.read() {
            if num_irqs == 0 {
                return false;
            }

            let irq_status = self.irq_status.load(Ordering::SeqCst);
            return matches!(
                (irq_status, interrupt_type.into()),
                (VIRTIO_MMIO_INT_CONFIG, IrqType::Config) | (VIRTIO_MMIO_INT_VRING, IrqType::Vring)
            );
        }
        false
    }

    #[cfg(test)]
    fn ack_interrupt(&self, interrupt_type: VirtioInterruptType) {
        let irq = match interrupt_type {
            VirtioInterruptType::Config => VIRTIO_MMIO_INT_CONFIG,
            VirtioInterruptType::Queue(_) => VIRTIO_MMIO_INT_VRING,
        };
        self.irq_status.fetch_and(!irq, Ordering::SeqCst);
    }
}

impl IrqTrigger {
    pub fn new() -> Self {
        Self {
            irq_status: Arc::new(AtomicU32::new(0)),
            irq_evt: EventFd::new(libc::EFD_NONBLOCK)
                .expect("Could not create EventFd for IrqTrigger"),
        }
    }

    fn trigger_irq(&self, irq_type: IrqType) -> Result<(), InterruptError> {
        let irq = match irq_type {
            IrqType::Config => VIRTIO_MMIO_INT_CONFIG,
            IrqType::Vring => VIRTIO_MMIO_INT_VRING,
        };
        self.irq_status.fetch_or(irq, Ordering::SeqCst);

        self.irq_evt.write(1).map_err(|err| {
            error!("Failed to send irq to the guest: {:?}", err);
            err
        })?;

        Ok(())
    }
}
