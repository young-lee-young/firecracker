// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
use acpi_tables::{Aml, aml};
use event_manager::SubscriberOps;
use kvm_ioctls::IoEventAddress;
use linux_loader::cmdline as kernel_cmdline;
use serde::{Deserialize, Serialize};
use vm_allocator::AllocPolicy;

use crate::EventManager;
use crate::arch::BOOT_DEVICE_MEM_START;
#[cfg(target_arch = "aarch64")]
use crate::arch::{RTC_MEM_START, SERIAL_MEM_START};
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::{RTCDevice, SerialDevice};
use crate::devices::pseudo::BootTimer;
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceId, VirtioDeviceType};
use crate::devices::virtio::transport::mmio::MmioTransport;
#[cfg(target_arch = "x86_64")]
use crate::logger::debug;
use crate::vstate::bus::{Bus, BusError};
#[cfg(target_arch = "x86_64")]
use crate::vstate::memory::GuestAddress;
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vm::KvmVm;

/// Errors for MMIO device manager.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MmioError {
    /// Failed to allocate requested resource: {0}
    Allocator(#[from] vm_allocator::Error),
    /// Failed to insert device on the bus: {0}
    BusInsert(#[from] BusError),
    /// Failed to allocate requested resourc: {0}
    Cmdline(#[from] linux_loader::cmdline::Error),
    /// Could not create IRQ for MMIO device: {0}
    CreateIrq(#[from] std::io::Error),
    /// Invalid MMIO IRQ configuration.
    InvalidIrqConfig,
    /// Failed to register IO event: {0}
    RegisterIoEvent(kvm_ioctls::Error),
    /// Failed to register irqfd: {0}
    RegisterIrqFd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to create AML code for device
    AmlError(#[from] aml::AmlError),
}

/// This represents the size of the mmio device specified to the kernel through ACPI and as a
/// command line option.
/// It has to be larger than 0x100 (the offset where the configuration space starts from
/// the beginning of the memory mapped device registers) + the size of the configuration space
/// Currently hardcoded to 4K.
pub const MMIO_LEN: u64 = 0x1000;

/// Stores the address range and irq allocated to this device.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MMIODeviceInfo {
    /// Mmio address at which the device is registered.
    pub addr: u64,
    /// Mmio addr range length.
    pub len: u64,
    /// Used GSI (interrupt line) for the device.
    pub gsi: Option<u32>,
}

#[cfg(target_arch = "x86_64")]
fn add_virtio_aml(
    dsdt_data: &mut Vec<u8>,
    addr: u64,
    len: u64,
    gsi: u32,
) -> Result<(), aml::AmlError> {
    let dev_id = gsi - crate::arch::GSI_LEGACY_START;
    debug!(
        "acpi: Building AML for VirtIO device _SB_.V{:03}. memory range: {:#010x}:{} gsi: {}",
        dev_id, addr, len, gsi
    );
    aml::Device::new(
        format!("V{:03}", dev_id).as_str().try_into()?,
        vec![
            &aml::Name::new("_HID".try_into()?, &"LNRO0005")?,
            &aml::Name::new("_UID".try_into()?, &dev_id)?,
            &aml::Name::new("_CCA".try_into()?, &aml::ONE)?,
            &aml::Name::new(
                "_CRS".try_into()?,
                &aml::ResourceTemplate::new(vec![
                    &aml::Memory32Fixed::new(
                        true,
                        addr.try_into().unwrap(),
                        len.try_into().unwrap(),
                    ),
                    &aml::Interrupt::new(true, true, false, false, gsi),
                ]),
            )?,
        ],
    )
    .append_aml_bytes(dsdt_data)
}

#[derive(Debug, Clone)]
/// A descriptor for MMIO devices
pub struct MMIODevice<T> {
    /// MMIO resources allocated to the device
    pub(crate) resources: MMIODeviceInfo,
    /// The actual device
    pub(crate) inner: Arc<Mutex<T>>,
    /// The subscriber ID returned by the EventManager
    pub(crate) sub_id: Option<event_manager::SubscriberId>,
}

/// Manages the complexities of registering a MMIO device.
#[derive(Debug, Default)]
pub struct MMIODeviceManager {
    /// VirtIO devices using an MMIO transport layer
    pub(crate) virtio_devices: HashMap<VirtioDeviceId, MMIODevice<MmioTransport>>,
    /// Boot timer device
    pub(crate) boot_timer: Option<MMIODevice<BootTimer>>,
    #[cfg(target_arch = "aarch64")]
    /// Real-Time clock on Aarch64 platforms
    pub(crate) rtc: Option<MMIODevice<RTCDevice>>,
    #[cfg(target_arch = "aarch64")]
    /// Serial device on Aarch64 platforms
    pub(crate) serial: Option<MMIODevice<SerialDevice>>,
    #[cfg(target_arch = "x86_64")]
    // We create the AML byte code for every VirtIO device in the order we build
    // it, so that we ensure the root block device is appears first in the DSDT.
    // This is needed, so that the root device appears as `/dev/vda` in the guest
    // filesystem.
    // The alternative would be that we iterate the bus to get the data after all
    // of the devices are build. However, iterating the bus won't give us the
    // devices in the order they were added.
    pub(crate) dsdt_data: Vec<u8>,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new() -> MMIODeviceManager {
        Default::default()
    }

    /// Allocates resources for a new device to be added.
    fn allocate_mmio_resources(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        irq_count: u32,
    ) -> Result<MMIODeviceInfo, MmioError> {
        let gsi = match resource_allocator.allocate_gsi_legacy(irq_count)?[..] {
            [] => None,
            [gsi] => Some(gsi),
            _ => return Err(MmioError::InvalidIrqConfig),
        };

        let range = resource_allocator.mmio32_memory.allocate(
            MMIO_LEN,
            MMIO_LEN,
            AllocPolicy::FirstMatch,
        )?;
        let device_info = MMIODeviceInfo {
            addr: range.start(),
            len: MMIO_LEN,
            gsi,
        };
        Ok(device_info)
    }

    /// Register a virtio-over-MMIO device to be used via MMIO transport at a specific slot.
    pub fn register_mmio_virtio(
        &mut self,
        vm: &KvmVm,
        device_id: String,
        mut device: MMIODevice<MmioTransport>,
        event_manager: &mut EventManager,
    ) -> Result<(), MmioError> {
        // Our virtio devices are currently hardcoded to use a single IRQ.
        // Validate that requirement.
        let gsi = device.resources.gsi.ok_or(MmioError::InvalidIrqConfig)?;
        let identifier;
        {
            let mmio_device = device.inner.lock().expect("Poisoned lock");
            let locked_device = mmio_device.locked_device();
            identifier = (locked_device.device_type(), device_id);
            for (i, queue_evt) in locked_device.queue_events().iter().enumerate() {
                let io_addr = IoEventAddress::Mmio(
                    device.resources.addr + u64::from(crate::devices::virtio::NOTIFY_REG_OFFSET),
                );
                vm.fd()
                    .register_ioevent(queue_evt, &io_addr, u32::try_from(i).unwrap())
                    .map_err(MmioError::RegisterIoEvent)?;
            }
            vm.register_irq(&mmio_device.interrupt.irq_evt, gsi)
                .map_err(MmioError::RegisterIrqFd)?;
        }

        vm.common.mmio_bus.insert(
            device.inner.clone(),
            device.resources.addr,
            device.resources.len,
        )?;

        let sub_id =
            event_manager.add_subscriber(device.inner.lock().expect("Poisoned lock").device());
        device.sub_id = Some(sub_id);

        self.virtio_devices.insert(identifier, device);

        Ok(())
    }

    /// Append a registered virtio-over-MMIO device to the kernel cmdline.
    #[cfg(target_arch = "x86_64")]
    pub fn add_virtio_device_to_cmdline(
        cmdline: &mut kernel_cmdline::Cmdline,
        device_info: &MMIODeviceInfo,
    ) -> Result<(), MmioError> {
        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel command line for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal
        cmdline
            .add_virtio_mmio_device(
                device_info.len,
                GuestAddress(device_info.addr),
                device_info.gsi.unwrap(),
                None,
            )
            .map_err(MmioError::Cmdline)
    }

    /// Allocate slot and register an already created virtio-over-MMIO device. Also Adds the device
    /// to the boot cmdline.
    pub fn register_mmio_virtio_for_boot(
        &mut self,
        vm: &KvmVm,
        device_id: String,
        mmio_device: MmioTransport,
        event_manager: &mut EventManager,
        _cmdline: &mut kernel_cmdline::Cmdline,
    ) -> Result<(), MmioError> {
        let device = MMIODevice {
            resources: self.allocate_mmio_resources(&mut vm.resource_allocator(), 1)?,
            inner: Arc::new(Mutex::new(mmio_device)),
            sub_id: None,
        };

        #[cfg(target_arch = "x86_64")]
        {
            Self::add_virtio_device_to_cmdline(_cmdline, &device.resources)?;
            add_virtio_aml(
                &mut self.dsdt_data,
                device.resources.addr,
                device.resources.len,
                // We are sure that `irqs` has at least one element; allocate_mmio_resources makes
                // sure of it.
                device.resources.gsi.unwrap(),
            )?;
        }
        self.register_mmio_virtio(vm, device_id, device, event_manager)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register an early console at the specified MMIO configuration if given as parameter,
    /// otherwise allocate a new MMIO resources for it.
    pub fn register_mmio_serial(
        &mut self,
        vm: &KvmVm,
        serial: Arc<Mutex<SerialDevice>>,
        device_info_opt: Option<MMIODeviceInfo>,
    ) -> Result<(), MmioError> {
        // Create a new MMIODeviceInfo object on boot path or unwrap the
        // existing object on restore path.
        let device_info = if let Some(device_info) = device_info_opt {
            vm.resource_allocator()
                .gsi_legacy_allocator
                .allocate_id_at(device_info.gsi.ok_or(MmioError::InvalidIrqConfig)?)?;
            device_info
        } else {
            let gsi = vm.resource_allocator().allocate_gsi_legacy(1)?;
            MMIODeviceInfo {
                addr: SERIAL_MEM_START,
                len: MMIO_LEN,
                gsi: Some(gsi[0]),
            }
        };

        vm.register_irq(
            serial.lock().expect("Poisoned lock").serial.interrupt_evt(),
            device_info.gsi.unwrap(),
        )
        .map_err(MmioError::RegisterIrqFd)?;

        let device = MMIODevice {
            resources: device_info,
            inner: serial,
            sub_id: None,
        };

        vm.common.mmio_bus.insert(
            device.inner.clone(),
            device.resources.addr,
            device.resources.len,
        )?;

        self.serial = Some(device);
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Append the registered early console to the kernel cmdline.
    ///
    /// This assumes that the device has been registered with the device manager.
    pub fn add_mmio_serial_to_cmdline(
        &self,
        cmdline: &mut kernel_cmdline::Cmdline,
    ) -> Result<(), MmioError> {
        let device = self.serial.as_ref().unwrap();
        cmdline.insert(
            "earlycon",
            &format!("uart,mmio,0x{:08x}", device.resources.addr),
        )?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Create and register a MMIO RTC device at the specified MMIO configuration if
    /// given as parameter, otherwise allocate a new MMIO resources for it.
    pub fn register_mmio_rtc(
        &mut self,
        vm: &KvmVm,
        rtc: Arc<Mutex<RTCDevice>>,
        device_info_opt: Option<MMIODeviceInfo>,
    ) -> Result<(), MmioError> {
        // Create a new MMIODeviceInfo object on boot path or unwrap the
        // existing object on restore path.
        let device_info = if let Some(device_info) = device_info_opt {
            vm.resource_allocator()
                .gsi_legacy_allocator
                .allocate_id_at(device_info.gsi.ok_or(MmioError::InvalidIrqConfig)?)?;
            device_info
        } else {
            let gsi = vm.resource_allocator().allocate_gsi_legacy(1)?;
            MMIODeviceInfo {
                addr: RTC_MEM_START,
                len: MMIO_LEN,
                gsi: Some(gsi[0]),
            }
        };

        let device = MMIODevice {
            resources: device_info,
            inner: rtc,
            sub_id: None,
        };

        vm.common.mmio_bus.insert(
            device.inner.clone(),
            device.resources.addr,
            device.resources.len,
        )?;
        self.rtc = Some(device);
        Ok(())
    }

    /// Register a boot timer device.
    pub fn register_mmio_boot_timer(
        &mut self,
        mmio_bus: &Bus,
        boot_timer: Arc<Mutex<BootTimer>>,
    ) -> Result<(), MmioError> {
        // Attach a new boot timer device.
        let device_info = MMIODeviceInfo {
            addr: BOOT_DEVICE_MEM_START,
            len: MMIO_LEN,
            gsi: None,
        };

        let device = MMIODevice {
            resources: device_info,
            inner: boot_timer,
            sub_id: None,
        };

        mmio_bus.insert(
            device.inner.clone(),
            device.resources.addr,
            device.resources.len,
        )?;
        self.boot_timer = Some(device);

        Ok(())
    }

    /// Gets the specified device.
    pub fn get_virtio_device(
        &self,
        device_type: VirtioDeviceType,
        device_id: &str,
    ) -> Option<&MMIODevice<MmioTransport>> {
        self.virtio_devices
            .get(&(device_type, device_id.to_string()))
    }

    /// Run fn for each registered virtio device.
    pub fn for_each_virtio_mmio_device<F, E: Debug>(&self, mut f: F) -> Result<(), E>
    where
        F: FnMut(&VirtioDeviceType, &String, &MMIODevice<MmioTransport>) -> Result<(), E>,
    {
        for ((device_type, device_id), mmio_device) in &self.virtio_devices {
            f(device_type, device_id, mmio_device)?;
        }
        Ok(())
    }

    pub fn for_each_virtio_device(&self, mut f: impl FnMut(VirtioDeviceType, &dyn VirtioDevice)) {
        for ((device_type, _), virtio_device) in &self.virtio_devices {
            let device_arc = virtio_device.inner.lock().expect("Poisoned lock").device();
            let virtio_device = device_arc.lock().expect("Poisoned lock");
            f(*device_type, &*virtio_device);
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn virtio_device_info(&self) -> Vec<&MMIODeviceInfo> {
        let mut device_info = Vec::new();
        for (_, dev) in self.virtio_devices.iter() {
            device_info.push(&dev.resources);
        }
        device_info
    }

    #[cfg(target_arch = "aarch64")]
    pub fn rtc_device_info(&self) -> Option<&MMIODeviceInfo> {
        self.rtc.as_ref().map(|device| &device.resources)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn serial_device_info(&self) -> Option<&MMIODeviceInfo> {
        self.serial.as_ref().map(|device| &device.resources)
    }
}
