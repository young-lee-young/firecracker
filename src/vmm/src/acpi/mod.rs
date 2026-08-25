// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use acpi_tables::fadt::{FADT_F_HW_REDUCED_ACPI, FADT_F_PWR_BUTTON, FADT_F_SLP_BUTTON};
use acpi_tables::{Aml, Dsdt, Fadt, Madt, Mcfg, Rsdp, Sdt, Xsdt, aml};
use vm_allocator::AllocPolicy;

use crate::Vcpu;
use crate::acpi::x86_64::{
    apic_addr, rsdp_addr, setup_arch_dsdt, setup_arch_fadt, setup_interrupt_controllers,
};
use crate::arch::x86_64::layout;
use crate::device_manager::DeviceManager;
use crate::logger::{debug, error};
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};
use crate::vstate::resources::ResourceAllocator;

mod x86_64;

// Our (Original Equipment Manufacturer" (OEM) name. OEM is how ACPI names the manufacturer of the
// hardware that is exposed to the OS, through ACPI tables. The OEM name is passed in every ACPI
// table, to let the OS know that we are the owner of the table.
const OEM_ID: [u8; 6] = *b"FIRECK";

// In reality the OEM revision is per table and it defines the revision of the OEM's implementation
// of the particular ACPI table. For our purpose, we can set it to a fixed value for all the tables
const OEM_REVISION: u32 = 0;

// This is needed for an entry in the FADT table. Populating this entry in FADT is a way to let the
// guest know that it runs within a Firecracker microVM.
const HYPERVISOR_VENDOR_ID: [u8; 8] = *b"FIRECKVM";

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Error type for ACPI related operations
pub enum AcpiError {
    /// Could not allocate resources: {0}
    VmAllocator(#[from] vm_allocator::Error),
    /// ACPI tables error: {0}
    AcpiTables(#[from] acpi_tables::AcpiError),
    /// Error creating AML bytecode: {0}
    AmlError(#[from] aml::AmlError),
}

/// Helper type that holds the guest memory in which we write the tables in and a resource
/// allocator for allocating space for the tables
struct AcpiTableWriter<'a> {
    mem: &'a GuestMemoryMmap,
}

impl AcpiTableWriter<'_> {
    /// Write a table in guest memory
    ///
    /// This will allocate enough space inside guest memory and write the table in the allocated
    /// buffer. It returns the address in which it wrote the table.
    fn write_acpi_table<S>(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        table: &mut S,
    ) -> Result<u64, AcpiError>
    where
        S: Sdt,
    {
        let addr = resource_allocator
            .system_memory
            .allocate(table.len().try_into().unwrap(), 1, AllocPolicy::FirstMatch)?
            .start();

        table
            .write_to_guest(self.mem, GuestAddress(addr))
            .inspect_err(|err| error!("acpi: Could not write table in guest memory: {err}"))?;

        debug!(
            "acpi: Wrote table ({} bytes) at address: {:#010x}",
            table.len(),
            addr
        );

        Ok(addr)
    }

    /// Build the DSDT table for the guest
    fn build_dsdt(
        &mut self,
        device_manager: &mut DeviceManager,
        resource_allocator: &mut ResourceAllocator,
    ) -> Result<u64, AcpiError> {
        let mut dsdt_data = Vec::new();

        // Virtio-devices DSDT data
        dsdt_data.extend_from_slice(&device_manager.mmio_devices.dsdt_data);

        // Add GED and VMGenID AML data.
        device_manager
            .acpi_devices
            .append_aml_bytes(&mut dsdt_data)?;

        if let Some(pci_segment) = &device_manager.pci_devices.pci_segment {
            pci_segment.append_aml_bytes(&mut dsdt_data)?;
        }

        // Architecture specific DSDT data
        setup_arch_dsdt(&mut dsdt_data)?;

        let mut dsdt = Dsdt::new(OEM_ID, *b"FCVMDSDT", OEM_REVISION, dsdt_data);
        self.write_acpi_table(resource_allocator, &mut dsdt)
    }

    /// Build the FADT table for the guest
    ///
    /// This includes a pointer with the location of the DSDT in guest memory
    fn build_fadt(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        dsdt_addr: u64,
    ) -> Result<u64, AcpiError> {
        let mut fadt = Fadt::new(OEM_ID, *b"FCVMFADT", OEM_REVISION);
        fadt.set_hypervisor_vendor_id(HYPERVISOR_VENDOR_ID);
        fadt.set_x_dsdt(dsdt_addr);
        fadt.set_flags(
            (1 << FADT_F_HW_REDUCED_ACPI) | (1 << FADT_F_PWR_BUTTON) | (1 << FADT_F_SLP_BUTTON),
        );
        setup_arch_fadt(&mut fadt);
        self.write_acpi_table(resource_allocator, &mut fadt)
    }

    /// Build the MADT table for the guest
    ///
    /// This includes information about the interrupt controllers supported in the platform
    fn build_madt(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        nr_vcpus: u8,
    ) -> Result<u64, AcpiError> {
        let mut madt = Madt::new(
            OEM_ID,
            *b"FCVMMADT",
            OEM_REVISION,
            apic_addr(),
            setup_interrupt_controllers(nr_vcpus),
        );
        self.write_acpi_table(resource_allocator, &mut madt)
    }

    /// Build the XSDT table for the guest
    ///
    /// Currently, we pass to the guest just FADT and MADT tables.
    fn build_xsdt(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        fadt_addr: u64,
        madt_addr: u64,
        mcfg_addr: u64,
    ) -> Result<u64, AcpiError> {
        let mut xsdt = Xsdt::new(
            OEM_ID,
            *b"FCMVXSDT",
            OEM_REVISION,
            vec![fadt_addr, madt_addr, mcfg_addr],
        );
        self.write_acpi_table(resource_allocator, &mut xsdt)
    }

    /// Build the MCFG table for the guest.
    fn build_mcfg(
        &mut self,
        resource_allocator: &mut ResourceAllocator,
        pci_mmio_config_addr: u64,
    ) -> Result<u64, AcpiError> {
        let mut mcfg = Mcfg::new(OEM_ID, *b"FCMVMCFG", OEM_REVISION, pci_mmio_config_addr);
        self.write_acpi_table(resource_allocator, &mut mcfg)
    }

    /// Build the RSDP pointer for the guest.
    ///
    /// This will build the RSDP pointer which points to the XSDT table and write it in guest
    /// memory. The address in which we write RSDP is pre-determined for every architecture.
    /// We will not allocate arbitrary memory for it
    fn build_rsdp(&mut self, xsdt_addr: u64) -> Result<(), AcpiError> {
        let mut rsdp = Rsdp::new(OEM_ID, xsdt_addr);
        rsdp.write_to_guest(self.mem, rsdp_addr())
            .inspect_err(|err| error!("acpi: Could not write RSDP in guest memory: {err}"))?;

        debug!(
            "acpi: Wrote RSDP ({} bytes) at address: {:#010x}",
            rsdp.len(),
            rsdp_addr().0
        );
        Ok(())
    }
}

/// Create ACPI tables for the guest
///
/// This will create the ACPI tables needed to describe to the guest OS the available hardware,
/// such as interrupt controllers, vCPUs and VirtIO devices.
pub(crate) fn create_acpi_tables(
    mem: &GuestMemoryMmap,
    device_manager: &mut DeviceManager,
    resource_allocator: &mut ResourceAllocator,
    vcpus: &[Vcpu],
) -> Result<(), AcpiError> {
    let mut writer = AcpiTableWriter { mem };
    let dsdt_addr = writer.build_dsdt(device_manager, resource_allocator)?;

    let fadt_addr = writer.build_fadt(resource_allocator, dsdt_addr)?;
    let madt_addr = writer.build_madt(resource_allocator, vcpus.len().try_into().unwrap())?;
    let mcfg_addr = writer.build_mcfg(resource_allocator, layout::PCI_MMCONFIG_START)?;
    let xsdt_addr = writer.build_xsdt(resource_allocator, fadt_addr, madt_addr, mcfg_addr)?;
    writer.build_rsdp(xsdt_addr)
}

