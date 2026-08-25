// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use kvm_bindings::{
    CpuId, KVM_MAX_CPUID_ENTRIES, KVM_MAX_MSR_ENTRIES, Msrs, Xsave, kvm_debugregs, kvm_lapic_state,
    kvm_mp_state, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs, kvm_xsave, kvm_xsave2,
};
use kvm_ioctls::{VcpuExit, VcpuFd};
use serde::{Deserialize, Serialize};
use vmm_sys_util::fam::{self, FamStruct};

use crate::arch::EntryPoint;
use crate::arch::x86_64::generated::msr_index::{MSR_IA32_TSC, MSR_IA32_TSC_DEADLINE};
use crate::arch::x86_64::interrupts;
use crate::arch::x86_64::msr::{MsrError, create_boot_msr_entries};
use crate::arch::x86_64::regs::{SetupFpuError, SetupRegistersError, SetupSpecialRegistersError};
use crate::cpu_config::x86_64::{CpuConfiguration, cpuid};
use crate::logger::{IncMetric, METRICS, error, warn};
use crate::vstate::bus::Bus;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::vcpu::{VcpuConfig, VcpuEmulation, VcpuError};
use crate::vstate::vm::KvmVm;

// Tolerance for TSC frequency expected variation.
// The value of 250 parts per million is based on
// the QEMU approach, more details here:
// https://bugzilla.redhat.com/show_bug.cgi?id=1839095
const TSC_KHZ_TOL_NUMERATOR: i64 = 250;
const TSC_KHZ_TOL_DENOMINATOR: i64 = 1_000_000;

/// A set of MSRs that should be restored separately after all other MSRs have already been restored
const DEFERRED_MSRS: [u32; 1] = [
    // MSR_IA32_TSC_DEADLINE must be restored after MSR_IA32_TSC, otherwise we risk "losing" timer
    // interrupts across the snapshot restore boundary (due to KVM querying MSR_IA32_TSC upon
    // writes to the TSC_DEADLINE MSR to determine whether it needs to prime a timer - if
    // MSR_IA32_TSC is not initialized correctly, it can wrongly assume no timer needs to be
    // primed, or the timer can be initialized with a wrong expiry).
    MSR_IA32_TSC_DEADLINE,
];

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum KvmVcpuError {
    /// Failed to convert `kvm_bindings::CpuId` to `Cpuid`: {0}
    ConvertCpuidType(#[from] cpuid::CpuidTryFromKvmCpuid),
    /// Failed FamStructWrapper operation: {0}
    Fam(#[from] vmm_sys_util::fam::Error),
    /// Failed to get dumpable MSR index list: {0}
    GetMsrsToDump(#[from] crate::arch::x86_64::msr::MsrError),
    /// Cannot open the VCPU file descriptor: {0}
    VcpuFd(kvm_ioctls::Error),
    /// Failed to get KVM vcpu debug regs: {0}
    VcpuGetDebugRegs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu lapic: {0}
    VcpuGetLapic(kvm_ioctls::Error),
    /// Failed to get KVM vcpu mp state: {0}
    VcpuGetMpState(kvm_ioctls::Error),
    /// Failed to get KVM vcpu msr: {0:#x}
    VcpuGetMsr(u32),
    /// Failed to get KVM vcpu msrs: {0}
    VcpuGetMsrs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu regs: {0}
    VcpuGetRegs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu sregs: {0}
    VcpuGetSregs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu event: {0}
    VcpuGetVcpuEvents(kvm_ioctls::Error),
    /// Failed to get KVM vcpu xcrs: {0}
    VcpuGetXcrs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu xsave via KVM_GET_XSAVE: {0}
    VcpuGetXsave(kvm_ioctls::Error),
    /// Failed to get KVM vcpu xsave via KVM_GET_XSAVE2: {0}
    VcpuGetXsave2(kvm_ioctls::Error),
    /// Failed to get KVM vcpu cpuid: {0}
    VcpuGetCpuid(kvm_ioctls::Error),
    /// Failed to get KVM TSC frequency: {0}
    VcpuGetTsc(kvm_ioctls::Error),
    /// Failed to set KVM vcpu cpuid: {0}
    VcpuSetCpuid(kvm_ioctls::Error),
    /// Failed to set KVM vcpu debug regs: {0}
    VcpuSetDebugRegs(kvm_ioctls::Error),
    /// Failed to set KVM vcpu lapic: {0}
    VcpuSetLapic(kvm_ioctls::Error),
    /// Failed to set KVM vcpu mp state: {0}
    VcpuSetMpState(kvm_ioctls::Error),
    /// Failed to set KVM vcpu msrs: {0}
    VcpuSetMsrs(kvm_ioctls::Error),
    /// Failed to set all KVM MSRs for this vCPU. Only a partial write was done.
    VcpuSetMsrsIncomplete,
    /// Failed to set KVM vcpu regs: {0}
    VcpuSetRegs(kvm_ioctls::Error),
    /// Failed to set KVM vcpu sregs: {0}
    VcpuSetSregs(kvm_ioctls::Error),
    /// Failed to set KVM vcpu event: {0}
    VcpuSetVcpuEvents(kvm_ioctls::Error),
    /// Failed to set KVM vcpu xcrs: {0}
    VcpuSetXcrs(kvm_ioctls::Error),
    /// Failed to set KVM vcpu xsave: {0}
    VcpuSetXsave(kvm_ioctls::Error),
}

/// Error type for [`KvmVcpu::get_tsc_khz`] and [`KvmVcpu::is_tsc_scaling_required`].
#[derive(Debug, thiserror::Error, derive_more::From, Eq, PartialEq)]
#[error("{0}")]
pub struct GetTscError(vmm_sys_util::errno::Error);

/// Error type for [`KvmVcpu::set_tsc_khz`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
#[error("{0}")]
pub struct SetTscError(#[from] kvm_ioctls::Error);

/// Error type for [`KvmVcpu::configure`].
#[derive(Debug, thiserror::Error, displaydoc::Display, Eq, PartialEq)]
pub enum KvmVcpuConfigureError {
    /// Failed to convert `Cpuid` to `kvm_bindings::CpuId`: {0}
    ConvertCpuidType(#[from] vmm_sys_util::fam::Error),
    /// Failed to apply modifications to CPUID: {0}
    NormalizeCpuidError(#[from] cpuid::NormalizeCpuidError),
    /// Failed to set CPUID: {0}
    SetCpuid(#[from] vmm_sys_util::errno::Error),
    /// Failed to set MSRs: {0}
    SetMsrs(#[from] MsrError),
    /// Failed to setup registers: {0}
    SetupRegisters(#[from] SetupRegistersError),
    /// Failed to setup FPU: {0}
    SetupFpu(#[from] SetupFpuError),
    /// Failed to setup special registers: {0}
    SetupSpecialRegisters(#[from] SetupSpecialRegistersError),
    /// Failed to configure LAPICs: {0}
    SetLint(#[from] interrupts::InterruptError),
}

/// A wrapper around creating and using a kvm x86_64 vcpu.
#[derive(Debug)]
pub struct KvmVcpu {
    /// Index of vcpu.
    pub index: u8,
    /// KVM vcpu fd.
    pub fd: VcpuFd,
    /// Vcpu peripherals, such as buses
    pub peripherals: Peripherals,
    /// The list of MSRs to include in a VM snapshot, in the same order as KVM returned them
    /// from KVM_GET_MSR_INDEX_LIST
    msrs_to_save: Vec<u32>,
    /// Size in bytes requiring to hold the dynamically-sized `kvm_xsave` struct.
    ///
    /// `None` if `KVM_CAP_XSAVE2` not supported.
    xsave2_size: Option<usize>,
}

/// Vcpu peripherals
// 假如 guest 中写串口端口 0x3f8，那么 vCPU 收到 VcpuExit::IoOut 后，调用 pio_bus
#[derive(Default, Debug)]
pub struct Peripherals {
    /// Pio bus.
    pub pio_bus: Option<Arc<Bus>>,
    /// Mmio bus.
    pub mmio_bus: Option<Arc<Bus>>,
}

impl KvmVcpu {
    /// Constructs a new kvm vcpu with arch specific functionality.
    ///
    /// # Arguments
    ///
    /// * `index` - Represents the 0-based CPU index between [0, max vcpus).
    /// * `vm` - The vm to which this vcpu will get attached.
    pub fn new(index: u8, vm: &KvmVm) -> Result<Self, KvmVcpuError> {
        // 调用 KVM 创建 vCPU，返回的是 vCPU 的 fd
        let kvm_vcpu = vm
            .fd()
            .create_vcpu(index.into())
            .map_err(KvmVcpuError::VcpuFd)?;

        Ok(KvmVcpu {
            index,
            fd: kvm_vcpu,
            // 访问虚拟设备总线的总线集合，包括 PIO 总线和 MMIO 总线
            peripherals: Default::default(),
            msrs_to_save: vm.msrs_to_save().to_vec(), // msr 特殊寄存器列表
            xsave2_size: vm.xsave2_size(), // xsave2 寄存器缓存区大小
        })
    }

    /// Configures a x86_64 specific vcpu for booting Linux and should be called once per vcpu.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_entry_point` - Specifies the boot protocol and offset from `guest_mem` at which
    ///   the kernel starts.
    /// * `vcpu_config` - The vCPU configuration.
    /// * `cpuid` - The capabilities exposed by this vCPU.
    pub fn configure(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kernel_entry_point: EntryPoint,
        vcpu_config: &VcpuConfig,
    ) -> Result<(), KvmVcpuConfigureError> {
        let mut cpuid = vcpu_config.cpu_config.cpuid.clone();

        // Apply machine specific changes to CPUID.
        cpuid.normalize(
            // The index of the current logical CPU in the range [0..cpu_count].
            self.index,
            // The total number of logical CPUs.
            vcpu_config.vcpu_count,
            // The number of bits needed to enumerate logical CPUs per core.
            u8::from(vcpu_config.vcpu_count > 1 && vcpu_config.smt),
        )?;

        // Set CPUID.
        let kvm_cpuid = kvm_bindings::CpuId::try_from(cpuid)?;

        // Set CPUID in the KVM
        self.fd
            .set_cpuid2(&kvm_cpuid)
            .map_err(KvmVcpuConfigureError::SetCpuid)?;

        // Clone MSR entries that are modified by CPU template from `VcpuConfig`.
        let mut msrs = vcpu_config.cpu_config.msrs.clone();
        self.msrs_to_save.extend(msrs.keys());

        // Apply MSR modification to comply the linux boot protocol.
        create_boot_msr_entries().into_iter().for_each(|entry| {
            msrs.insert(entry.index, entry.data);
        });

        // TODO - Add/amend MSRs for vCPUs based on cpu_config
        // By this point the Guest CPUID is established. Some CPU features require MSRs
        // to configure and interact with those features. If a MSR is writable from
        // inside the Guest, or is changed by KVM or Firecracker on behalf of the Guest,
        // then we will need to save it every time we take a snapshot, and restore its
        // value when we restore the microVM since the Guest may need that value.
        // Since CPUID tells us what features are enabled for the Guest, we can infer
        // the extra MSRs that we need to save based on a dependency map.
        let extra_msrs = cpuid::common::msrs_to_save_by_cpuid(&kvm_cpuid);
        self.msrs_to_save.extend(extra_msrs);

        // NOTE: Some MSRs depend on values of other MSRs. This dependency will need to
        // be implemented.

        // By this point we know that at snapshot, the list of MSRs we need to
        // save is `architectural MSRs` + `MSRs inferred through CPUID` + `other
        // MSRs defined by the template`

        let kvm_msrs = msrs
            .into_iter()
            .map(|entry| kvm_bindings::kvm_msr_entry {
                index: entry.0,
                data: entry.1,
                ..Default::default()
            })
            .collect::<Vec<_>>();

        crate::arch::x86_64::msr::set_msrs(&self.fd, &kvm_msrs)?;
        crate::arch::x86_64::regs::setup_regs(&self.fd, kernel_entry_point)?;
        crate::arch::x86_64::regs::setup_fpu(&self.fd)?;
        crate::arch::x86_64::regs::setup_sregs(guest_mem, &self.fd, kernel_entry_point.protocol)?;
        crate::arch::x86_64::interrupts::set_lint(&self.fd)?;
        Ok(())
    }

    /// Sets a Port Mapped IO bus for this vcpu.
    pub fn set_pio_bus(&mut self, pio_bus: Arc<Bus>) {
        self.peripherals.pio_bus = Some(pio_bus);
    }

    /// Calls KVM_KVMCLOCK_CTRL to avoid guest soft lockup watchdog panics on resume.
    /// See https://docs.kernel.org/virt/kvm/api.html .
    pub fn kvmclock_ctrl(&self) {
        // We do not want to fail if the call is not successful, because that may be acceptable
        // depending on the workload. For example, EINVAL is returned if kvm-clock is not
        // activated (e.g., no-kvmclock is specified in the guest kernel parameter).
        // https://elixir.bootlin.com/linux/v6.17.5/source/arch/x86/kvm/x86.c#L5736-L5737
        if let Err(err) = self.fd.kvmclock_ctrl() {
            METRICS.vcpu.kvmclock_ctrl_fails.inc();
            warn!("KVM_KVMCLOCK_CTRL call failed {}", err);
        }
    }

    /// Get the current XSAVE state for this vCPU.
    ///
    /// The C `kvm_xsave` struct was extended by adding a flexible array member (FAM) in the end
    /// to support variable-sized XSTATE buffer.
    ///
    /// https://elixir.bootlin.com/linux/v6.13.6/source/arch/x86/include/uapi/asm/kvm.h#L381
    /// ```c
    /// struct kvm_xsave {
    ///         __u32 region[1024];
    ///         __u32 extra[];
    /// };
    /// ```
    ///
    /// As shown above, the C `kvm_xsave` struct does not have any field for the size of itself or
    /// the length of its FAM. The required size (in bytes) of `kvm_xsave` struct can be retrieved
    /// via `KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2)`.
    ///
    /// kvm-bindings defines `kvm_xsave2` struct that wraps the `kvm_xsave` struct to have `len`
    /// field that indicates the number of FAM entries (i.e. `extra`), it also defines `Xsave` as
    /// a `FamStructWrapper` of `kvm_xsave2`.
    ///
    /// https://github.com/rust-vmm/kvm/blob/68fff5491703bf32bd35656f7ba994a4cae9ea7d/kvm-bindings/src/x86_64/fam_wrappers.rs#L106
    /// ```rs
    /// pub struct kvm_xsave2 {
    ///     pub len: usize,
    ///     pub xsave: kvm_xsave,
    /// }
    /// ```
    fn get_xsave(&self) -> Result<Xsave, KvmVcpuError> {
        match self.xsave2_size {
            // if `KVM_CAP_XSAVE2` supported
            Some(xsave2_size) => {
                // Convert the `kvm_xsave` size in bytes to the length of FAM (i.e. `extra`).
                let fam_len =
                    // Calculate the size of FAM (`extra`) area in bytes. Note that the subtraction
                    // never underflows because `KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2)` always returns
                    // at least 4096 bytes that is the size of `kvm_xsave` without FAM area.
                    (xsave2_size - std::mem::size_of::<kvm_xsave>())
                    // Divide by the size of FAM (`extra`) entry (i.e. `__u32`).
                    .div_ceil(std::mem::size_of::<<kvm_xsave2 as FamStruct>::Entry>());
                let mut xsave = Xsave::new(fam_len).map_err(KvmVcpuError::Fam)?;
                // SAFETY: Safe because `xsave` is allocated with enough size to save XSTATE.
                unsafe { self.fd.get_xsave2(&mut xsave) }.map_err(KvmVcpuError::VcpuGetXsave2)?;
                Ok(xsave)
            }
            // if `KVM_CAP_XSAVE2` not supported
            None => Ok(
                // SAFETY: The content is correctly laid out.
                unsafe {
                    Xsave::from_raw(vec![kvm_xsave2 {
                        // Note that `len` is the number of FAM (`extra`) entries that didn't exist
                        // on older kernels not supporting `KVM_CAP_XSAVE2`. Thus, it's always zero.
                        len: 0,
                        xsave: self.fd.get_xsave().map_err(KvmVcpuError::VcpuGetXsave)?,
                    }])
                },
            ),
        }
    }

    /// Get the current TSC frequency for this vCPU.
    ///
    /// # Errors
    ///
    /// When [`kvm_ioctls::VcpuFd::get_tsc_khz`] errors.
    pub fn get_tsc_khz(&self) -> Result<u32, GetTscError> {
        let res = self.fd.get_tsc_khz()?;
        Ok(res)
    }

    /// Get CPUID for this vCPU.
    ///
    /// Opposed to KVM_GET_SUPPORTED_CPUID, KVM_GET_CPUID2 does not update "nent" with valid number
    /// of entries on success. Thus, when it passes "num_entries" greater than required, zeroed
    /// entries follow after valid entries. This function removes such zeroed empty entries.
    ///
    /// # Errors
    ///
    /// * When [`kvm_ioctls::VcpuFd::get_cpuid2`] returns errors.
    fn get_cpuid(&self) -> Result<kvm_bindings::CpuId, KvmVcpuError> {
        let mut cpuid = self
            .fd
            .get_cpuid2(KVM_MAX_CPUID_ENTRIES)
            .map_err(KvmVcpuError::VcpuGetCpuid)?;

        // As CPUID.0h:EAX should have the largest CPUID standard function, we don't need to check
        // EBX, ECX and EDX to confirm whether it is a valid entry.
        cpuid.retain(|entry| {
            !(entry.function == 0 && entry.index == 0 && entry.flags == 0 && entry.eax == 0)
        });

        Ok(cpuid)
    }

    /// If the IA32_TSC_DEADLINE MSR value is zero, update it
    /// with the IA32_TSC value to guarantee that
    /// the vCPU will continue receiving interrupts after restoring from a snapshot.
    ///
    /// Rationale: we observed that sometimes when taking a snapshot,
    /// the IA32_TSC_DEADLINE MSR is cleared, but the interrupt is not
    /// delivered to the guest, leading to a situation where one
    /// of the vCPUs never receives TSC interrupts after restoring,
    /// until the MSR is updated externally, eg by setting the system time.
    fn fix_zero_tsc_deadline_msr(msr_chunks: &mut [Msrs]) {
        // We do not expect more than 1 TSC MSR entry, but if there are multiple, pick the maximum.
        let max_tsc_value = msr_chunks
            .iter()
            .flat_map(|msrs| msrs.as_slice())
            .filter(|msr| msr.index == MSR_IA32_TSC)
            .map(|msr| msr.data)
            .max();

        if let Some(tsc_value) = max_tsc_value {
            msr_chunks
                .iter_mut()
                .flat_map(|msrs| msrs.as_mut_slice())
                .filter(|msr| msr.index == MSR_IA32_TSC_DEADLINE && msr.data == 0)
                .for_each(|msr| {
                    warn!(
                        "MSR_IA32_TSC_DEADLINE is 0, replacing with {:#x}.",
                        tsc_value
                    );
                    msr.data = tsc_value;
                });
        }
    }

    /// Looks for MSRs from the [`DEFERRED_MSRS`] array and removes them from `msr_chunks`.
    /// Returns a new [`Msrs`] object containing all the removed MSRs.
    ///
    /// We use this to capture some causal dependencies between MSRs where the relative order
    /// of restoration matters (e.g. MSR_IA32_TSC must be restored before MSR_IA32_TSC_DEADLINE).
    fn extract_deferred_msrs(msr_chunks: &mut [Msrs]) -> Result<Msrs, fam::Error> {
        // Use 0 here as FamStructWrapper doesn't really give an equivalent of `Vec::with_capacity`,
        // and if we specify something N != 0 here, then it will create a FamStructWrapper with N
        // elements pre-allocated and zero'd out. Unless we then actually "fill" all those N values,
        // KVM will later yell at us about invalid MSRs.
        let mut deferred_msrs = Msrs::new(0)?;

        for msrs in msr_chunks {
            msrs.retain(|msr| {
                if DEFERRED_MSRS.contains(&msr.index) {
                    deferred_msrs
                        .push(*msr)
                        .inspect_err(|err| {
                            error!(
                                "Failed to move MSR {} into later chunk: {:?}",
                                msr.index, err
                            )
                        })
                        .is_err()
                } else {
                    true
                }
            });
        }

        Ok(deferred_msrs)
    }

    /// Get MSR chunks for the given MSR index list.
    ///
    /// KVM only supports getting `KVM_MAX_MSR_ENTRIES` at a time, so we divide
    /// the list of MSR indices into chunks, call `KVM_GET_MSRS` for each
    /// chunk, and collect into a [`Vec<Msrs>`].
    ///
    /// # Arguments
    ///
    /// * `msr_index_iter`: Iterator over MSR indices.
    ///
    /// # Errors
    ///
    /// * When [`kvm_bindings::Msrs::new`] returns errors.
    /// * When [`kvm_ioctls::VcpuFd::get_msrs`] returns errors.
    /// * When the return value of [`kvm_ioctls::VcpuFd::get_msrs`] (the number of entries that
    ///   could be gotten) is less than expected.
    fn get_msr_chunks(
        &self,
        mut msr_index_iter: impl ExactSizeIterator<Item = u32>,
    ) -> Result<Vec<Msrs>, KvmVcpuError> {
        let num_chunks = msr_index_iter.len().div_ceil(KVM_MAX_MSR_ENTRIES);

        // + 1 for the chunk of deferred MSRs
        let mut msr_chunks: Vec<Msrs> = Vec::with_capacity(num_chunks + 1);

        for _ in 0..num_chunks {
            let chunk_len = msr_index_iter.len().min(KVM_MAX_MSR_ENTRIES);
            let chunk = self.get_msr_chunk(&mut msr_index_iter, chunk_len)?;
            msr_chunks.push(chunk);
        }

        Self::fix_zero_tsc_deadline_msr(&mut msr_chunks);

        let deferred = Self::extract_deferred_msrs(&mut msr_chunks)?;
        msr_chunks.push(deferred);

        Ok(msr_chunks)
    }

    /// Get single MSR chunk for the given MSR index iterator with
    /// specified length. Iterator should have enough elements
    /// to fill the chunk with indices, otherwise KVM will
    /// return an error when processing half filled chunk.
    ///
    /// # Arguments
    ///
    /// * `msr_index_iter`: Iterator over MSR indices.
    /// * `chunk_size`: Length of a chunk.
    ///
    /// # Errors
    ///
    /// * When [`kvm_bindings::Msrs::new`] returns errors.
    /// * When [`kvm_ioctls::VcpuFd::get_msrs`] returns errors.
    /// * When the return value of [`kvm_ioctls::VcpuFd::get_msrs`] (the number of entries that
    ///   could be gotten) is less than expected.
    pub fn get_msr_chunk(
        &self,
        msr_index_iter: impl Iterator<Item = u32>,
        chunk_size: usize,
    ) -> Result<Msrs, KvmVcpuError> {
        let chunk_iter = msr_index_iter.take(chunk_size);

        let mut msrs = Msrs::new(chunk_size)?;
        let msr_entries = msrs.as_mut_slice();
        for (pos, msr_index) in chunk_iter.enumerate() {
            msr_entries[pos].index = msr_index;
        }

        let nmsrs = self
            .fd
            .get_msrs(&mut msrs)
            .map_err(KvmVcpuError::VcpuGetMsrs)?;
        // GET_MSRS returns a number of successfully set msrs.
        // If number of set msrs is not equal to the length of
        // `msrs`, then the value returned by GET_MSRS can act
        // as an index to the problematic msr.
        if nmsrs != chunk_size {
            Err(KvmVcpuError::VcpuGetMsr(msrs.as_slice()[nmsrs].index))
        } else {
            Ok(msrs)
        }
    }

    /// Get MSRs for the given MSR index list.
    ///
    /// # Arguments
    ///
    /// * `msr_index_list`: List of MSR indices
    ///
    /// # Errors
    ///
    /// * When `KvmVcpu::get_msr_chunks()` returns errors.
    pub fn get_msrs(
        &self,
        msr_index_iter: impl ExactSizeIterator<Item = u32>,
    ) -> Result<BTreeMap<u32, u64>, KvmVcpuError> {
        let mut msrs = BTreeMap::new();
        self.get_msr_chunks(msr_index_iter)?
            .iter()
            .for_each(|msr_chunk| {
                msr_chunk.as_slice().iter().for_each(|msr| {
                    msrs.insert(msr.index, msr.data);
                });
            });
        Ok(msrs)
    }

    /// Save the KVM internal state.
    pub fn save_state(&self) -> Result<VcpuState, KvmVcpuError> {
        // Ordering requirements:
        //
        // KVM_GET_MP_STATE calls kvm_apic_accept_events(), which might modify
        // vCPU/LAPIC state. As such, it must be done before most everything
        // else, otherwise we cannot restore everything and expect it to work.
        //
        // KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
        // still running.
        //
        // KVM_GET_LAPIC may change state of LAPIC before returning it.
        //
        // GET_VCPU_EVENTS should probably be last to save. The code looks as
        // it might as well be affected by internal state modifications of the
        // GET ioctls.
        //
        // SREGS saves/restores a pending interrupt, similar to what
        // VCPU_EVENTS also does.

        let mp_state = self
            .fd
            .get_mp_state()
            .map_err(KvmVcpuError::VcpuGetMpState)?;
        let regs = self.fd.get_regs().map_err(KvmVcpuError::VcpuGetRegs)?;
        let sregs = self.fd.get_sregs().map_err(KvmVcpuError::VcpuGetSregs)?;
        let xsave = self.get_xsave()?;
        let xcrs = self.fd.get_xcrs().map_err(KvmVcpuError::VcpuGetXcrs)?;
        let debug_regs = self
            .fd
            .get_debug_regs()
            .map_err(KvmVcpuError::VcpuGetDebugRegs)?;
        let lapic = self.fd.get_lapic().map_err(KvmVcpuError::VcpuGetLapic)?;
        let tsc_khz = self.get_tsc_khz().ok().or_else(|| {
            warn!("TSC freq not available. Snapshot cannot be loaded on a different CPU model.");
            None
        });
        let cpuid = self.get_cpuid()?;
        let saved_msrs = self.get_msr_chunks(self.msrs_to_save.iter().copied())?;
        let vcpu_events = self
            .fd
            .get_vcpu_events()
            .map_err(KvmVcpuError::VcpuGetVcpuEvents)?;

        Ok(VcpuState {
            cpuid,
            saved_msrs,
            debug_regs,
            lapic,
            mp_state,
            regs,
            sregs,
            vcpu_events,
            xcrs,
            xsave,
            tsc_khz,
        })
    }

    /// Dumps CPU configuration (CPUID and MSRs).
    ///
    /// Opposed to `save_state()`, this dumps all the supported and dumpable MSRs not limited to
    /// serializable ones.
    pub fn dump_cpu_config(&self) -> Result<CpuConfiguration, KvmVcpuError> {
        let cpuid = cpuid::Cpuid::try_from(self.get_cpuid()?)?;
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let msr_index_list = crate::arch::x86_64::msr::get_msrs_to_dump(&kvm)?;
        let msrs = self.get_msrs(msr_index_list.as_slice().iter().copied())?;
        Ok(CpuConfiguration { cpuid, msrs })
    }

    /// Checks whether the TSC needs scaling when restoring a snapshot.
    ///
    /// # Errors
    ///
    /// When
    pub fn is_tsc_scaling_required(&self, state_tsc_freq: u32) -> Result<bool, GetTscError> {
        // Compare the current TSC freq to the one found
        // in the state. If they are different, we need to
        // scale the TSC to the freq found in the state.
        // We accept values within a tolerance of 250 parts
        // per million because it is common for TSC frequency
        // to differ due to calibration at boot time.
        let diff = (i64::from(self.get_tsc_khz()?) - i64::from(state_tsc_freq)).abs();
        // Cannot overflow since u32::MAX * 250 < i64::MAX
        Ok(diff > i64::from(state_tsc_freq) * TSC_KHZ_TOL_NUMERATOR / TSC_KHZ_TOL_DENOMINATOR)
    }

    /// Scale the TSC frequency of this vCPU to the one provided as a parameter.
    pub fn set_tsc_khz(&self, tsc_freq: u32) -> Result<(), SetTscError> {
        self.fd.set_tsc_khz(tsc_freq).map_err(SetTscError)
    }

    /// Use provided state to populate KVM internal state.
    pub fn restore_state(&self, state: &VcpuState) -> Result<(), KvmVcpuError> {
        // Ordering requirements:
        //
        // KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
        // still running.
        //
        // Some SET ioctls (like set_mp_state) depend on kvm_vcpu_is_bsp(), so
        // if we ever change the BSP, we have to do that before restoring anything.
        // The same seems to be true for CPUID stuff.
        //
        // SREGS saves/restores a pending interrupt, similar to what
        // VCPU_EVENTS also does.
        //
        // SET_REGS clears pending exceptions unconditionally, thus, it must be
        // done before SET_VCPU_EVENTS, which restores it.
        //
        // SET_LAPIC must come after SET_SREGS, because the latter restores
        // the apic base msr.
        //
        // SET_LAPIC must come before SET_MSRS, because the TSC deadline MSR
        // only restores successfully, when the LAPIC is correctly configured.

        self.fd
            .set_cpuid2(&state.cpuid)
            .map_err(KvmVcpuError::VcpuSetCpuid)?;
        self.fd
            .set_mp_state(state.mp_state)
            .map_err(KvmVcpuError::VcpuSetMpState)?;
        self.fd
            .set_regs(&state.regs)
            .map_err(KvmVcpuError::VcpuSetRegs)?;
        self.fd
            .set_sregs(&state.sregs)
            .map_err(KvmVcpuError::VcpuSetSregs)?;
        // SAFETY: Safe unless the snapshot is corrupted.
        unsafe {
            // kvm-ioctl's `set_xsave2()` can be called even on kernel versions not supporting
            // `KVM_CAP_XSAVE2`, because it internally calls `KVM_SET_XSAVE` API that was extended
            // by Linux kernel. Thus, `KVM_SET_XSAVE2` API does not exist as a KVM interface.
            // However, kvm-ioctl added `set_xsave2()` to allow users to pass `Xsave` instead of the
            // older `kvm_xsave`.
            self.fd
                .set_xsave2(&state.xsave)
                .map_err(KvmVcpuError::VcpuSetXsave)?;
        }
        self.fd
            .set_xcrs(&state.xcrs)
            .map_err(KvmVcpuError::VcpuSetXcrs)?;
        self.fd
            .set_debug_regs(&state.debug_regs)
            .map_err(KvmVcpuError::VcpuSetDebugRegs)?;
        self.fd
            .set_lapic(&state.lapic)
            .map_err(KvmVcpuError::VcpuSetLapic)?;
        for msrs in &state.saved_msrs {
            let nmsrs = self.fd.set_msrs(msrs).map_err(KvmVcpuError::VcpuSetMsrs)?;
            if nmsrs < msrs.as_fam_struct_ref().nmsrs as usize {
                return Err(KvmVcpuError::VcpuSetMsrsIncomplete);
            }
        }
        self.fd
            .set_vcpu_events(&state.vcpu_events)
            .map_err(KvmVcpuError::VcpuSetVcpuEvents)?;

        self.kvmclock_ctrl();
        Ok(())
    }
}

impl Peripherals {
    // 处理 Port IO 的逻辑

    /// Runs the vCPU in KVM context and handles the kvm exit reason.
    ///
    /// Returns error or enum specifying whether emulation was handled or interrupted.
    pub fn run_arch_emulation(&self, exit: VcpuExit) -> Result<VcpuEmulation, VcpuError> {
        match exit {
            VcpuExit::IoIn(addr, data) => {
                data.fill(0);
                if let Some(pio_bus) = &self.pio_bus {
                    let _metric = METRICS.vcpu.exit_io_in_agg.record_latency_metrics();
                    if let Err(err) = pio_bus.read(u64::from(addr), data) {
                        warn!("vcpu: IO read @ {addr:#x}:{:#x} failed: {err}", data.len());
                    }
                    METRICS.vcpu.exit_io_in.inc();
                }
                Ok(VcpuEmulation::Handled)
            }
            VcpuExit::IoOut(addr, data) => {
                if let Some(pio_bus) = &self.pio_bus {
                    let _metric = METRICS.vcpu.exit_io_out_agg.record_latency_metrics();
                    if let Err(err) = pio_bus.write(u64::from(addr), data) {
                        warn!("vcpu: IO write @ {addr:#x}:{:#x} failed: {err}", data.len());
                    }
                    METRICS.vcpu.exit_io_out.inc();
                }
                Ok(VcpuEmulation::Handled)
            }
            unexpected_exit => {
                METRICS.vcpu.failures.inc();
                error!("Unexpected exit reason on vcpu run: {:?}", unexpected_exit);
                Err(VcpuError::UnhandledKvmExit(format!(
                    "{:?}",
                    unexpected_exit
                )))
            }
        }
    }
}

/// Structure holding VCPU kvm state.
#[derive(Serialize, Deserialize)]
pub struct VcpuState {
    /// CpuId.
    pub cpuid: CpuId,
    /// Saved msrs.
    pub saved_msrs: Vec<Msrs>,
    /// Debug regs.
    pub debug_regs: kvm_debugregs,
    /// Lapic.
    pub lapic: kvm_lapic_state,
    /// Mp state
    pub mp_state: kvm_mp_state,
    /// Kvm regs.
    pub regs: kvm_regs,
    /// Sregs.
    pub sregs: kvm_sregs,
    /// Vcpu events
    pub vcpu_events: kvm_vcpu_events,
    /// Xcrs.
    pub xcrs: kvm_xcrs,
    /// Xsave.
    pub xsave: Xsave,
    /// Tsc khz.
    pub tsc_khz: Option<u32>,
}

impl Debug for VcpuState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_kvm_regs: Vec<kvm_bindings::kvm_msrs> = Vec::new();
        for kvm_msrs in self.saved_msrs.iter() {
            debug_kvm_regs = kvm_msrs.clone().into_raw();
            debug_kvm_regs.sort_by_key(|msr| (msr.nmsrs, msr.pad));
        }
        f.debug_struct("VcpuState")
            .field("cpuid", &self.cpuid)
            .field("saved_msrs", &debug_kvm_regs)
            .field("debug_regs", &self.debug_regs)
            .field("lapic", &self.lapic)
            .field("mp_state", &self.mp_state)
            .field("regs", &self.regs)
            .field("sregs", &self.sregs)
            .field("vcpu_events", &self.vcpu_events)
            .field("xcrs", &self.xcrs)
            .field("xsave", &self.xsave)
            .field("tsc_khz", &self.tsc_khz)
            .finish()
    }
}
