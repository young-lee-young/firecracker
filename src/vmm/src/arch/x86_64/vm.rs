// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    KVM_CLOCK_REALTIME, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    KVM_PIT_SPEAKER_DUMMY, MsrList, kvm_clock_data, kvm_irqchip, kvm_pit_config, kvm_pit_state2,
};
use kvm_ioctls::Cap;
use serde::{Deserialize, Serialize};

use crate::arch::x86_64::msr::MsrError;
use crate::snapshot::Persist;
use crate::utils::u64_to_usize;
use crate::vstate::bus::Bus;
use crate::vstate::kvm::Kvm;
use crate::vstate::memory::{GuestMemoryExtension, GuestMemoryState};
use crate::vstate::resources::{ResourceAllocator, ResourceAllocatorState};
use crate::vstate::vm::{VmCommon, VmError};

/// Error type for [`KvmVm::restore_state`]
#[allow(missing_docs)]
#[cfg(target_arch = "x86_64")]
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum KvmVmError {
    /// Failed to check KVM capability (0): {1}
    CheckCapability(Cap, kvm_ioctls::Error),
    /// Set PIT2 error: {0}
    SetPit2(kvm_ioctls::Error),
    /// Set clock error: {0}
    SetClock(kvm_ioctls::Error),
    /// clock_realtime requested but not present in the snapshot state
    ClockRealtimeNotInState,
    /// Set IrqChipPicMaster error: {0}
    SetIrqChipPicMaster(kvm_ioctls::Error),
    /// Set IrqChipPicSlave error: {0}
    SetIrqChipPicSlave(kvm_ioctls::Error),
    /// Set IrqChipIoAPIC error: {0}
    SetIrqChipIoAPIC(kvm_ioctls::Error),
    /// Failed to get KVM vm pit state: {0}
    VmGetPit2(kvm_ioctls::Error),
    /// Failed to get KVM vm clock: {0}
    VmGetClock(kvm_ioctls::Error),
    /// Failed to get KVM vm irqchip: {0}
    VmGetIrqChip(kvm_ioctls::Error),
    /// Failed to set KVM vm irqchip: {0}
    VmSetIrqChip(kvm_ioctls::Error),
    /// Failed to get MSR index list to save into snapshots: {0}
    GetMsrsToSave(MsrError),
    /// Failed during KVM_SET_TSS_ADDRESS: {0}
    SetTssAddress(kvm_ioctls::Error),
    /// Failed to restore resource allocator: {0}
    ResourceAllocator(#[from] vm_allocator::Error),
}

/// Structure representing the current architecture's understand of what a "virtual machine" is.
#[derive(Debug)]
pub struct KvmVm {
    /// Architecture independent parts of a vm
    pub common: VmCommon,
    // msr 这个列表，是在 vCPU 创建的时候放到 vCPU 结构体的 msrs_to_save 字段里面了
    msrs_to_save: MsrList,
    // xsave2 也是 vCPU 创建的时候放到 vCPU 结构体中的 xsave2_size 字段里
    // 表示扩展寄存器需要多大的字节来保存
    /// Size in bytes requiring to hold the dynamically-sized `kvm_xsave` struct.
    ///
    /// `None` if `KVM_CAP_XSAVE2` not supported.
    xsave2_size: Option<usize>,
    /// Port IO bus
    pub pio_bus: Arc<Bus>,
}

impl KvmVm {
    /// Create a new `KvmVm` struct.
    pub fn new(kvm: Kvm) -> Result<KvmVm, VmError> {
        // 通过调用 KVM 创建了一个 VM 实例
        let common = Self::create_common(kvm)?;


        // 获取 msr 寄存器（Model-Specific Register，模型特定寄存器）
        // msr 的作用是在 save snapshot 的时候保存
        // 每个 vcpu 都保存自己的 msr，保存的是特殊控制寄存器
        let msrs_to_save = common
            .kvm
            .msrs_to_save()
            .map_err(KvmVmError::GetMsrsToSave)?;


        // XSAVE2 是每个 vCPU 的扩展状态
        // 保存的是 浮点、SSE、AVX 等扩展寄存器的状态
        // TODO Lee P2 要搞清楚 xsave2 是什么

        // `KVM_CAP_XSAVE2` was introduced to support dynamically-sized XSTATE buffer in kernel
        // v5.17. `KVM_GET_EXTENSION(KVM_CAP_XSAVE2)` returns the required size in byte if
        // supported; otherwise returns 0.
        // https://github.com/torvalds/linux/commit/be50b2065dfa3d88428fdfdc340d154d96bf6848
        //
        // Cache the value in order not to call it at each vCPU creation.
        let xsave2_size = match common.fd.check_extension_int(Cap::Xsave2) {
            // Catch all negative values just in case although the possible negative return value
            // of ioctl() is only -1.
            ..=-1 => {
                return Err(VmError::Arch(KvmVmError::CheckCapability(
                    Cap::Xsave2,
                    vmm_sys_util::errno::Error::last(),
                )));
            }
            0 => None,
            // SAFETY: Safe because negative values are handled above.
            ret => Some(usize::try_from(ret).unwrap()),
        };


        // TSS：Task State Segment（任务状态段）
        // 作用：保存的是 CPU 进行任务切换、特权级切换和实模式兼容运行时所需的处理器状态与权限信息
        // 大小：需要 3 个内存页（3 * 4 KiB = 12 KiB）来保存数据
        // 这个 TSS 是 x86 特有的
        common
            .fd
            .set_tss_address(u64_to_usize(crate::arch::x86_64::layout::KVM_TSS_ADDRESS))
            .map_err(KvmVmError::SetTssAddress)?;


        // 创建空的 port IO bus（端口 I/O 总线）
        let pio_bus = Arc::new(Bus::new());

        Ok(KvmVm {
            common,
            msrs_to_save,
            xsave2_size,
            pio_bus,
        })
    }

    /// Pre-vCPU creation setup.
    pub fn arch_pre_create_vcpus(&mut self, _: u8) -> Result<(), KvmVmError> {
        // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
        self.setup_irqchip()
    }

    /// Post-vCPU creation setup.
    pub fn arch_post_create_vcpus(&mut self, _: u8) -> Result<(), KvmVmError> {
        Ok(())
    }

    /// Restores the KVM VM state.
    ///
    /// # Errors
    ///
    /// When:
    /// - [`kvm_ioctls::VmFd::set_pit`] errors.
    /// - [`kvm_ioctls::VmFd::set_clock`] errors.
    /// - [`kvm_ioctls::VmFd::set_irqchip`] errors.
    /// - [`kvm_ioctls::VmFd::set_irqchip`] errors.
    /// - [`kvm_ioctls::VmFd::set_irqchip`] errors.
    pub fn restore_state(
        &mut self,
        state: &VmState,
        clock_realtime: bool,
    ) -> Result<(), KvmVmError> {
        self.fd()
            .set_pit2(&state.pitstate)
            .map_err(KvmVmError::SetPit2)?;
        let mut clock = state.clock;
        clock.flags = if clock_realtime {
            // clock_realtime needs to be present in the snapshot
            if clock.flags & KVM_CLOCK_REALTIME == 0 {
                return Err(KvmVmError::ClockRealtimeNotInState);
            }
            KVM_CLOCK_REALTIME
        } else {
            0
        };
        self.fd().set_clock(&clock).map_err(KvmVmError::SetClock)?;
        self.fd()
            .set_irqchip(&state.pic_master)
            .map_err(KvmVmError::SetIrqChipPicMaster)?;
        self.fd()
            .set_irqchip(&state.pic_slave)
            .map_err(KvmVmError::SetIrqChipPicSlave)?;
        self.fd()
            .set_irqchip(&state.ioapic)
            .map_err(KvmVmError::SetIrqChipIoAPIC)?;
        self.common.resource_allocator =
            Mutex::new(ResourceAllocator::restore((), &state.resource_allocator)?);
        Ok(())
    }

    /// Creates the irq chip and an in-kernel device model for the PIT.
    pub fn setup_irqchip(&self) -> Result<(), KvmVmError> {
        // 创建中断请求控制器，主要用来处理 guest 的中断
        // TODO Lee P0 要学习下中断虚拟化
        self.fd()
            .create_irq_chip()
            .map_err(KvmVmError::VmSetIrqChip)?;

        // We need to enable the emulation of a dummy speaker port stub so that writing to port 0x61
        // (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        self.fd()
            .create_pit2(pit_config)
            .map_err(KvmVmError::VmSetIrqChip)
    }

    /// Saves and returns the KVM VM state.
    pub fn save_state(&self) -> Result<VmState, KvmVmError> {
        let pitstate = self.fd().get_pit2().map_err(KvmVmError::VmGetPit2)?;

        let clock = self.fd().get_clock().map_err(KvmVmError::VmGetClock)?;

        let mut pic_master = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_MASTER,
            ..Default::default()
        };
        self.fd()
            .get_irqchip(&mut pic_master)
            .map_err(KvmVmError::VmGetIrqChip)?;

        let mut pic_slave = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_SLAVE,
            ..Default::default()
        };
        self.fd()
            .get_irqchip(&mut pic_slave)
            .map_err(KvmVmError::VmGetIrqChip)?;

        let mut ioapic = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        self.fd()
            .get_irqchip(&mut ioapic)
            .map_err(KvmVmError::VmGetIrqChip)?;

        Ok(VmState {
            memory: self.common.guest_memory.describe(),
            resource_allocator: self.resource_allocator().save(),
            pitstate,
            clock,
            pic_master,
            pic_slave,
            ioapic,
        })
    }

    /// Gets the list of MSRs to save when creating snapshots
    pub fn msrs_to_save(&self) -> &[u32] {
        self.msrs_to_save.as_slice()
    }

    /// Gets the size (in bytes) of the `kvm_xsave` struct.
    pub fn xsave2_size(&self) -> Option<usize> {
        self.xsave2_size
    }
}

#[derive(Default, Deserialize, Serialize)]
/// Structure holding VM kvm state.
pub struct VmState {
    /// guest memory state
    pub memory: GuestMemoryState,
    /// resource allocator
    pub resource_allocator: ResourceAllocatorState,
    pitstate: kvm_pit_state2,
    clock: kvm_clock_data,
    // TODO: rename this field to adopt inclusive language once Linux updates it, too.
    pic_master: kvm_irqchip,
    // TODO: rename this field to adopt inclusive language once Linux updates it, too.
    pic_slave: kvm_irqchip,
    ioapic: kvm_irqchip,
}

impl fmt::Debug for VmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmState")
            .field("pitstate", &self.pitstate)
            .field("clock", &self.clock)
            .field("pic_master", &"?")
            .field("pic_slave", &"?")
            .field("ioapic", &"?")
            .finish()
    }
}
