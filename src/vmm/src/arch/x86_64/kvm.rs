// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{CpuId, KVM_MAX_CPUID_ENTRIES, MsrList};
use kvm_ioctls::Kvm as KvmFd;

use crate::arch::x86_64::xstate::{XstateError, request_dynamic_xstate_features};
use crate::cpu_config::templates::KvmCapability;

/// Architecture specific error for KVM initialization
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum KvmArchError {
    /// Failed to get supported cpuid: {0}
    GetSupportedCpuId(kvm_ioctls::Error),
    /// Failed to request permission for dynamic XSTATE features: {0}
    XstateFeatures(XstateError),
}

/// Struct with kvm fd and kvm associated parameters.
#[derive(Debug)]
pub struct Kvm {
    /// KVM fd.
    pub fd: KvmFd,
    /// Additional capabilities that were specified in cpu template.
    pub kvm_cap_modifiers: Vec<KvmCapability>,
    /// Supported CpuIds.
    pub supported_cpuid: CpuId,
}

impl Kvm {
    pub(crate) const DEFAULT_CAPABILITIES: [u32; 14] = [
        kvm_bindings::KVM_CAP_IRQCHIP,
        kvm_bindings::KVM_CAP_IOEVENTFD,
        kvm_bindings::KVM_CAP_IRQFD,
        kvm_bindings::KVM_CAP_USER_MEMORY,
        kvm_bindings::KVM_CAP_SET_TSS_ADDR,
        kvm_bindings::KVM_CAP_PIT2,
        kvm_bindings::KVM_CAP_PIT_STATE2,
        kvm_bindings::KVM_CAP_ADJUST_CLOCK,
        kvm_bindings::KVM_CAP_DEBUGREGS,
        kvm_bindings::KVM_CAP_MP_STATE,
        kvm_bindings::KVM_CAP_VCPU_EVENTS,
        kvm_bindings::KVM_CAP_XCRS,
        kvm_bindings::KVM_CAP_XSAVE,
        kvm_bindings::KVM_CAP_EXT_CPUID,
    ];

    /// Initialize [`Kvm`] type for x86_64 architecture
    pub fn init_arch(
        fd: KvmFd,
        kvm_cap_modifiers: Vec<KvmCapability>,
    ) -> Result<Self, KvmArchError> {
        // 请求使用 xstate 中的功能
        // 这些功能默认不使用，所以需要手动去请求
        // TODO Lee P2 搞清楚这里在干嘛
        request_dynamic_xstate_features().map_err(KvmArchError::XstateFeatures)?;

        // 向 KVM 查询 CPU 支持的特性
        // CPUID：CPU Identification
        let supported_cpuid = fd
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(KvmArchError::GetSupportedCpuId)?;

        Ok(Kvm {
            fd,
            kvm_cap_modifiers,
            supported_cpuid,
        })
    }

    /// Msrs needed to be saved on snapshot creation.
    pub fn msrs_to_save(&self) -> Result<MsrList, crate::arch::x86_64::msr::MsrError> {
        crate::arch::x86_64::msr::get_msrs_to_save(&self.fd)
    }
}
