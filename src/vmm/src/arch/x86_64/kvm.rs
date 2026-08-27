// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{CpuId, KVM_MAX_CPUID_ENTRIES, MsrList, __u32, kvm_cpuid_entry2, __IncompleteArrayField};
use kvm_ioctls::Kvm as KvmFd;

use crate::arch::x86_64::xstate::{XstateError, request_dynamic_xstate_features};
use crate::cpu_config::templates::KvmCapability;
use crate::{debug, info};

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

        /**
        这里介绍下 CPUID 的原理
        作用：查询 CPU 具有什么能力，不是保存的运行过程

        pub struct kvm_cpuid2 {
            pub nent: __u32, // 一共有多少项 CPUID
            pub padding: __u32,
            pub entries: __IncompleteArrayField<kvm_cpuid_entry2>,
        }

        pub struct kvm_cpuid_entry2 {
            pub function: __u32, // 查询的能力，也叫 leaf
            pub index: __u32,    // 查询的子能力，也叫 sub-leaf
            pub flags: __u32,
            pub eax: __u32,
            pub ebx: __u32,
            pub ecx: __u32,
            pub edx: __u32,
            pub padding: [__u32; 3usize],
        }

        查询的时候会把 function 的值赋值给 eax，把 index 的值赋值给 ecx
        查询到的结果会存储在 eax ebx ecx edx 中

        kvm_cpuid_entry2 {
            function: 0,
            index: 0,
            flags: 0,
            eax: 13, // 查询到的结果是 13，表示基础的 CPUID 是 13 个，当然还有很多扩展的 CPUID
            ebx: 1970169159, // ebx - edx 返回的是 CPU 厂商的信息
            ecx: 1818588270,
            edx: 1231384169,
            padding: [
                0,
                0,
                0,
            ],
        },
        */


        debug!("supported_cpuid: {supported_cpuid:#?}");


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
