// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module for CPUID instruction related content
pub mod cpuid;
/// Module for custom CPU templates
pub mod custom_cpu_template;
/// Module for static CPU templates
pub mod static_cpu_templates;
/// Module with test utils for custom CPU templates
pub mod test_utils;

use std::collections::BTreeMap;

use kvm_bindings::CpuId;

use self::custom_cpu_template::CpuidRegister;
use super::templates::CustomCpuTemplate;
use crate::Vcpu;
use crate::cpu_config::x86_64::cpuid::{Cpuid, CpuidKey};

/// Errors thrown while configuring templates.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum CpuConfigurationError {
    /// Template changes a CPUID entry not supported by KVM: Leaf: {0:0x}, Subleaf: {1:0x}
    CpuidFeatureNotSupported(u32, u32),
    /// Template changes an MSR entry not supported by KVM: Register Address: {0:0x}
    MsrNotSupported(u32),
    /// Can create cpuid from raw: {0}
    CpuidFromKvmCpuid(#[from] crate::cpu_config::x86_64::cpuid::CpuidTryFromKvmCpuid),
    /// KVM vcpu ioctl failed: {0}
    VcpuIoctl(#[from] crate::vstate::vcpu::KvmVcpuError),
}

/// CPU configuration for x86_64 CPUs
#[derive(Debug, Clone, PartialEq)]
pub struct CpuConfiguration {
    /// CPUID configuration
    pub cpuid: Cpuid,
    /// Register values as a key pair for model specific registers
    /// Key: MSR address
    /// Value: MSR value
    /// 这个结果是一个 map，键是 msr 的地址，值是 msr 的值
    pub msrs: BTreeMap<u32, u64>,
}

impl CpuConfiguration {
    /// Create new CpuConfiguration.
    pub fn new(
        // 在宿主机上查询到 CPUID 的集合
        supported_cpuid: CpuId,
        // 用户配置的 cpu template
        cpu_template: &CustomCpuTemplate,
        first_vcpu: &Vcpu,
    ) -> Result<Self, CpuConfigurationError> {
        // 把库里面的 CPUID 转换为 firecracker 自己的 CPUID 结构
        let cpuid = cpuid::Cpuid::try_from(supported_cpuid)?;


        // 查询 msr 的当前值，这里只查询 cpu template 中的值
        let msrs = first_vcpu
            .kvm_vcpu
            .get_msrs(cpu_template.msr_index_iter())?;


        Ok(CpuConfiguration { cpuid, msrs })
    }

    /// Modifies provided config with changes from template
    pub fn apply_template(
        self,
        template: &CustomCpuTemplate,
    ) -> Result<Self, CpuConfigurationError> {
        let Self {
            mut cpuid,
            mut msrs,
        } = self;

        let guest_cpuid = cpuid.inner_mut();

        // Apply CPUID modifiers
        // 把 cpu template 中对 CPUID 的修改，应用上
        for mod_leaf in template.cpuid_modifiers.iter() {
            let cpuid_key = CpuidKey {
                leaf: mod_leaf.leaf,
                subleaf: mod_leaf.subleaf,
            };
            if let Some(entry) = guest_cpuid.get_mut(&cpuid_key) {
                entry.flags = mod_leaf.flags;

                // Can we modify one reg multiple times????
                for mod_reg in &mod_leaf.modifiers {
                    match mod_reg.register {
                        CpuidRegister::Eax => {
                            entry.result.eax = mod_reg.bitmap.apply(entry.result.eax)
                        }
                        CpuidRegister::Ebx => {
                            entry.result.ebx = mod_reg.bitmap.apply(entry.result.ebx)
                        }
                        CpuidRegister::Ecx => {
                            entry.result.ecx = mod_reg.bitmap.apply(entry.result.ecx)
                        }
                        CpuidRegister::Edx => {
                            entry.result.edx = mod_reg.bitmap.apply(entry.result.edx)
                        }
                    }
                }
            } else {
                return Err(CpuConfigurationError::CpuidFeatureNotSupported(
                    cpuid_key.leaf,
                    cpuid_key.subleaf,
                ));
            }
        }

        
        // 把 cpu template 中对 msr 的修改，应用上
        for modifier in &template.msr_modifiers {
            if let Some(reg_value) = msrs.get_mut(&modifier.addr) {
                *reg_value = modifier.bitmap.apply(*reg_value);
            } else {
                return Err(CpuConfigurationError::MsrNotSupported(modifier.addr));
            }
        }

        Ok(Self { cpuid, msrs })
    }
}

