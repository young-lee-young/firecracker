// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Guest config sub-module specifically useful for
/// config templates.
use std::borrow::Cow;

use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::arch::x86_64::cpu_model::{CpuModel, SKYLAKE_FMS};
use crate::cpu_config::templates::{
    CpuTemplateType, GetCpuTemplate, GetCpuTemplateError, KvmCapability, RegisterValueFilter,
};
use crate::cpu_config::templates_serde::*;
use crate::cpu_config::x86_64::cpuid::KvmCpuidFlags;
use crate::cpu_config::x86_64::cpuid::common::get_vendor_id_from_host;
use crate::cpu_config::x86_64::static_cpu_templates::{StaticCpuTemplate, c3, t2, t2a, t2cl, t2s};
use crate::logger::warn;

impl GetCpuTemplate for Option<CpuTemplateType> {
    fn get_cpu_template(&self) -> Result<Cow<'_, CustomCpuTemplate>, GetCpuTemplateError> {
        use GetCpuTemplateError::*;

        match self {
            Some(template_type) => match template_type {
                CpuTemplateType::Custom(template) => Ok(Cow::Borrowed(template)),
                CpuTemplateType::Static(template) => {
                    // Return early for `None` due to no valid vendor and CPU models.
                    if template == &StaticCpuTemplate::None {
                        return Err(InvalidStaticCpuTemplate(StaticCpuTemplate::None));
                    }

                    if &get_vendor_id_from_host().map_err(GetCpuVendor)?
                        != template.get_supported_vendor()
                    {
                        return Err(CpuVendorMismatched);
                    }

                    let cpu_model = CpuModel::get_cpu_model();
                    if !template.get_supported_cpu_models().contains(&cpu_model) {
                        return Err(InvalidCpuModel);
                    }

                    match template {
                        StaticCpuTemplate::C3 => {
                            if cpu_model == SKYLAKE_FMS {
                                warn!(
                                    "On processors that do not enumerate FBSDP_NO, PSDP_NO and \
                                     SBDR_SSDP_NO on IA32_ARCH_CAPABILITIES MSR, the guest kernel \
                                     does not apply the mitigation against MMIO stale data \
                                     vulnerability."
                                );
                            }
                            Ok(Cow::Owned(c3::c3()))
                        }
                        StaticCpuTemplate::T2 => Ok(Cow::Owned(t2::t2())),
                        StaticCpuTemplate::T2S => Ok(Cow::Owned(t2s::t2s())),
                        StaticCpuTemplate::T2CL => Ok(Cow::Owned(t2cl::t2cl())),
                        StaticCpuTemplate::T2A => Ok(Cow::Owned(t2a::t2a())),
                        StaticCpuTemplate::None => unreachable!(), // Handled earlier
                    }
                }
            },
            None => Ok(Cow::Owned(CustomCpuTemplate::default())),
        }
    }
}

/// CPUID register enumeration
#[allow(missing_docs)]
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Ord, PartialOrd)]
pub enum CpuidRegister {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

/// Target register to be modified by a bitmap.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct CpuidRegisterModifier {
    /// CPUID register to be modified by the bitmap.
    #[serde(
        deserialize_with = "deserialize_cpuid_register",
        serialize_with = "serialize_cpuid_register"
    )]
    pub register: CpuidRegister,
    /// Bit mapping to be applied as a modifier to the
    /// register's value at the address provided.
    pub bitmap: RegisterValueFilter<u32>,
}

/// Composite type that holistically provides
/// the location of a specific register being used
/// in the context of a CPUID tree.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct CpuidLeafModifier {
    /// Leaf value.
    #[serde(
        deserialize_with = "deserialize_from_str_u32",
        serialize_with = "serialize_to_hex_str"
    )]
    pub leaf: u32,
    /// Sub-Leaf value.
    #[serde(
        deserialize_with = "deserialize_from_str_u32",
        serialize_with = "serialize_to_hex_str"
    )]
    pub subleaf: u32,
    /// KVM feature flags for this leaf-subleaf.
    #[serde(deserialize_with = "deserialize_kvm_cpuid_flags")]
    pub flags: KvmCpuidFlags,
    /// All registers to be modified under the sub-leaf.
    pub modifiers: Vec<CpuidRegisterModifier>,
}

/// Wrapper type to containing x86_64 CPU config modifiers.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCpuTemplate {
    /// Additional kvm capabilities to check before
    /// configuring vcpus.
    #[serde(default)]
    pub kvm_capabilities: Vec<KvmCapability>,
    /// Modifiers for CPUID configuration.
    #[serde(default)]
    pub cpuid_modifiers: Vec<CpuidLeafModifier>,
    /// Modifiers for model specific registers.
    #[serde(default)]
    pub msr_modifiers: Vec<RegisterModifier>,
}

impl CustomCpuTemplate {
    /// Get an iterator of MSR indices that are modified by the CPU template.
    pub fn msr_index_iter(&self) -> impl ExactSizeIterator<Item = u32> + '_ {
        self.msr_modifiers.iter().map(|modifier| modifier.addr)
    }

    /// Validate the correctness of the template.
    pub fn validate(&self) -> Result<(), serde_json::Error> {
        Ok(())
    }
}

/// Wrapper of a mask defined as a bitmap to apply
/// changes to a given register's value.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct RegisterModifier {
    /// Pointer of the location to be bit mapped.
    #[serde(
        deserialize_with = "deserialize_from_str_u32",
        serialize_with = "serialize_to_hex_str"
    )]
    pub addr: u32,
    /// Bit mapping to be applied as a modifier to the
    /// register's value at the address provided.
    pub bitmap: RegisterValueFilter<u64>,
}

fn deserialize_kvm_cpuid_flags<'de, D>(deserializer: D) -> Result<KvmCpuidFlags, D::Error>
where
    D: Deserializer<'de>,
{
    let flag = u32::deserialize(deserializer)?;
    Ok(KvmCpuidFlags(flag))
}

fn deserialize_cpuid_register<'de, D>(deserializer: D) -> Result<CpuidRegister, D::Error>
where
    D: Deserializer<'de>,
{
    let cpuid_register_str = String::deserialize(deserializer)?;

    Ok(match cpuid_register_str.as_str() {
        "eax" => CpuidRegister::Eax,
        "ebx" => CpuidRegister::Ebx,
        "ecx" => CpuidRegister::Ecx,
        "edx" => CpuidRegister::Edx,
        _ => {
            return Err(D::Error::custom(
                "Invalid CPUID register. Must be one of [eax, ebx, ecx, edx]",
            ));
        }
    })
}

fn serialize_cpuid_register<S>(cpuid_reg: &CpuidRegister, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match cpuid_reg {
        CpuidRegister::Eax => serializer.serialize_str("eax"),
        CpuidRegister::Ebx => serializer.serialize_str("ebx"),
        CpuidRegister::Ecx => serializer.serialize_str("ecx"),
        CpuidRegister::Edx => serializer.serialize_str("edx"),
    }
}
