// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Debug;

use vmm::cpu_config::templates::{Numeric, RegisterValueFilter};

use crate::utils::{DiffString, ModifierMapKey};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::verify;
#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::verify;

#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VerifyError {
    /// {0} not found in CPU configuration.
    KeyNotFound(String),
    /** Value for {0} mismatched.
    {1} */
    ValueMismatched(String, String),
}

/// Verify that the given CPU template is applied as intended.
///
/// This function is an arch-agnostic part of CPU template verification. As template formats differ
/// between x86_64 and aarch64, the arch-specific part converts the structure to an arch-agnostic
/// `HashMap` implementing `ModifierMapKey` before calling this arch-agnostic function.
pub fn verify_common<K, V>(
    template: HashMap<K, RegisterValueFilter<V>>,
    config: HashMap<K, RegisterValueFilter<V>>,
) -> Result<(), VerifyError>
where
    K: ModifierMapKey + Debug,
    V: Numeric + Debug,
{
    for (key, template_value_filter) in template {
        let config_value_filter = config
            .get(&key)
            .ok_or_else(|| VerifyError::KeyNotFound(key.to_string()))?;

        let template_value = template_value_filter.value & template_value_filter.filter;
        let config_value = config_value_filter.value & template_value_filter.filter;

        if template_value != config_value {
            return Err(VerifyError::ValueMismatched(
                key.to_string(),
                V::to_diff_string(template_value, config_value),
            ));
        }
    }

    Ok(())
}

