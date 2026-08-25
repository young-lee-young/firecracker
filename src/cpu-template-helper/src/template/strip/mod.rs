// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Debug;

use vmm::cpu_config::templates::{Numeric, RegisterValueFilter};

use crate::utils::ModifierMapKey;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::strip;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::strip;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StripError {
    /// The number of inputs should be two or more.
    NumberOfInputs,
}

fn strip_common<K, V>(maps: &mut [HashMap<K, RegisterValueFilter<V>>]) -> Result<(), StripError>
where
    K: ModifierMapKey + Debug,
    V: Numeric + Debug,
{
    if maps.len() < 2 {
        return Err(StripError::NumberOfInputs);
    }

    // Initialize `common` with the cloned `maps[0]`.
    let mut common = maps[0].clone();

    // Iterate all items included in the `common`.
    // Use `maps[0]` instead of `common` since the `common` is mutated in the loop.
    for (key, common_vf) in &maps[0] {
        // Hold which bits are different from the `common`'s value/filter.
        // `diff` remains 0 if all the filtered values in all the `maps` are same.
        let mut diff = V::zero();

        for map in maps[1..].iter() {
            match map.get(key) {
                // Record which bits of filtered value are different from the `common` if the `key`
                // is found in the `map`.
                Some(map_vf) => {
                    let map_filtered_value = map_vf.value & map_vf.filter;
                    let common_filtered_value = common_vf.value & common_vf.filter;
                    diff |= map_filtered_value ^ common_filtered_value;
                }
                // Remove the `key` from the `common` if at least one of the `maps` does not have
                // the `key`.
                None => {
                    common.remove(key);
                }
            }
        }

        // Store the `diff` in the `common`'s `filter` if the `key` exist in all the `maps`.
        if let Some(common_vf) = common.get_mut(key) {
            common_vf.filter = diff;
        }
    }

    // Remove the `common` items from all the `maps`.
    for (key, common_vf) in common {
        for map in maps.iter_mut() {
            if common_vf.filter == V::zero() {
                // Remove the `key` if the filtered value is identical in all the `maps`.
                map.remove(&key).unwrap();
            } else {
                // Update the `filter` with `diff`.
                let map_vf = map.get_mut(&key).unwrap();
                map_vf.filter = map_vf.filter & common_vf.filter;
            }
        }
    }

    Ok(())
}

