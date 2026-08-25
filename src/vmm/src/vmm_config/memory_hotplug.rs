// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::devices::virtio::mem::{
    VIRTIO_MEM_DEFAULT_BLOCK_SIZE_MIB, VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB, VirtioMem,
};

/// Errors associated with memory hotplug configuration.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MemoryHotplugConfigError {
    /// Block size must not be lower than {0} MiB
    BlockSizeTooSmall(usize),
    /// Block size must be a power of 2
    BlockSizeNotPowerOfTwo,
    /// Slot size must not be lower than {0} MiB
    SlotSizeTooSmall(usize),
    /// Slot size must be a multiple of block size ({0} MiB)
    SlotSizeNotMultipleOfBlockSize(usize),
    /// Total size must not be lower than slot size ({0} MiB)
    TotalSizeTooSmall(usize),
    /// Total size must be a multiple of slot size ({0} MiB)
    TotalSizeNotMultipleOfSlotSize(usize),
}

fn default_block_size_mib() -> usize {
    VIRTIO_MEM_DEFAULT_BLOCK_SIZE_MIB
}

fn default_slot_size_mib() -> usize {
    VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB
}

/// Configuration for memory hotplug device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryHotplugConfig {
    /// Total memory size in MiB that can be hotplugged.
    pub total_size_mib: usize,
    /// Block size in MiB. A block is the smallest unit the guest can hot(un)plug
    #[serde(default = "default_block_size_mib")]
    pub block_size_mib: usize,
    /// Slot size in MiB. A slot is the smallest unit the host can (de)attach memory
    #[serde(default = "default_slot_size_mib")]
    pub slot_size_mib: usize,
}

impl MemoryHotplugConfig {
    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), MemoryHotplugConfigError> {
        let min_block_size_mib = VIRTIO_MEM_DEFAULT_BLOCK_SIZE_MIB;
        if self.block_size_mib < min_block_size_mib {
            return Err(MemoryHotplugConfigError::BlockSizeTooSmall(
                min_block_size_mib,
            ));
        }
        if !self.block_size_mib.is_power_of_two() {
            return Err(MemoryHotplugConfigError::BlockSizeNotPowerOfTwo);
        }

        let min_slot_size_mib = VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB;
        if self.slot_size_mib < min_slot_size_mib {
            return Err(MemoryHotplugConfigError::SlotSizeTooSmall(
                min_slot_size_mib,
            ));
        }
        if !self.slot_size_mib.is_multiple_of(self.block_size_mib) {
            return Err(MemoryHotplugConfigError::SlotSizeNotMultipleOfBlockSize(
                self.block_size_mib,
            ));
        }

        if self.total_size_mib < self.slot_size_mib {
            return Err(MemoryHotplugConfigError::TotalSizeTooSmall(
                self.slot_size_mib,
            ));
        }
        if !self.total_size_mib.is_multiple_of(self.slot_size_mib) {
            return Err(MemoryHotplugConfigError::TotalSizeNotMultipleOfSlotSize(
                self.slot_size_mib,
            ));
        }

        Ok(())
    }
}

impl From<&VirtioMem> for MemoryHotplugConfig {
    fn from(mem: &VirtioMem) -> Self {
        MemoryHotplugConfig {
            total_size_mib: mem.total_size_mib(),
            block_size_mib: mem.block_size_mib(),
            slot_size_mib: mem.slot_size_mib(),
        }
    }
}

/// Configuration for memory hotplug device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryHotplugSizeUpdate {
    /// Requested size in MiB to resize the hotpluggable memory to.
    pub requested_size_mib: usize,
}
