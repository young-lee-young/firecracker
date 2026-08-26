// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bitvec::vec::BitVec;
use serde::{Deserialize, Serialize};
use vm_allocator::AddressAllocator;
pub use vm_allocator::AllocPolicy;

use crate::arch;
use crate::snapshot::Persist;

/// Helper function to allocate many ids from an id allocator
fn allocate_many_ids(
    id_allocator: &mut IdAllocator,
    count: u32,
) -> Result<Vec<u32>, vm_allocator::Error> {
    let mut ids = Vec::with_capacity(count as usize);

    for _ in 0..count {
        match id_allocator.allocate_id() {
            Ok(id) => ids.push(id),
            Err(err) => {
                // It is ok to unwrap here, we just allocated the GSI
                ids.into_iter().for_each(|id| {
                    id_allocator.free_id(id).unwrap();
                });
                return Err(err);
            }
        }
    }

    Ok(ids)
}

/// A resource manager for (de)allocating interrupt lines (GSIs) and guest memory
///
/// At the moment, we support:
///
/// * GSIs for legacy x86_64 devices
/// * GSIs for MMIO devicecs
/// * Memory allocations in the MMIO address space
#[derive(Debug, Clone)]
pub struct ResourceAllocator {
    /// Allocator for legacy device interrupt lines
    pub gsi_legacy_allocator: IdAllocator,
    /// Allocator for PCI device GSIs
    pub gsi_msi_allocator: IdAllocator,
    /// Allocator for memory in the 32-bit MMIO address space
    pub mmio32_memory: AddressAllocator,
    /// Allocator for memory in the 64-bit MMIO address space
    pub mmio64_memory: AddressAllocator,
    /// Allocator for memory after the 64-bit MMIO address space
    pub past_mmio64_memory: AddressAllocator,
    /// Memory allocator for system data
    pub system_memory: AddressAllocator,
}

impl Default for ResourceAllocator {
    fn default() -> Self {
        ResourceAllocator::new()
    }
}

impl ResourceAllocator {
    /// Create a new resource allocator for Firecracker devices
    pub fn new() -> Self {
        // It is fine for us to unwrap the following since we know we are passing valid ranges for
        // all allocators
        Self {
            gsi_legacy_allocator: IdAllocator::new(arch::GSI_LEGACY_START, arch::GSI_LEGACY_END)
                .unwrap(),
            gsi_msi_allocator: IdAllocator::new(arch::GSI_MSI_START, arch::GSI_MSI_END).unwrap(),
            mmio32_memory: AddressAllocator::new(
                arch::MEM_32BIT_DEVICES_START,
                arch::MEM_32BIT_DEVICES_SIZE,
            )
            .unwrap(),
            mmio64_memory: AddressAllocator::new(
                arch::MEM_64BIT_DEVICES_START,
                arch::MEM_64BIT_DEVICES_SIZE,
            )
            .unwrap(),
            past_mmio64_memory: AddressAllocator::new(
                arch::FIRST_ADDR_PAST_64BITS_MMIO,
                arch::PAST_64BITS_MMIO_SIZE,
            )
            .unwrap(),
            system_memory: AddressAllocator::new(arch::SYSTEM_MEM_START, arch::SYSTEM_MEM_SIZE)
                .unwrap(),
        }
    }

    /// Allocate a number of legacy GSIs
    ///
    /// # Arguments
    ///
    /// * `gsi_count` - The number of legacy GSIs to allocate
    pub fn allocate_gsi_legacy(&mut self, gsi_count: u32) -> Result<Vec<u32>, vm_allocator::Error> {
        allocate_many_ids(&mut self.gsi_legacy_allocator, gsi_count)
    }

    /// Allocate a number of GSIs for MSI
    ///
    /// # Arguments
    ///
    /// * `gsi_count` - The number of GSIs to allocate
    pub fn allocate_gsi_msi(&mut self, gsi_count: u32) -> Result<Vec<u32>, vm_allocator::Error> {
        allocate_many_ids(&mut self.gsi_msi_allocator, gsi_count)
    }
}

/// Serializable state for the resource allocator.
///
/// GSI allocators are reconstructed empty and repopulated from restored device state so malformed
/// snapshots cannot provide allocator state that disagrees with the devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocatorState {
    /// Allocator for memory in the 32-bit MMIO address space
    pub mmio32_memory: AddressAllocator,
    /// Allocator for memory in the 64-bit MMIO address space
    pub mmio64_memory: AddressAllocator,
    /// Allocator for memory after the 64-bit MMIO address space
    pub past_mmio64_memory: AddressAllocator,
    /// Memory allocator for system data
    pub system_memory: AddressAllocator,
}

impl Default for ResourceAllocatorState {
    fn default() -> Self {
        ResourceAllocator::new().save()
    }
}

impl<'a> Persist<'a> for ResourceAllocator {
    type State = ResourceAllocatorState;
    type ConstructorArgs = ();
    type Error = vm_allocator::Error;

    fn save(&self) -> Self::State {
        ResourceAllocatorState {
            mmio32_memory: self.mmio32_memory.clone(),
            mmio64_memory: self.mmio64_memory.clone(),
            past_mmio64_memory: self.past_mmio64_memory.clone(),
            system_memory: self.system_memory.clone(),
        }
    }

    fn restore(
        _constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        Ok(ResourceAllocator {
            gsi_legacy_allocator: IdAllocator::new(arch::GSI_LEGACY_START, arch::GSI_LEGACY_END)?,
            gsi_msi_allocator: IdAllocator::new(arch::GSI_MSI_START, arch::GSI_MSI_END)?,
            mmio32_memory: state.mmio32_memory.clone(),
            mmio64_memory: state.mmio64_memory.clone(),
            past_mmio64_memory: state.past_mmio64_memory.clone(),
            system_memory: state.system_memory.clone(),
        })
    }
}

/// An unique ID allocator that allows management of IDs in a given interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdAllocator {
    // Beginning of the range of IDs that we want to manage.
    range_base: u32,
    // One bit per id in the managed range. A set bit means the corresponding
    // id is currently allocated.
    allocated: BitVec,
}

impl IdAllocator {
    /// Create a new IdAllocator with IDs in [`range_base`, `range_end`].
    pub fn new(range_base: u32, range_end: u32) -> Result<Self, vm_allocator::Error> {
        if range_end < range_base {
            return Err(vm_allocator::Error::InvalidRange(
                range_base.into(),
                range_end.into(),
            ));
        }

        let num_ids = u64::from(range_end) - u64::from(range_base) + 1;
        let num_ids = usize::try_from(num_ids).map_err(|_| vm_allocator::Error::Overflow)?;
        let mut allocated = BitVec::with_capacity(num_ids);
        allocated.resize(num_ids, false);

        Ok(IdAllocator {
            range_base,
            allocated,
        })
    }

    /// Map `id` to its corresponding index in the bitmap.
    fn index_for(&self, id: u32) -> Result<usize, vm_allocator::Error> {
        let offset = id
            .checked_sub(self.range_base)
            .ok_or(vm_allocator::Error::OutOfRange(id))?;
        let index = offset as usize;
        self.allocated
            .get(index)
            .map(|_| index)
            .ok_or(vm_allocator::Error::OutOfRange(id))
    }

    // Given `index` into the bitmap, return the `id` in that position
    // Returns `vm_allocator::Error::Overflow` if the index would map to an overflowed id.
    fn id_for_index(&self, index: usize) -> Result<u32, vm_allocator::Error> {
        let offset = u32::try_from(index).map_err(|_| vm_allocator::Error::Overflow)?;
        self.range_base
            .checked_add(offset)
            .ok_or(vm_allocator::Error::Overflow)
    }

    /// Allocate an ID from the managed range.Returns the first available id
    /// from the managed range, or `ResourceNotAvailable` if every id has been
    /// handed out.
    pub fn allocate_id(&mut self) -> Result<u32, vm_allocator::Error> {
        if let Some(index) = self.allocated.first_zero() {
            self.allocated.set(index, true);
            let id = self.id_for_index(index)?;
            Ok(id)
        } else {
            Err(vm_allocator::Error::ResourceNotAvailable)
        }
    }

    /// Allocate the specified ID from the managed range.
    ///
    /// Returns `id` on success, `OutOfRange` if `id` is outside the managed
    /// range, or `ResourceNotAvailable` if `id` has already been allocated.
    pub fn allocate_id_at(&mut self, id: u32) -> Result<u32, vm_allocator::Error> {
        let index = self.index_for(id)?;
        if !self.allocated[index] {
            self.allocated.set(index, true);
            Ok(id)
        } else {
            Err(vm_allocator::Error::ResourceNotAvailable)
        }
    }

    /// Returns `true` if `id` is currently allocated from the managed range.
    ///
    /// Ids outside the managed range are considered never allocated, so return false.
    pub fn is_allocated(&self, id: u32) -> bool {
        match self.index_for(id) {
            Ok(index) => self.allocated[index],
            Err(_) => false,
        }
    }

    /// Frees an id from the managed range.
    pub fn free_id(&mut self, id: u32) -> Result<u32, vm_allocator::Error> {
        let index = self.index_for(id)?;
        if self.allocated[index] {
            self.allocated.set(index, false);
            Ok(id)
        } else {
            Err(vm_allocator::Error::NeverAllocated(id))
        }
    }
}
