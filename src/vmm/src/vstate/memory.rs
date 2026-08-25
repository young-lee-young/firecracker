// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs::File;
use std::io::SeekFrom;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use bitvec::vec::BitVec;
use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, kvm_userspace_memory_region};
use serde::{Deserialize, Serialize};
pub use vm_memory::bitmap::{AtomicBitmap, BS, Bitmap, BitmapSlice};
pub use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::mmap::{MmapRegionError, NewBitmap};
pub use vm_memory::{
    Address, ByteValued, Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryRegion,
    GuestUsize, MemoryRegionAddress, MmapRegion, address,
};
use vm_memory::{GuestMemoryError, GuestMemoryRegionBytes, VolatileSlice, WriteVolatile};

use crate::DirtyBitmap;
use crate::arch::host_page_size;
use crate::logger::error;
use crate::utils::u64_to_usize;
use crate::vmm_config::machine_config::HugePageConfig;
use crate::vstate::vm::{KvmVm, VmError};

/// Type of GuestRegionMmap.
pub type GuestRegionMmap = vm_memory::GuestRegionMmap<Option<AtomicBitmap>>;
/// Type of GuestMemoryMmap.
pub type GuestMemoryMmap = vm_memory::GuestRegionCollection<GuestRegionMmapExt>;
/// Type of GuestMmapRegion.
pub type GuestMmapRegion = vm_memory::MmapRegion<Option<AtomicBitmap>>;

/// Errors associated with dumping guest memory to file.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MemoryError {
    /// Cannot dump memory: {0}
    WriteMemory(GuestMemoryError),
    /// Cannot create mmap region: {0}
    MmapRegionError(MmapRegionError),
    /// Cannot create guest memory
    VmMemoryError,
    /// Cannot create memfd: {0}
    Memfd(memfd::Error),
    /// Cannot resize memfd file: {0}
    MemfdSetLen(std::io::Error),
    /// Total sum of memory regions exceeds largest possible file offset
    OffsetTooLarge,
    /// Cannot retrieve snapshot file metadata: {0}
    FileMetadata(std::io::Error),
    /// Memory region has zero slots
    ZeroSlots,
    /// Memory region of {region_size} bytes is not evenly divisible into {slot_count} slots
    Unaligned {
        /// Region size in bytes.
        region_size: u64,
        /// Number of slots declared in the snapshot.
        slot_count: usize,
    },
    /// Error protecting memory slot: {0}
    Mprotect(std::io::Error),
    /// Size too large for i64 conversion
    SlotSizeTooLarge,
    /// Dirty bitmap not found for memory slot {0}
    DirtyBitmapNotFound(u32),
    /// Dirty bitmap is larger than the slot size
    DirtyBitmapTooLarge,
    /// Dirty bitmap is smaller than the slot size
    DirtyBitmapTooSmall,
    /// Seek error: {0}
    SeekError(std::io::Error),
    /// Volatile memory error: {0}
    VolatileMemoryError(vm_memory::VolatileMemoryError),
}

impl From<vm_memory::VolatileMemoryError> for MemoryError {
    fn from(e: vm_memory::VolatileMemoryError) -> Self {
        MemoryError::VolatileMemoryError(e)
    }
}

/// Type of the guest region
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GuestRegionType {
    /// Guest DRAM
    Dram,
    /// Hotpluggable memory
    Hotpluggable,
}

/// An extension to GuestMemoryRegion that can be split into multiple KVM slots of
/// the same slot_size, and stores the type of region, and the starting KVM slot number.
#[derive(Debug)]
pub struct GuestRegionMmapExt {
    /// the wrapped GuestRegionMmap
    pub inner: GuestRegionMmap,
    /// the type of region
    pub region_type: GuestRegionType,
    /// the starting KVM slot number assigned to this region
    pub slot_from: u32,
    /// the size of the slots of this region
    pub slot_size: usize,
    /// a bitvec indicating whether slot `i` is plugged into KVM (1) or not (0)
    pub plugged: Mutex<BitVec>,
}

/// A guest memory slot, which is a slice of a guest memory region
#[derive(Debug)]
pub struct GuestMemorySlot<'a> {
    /// KVM memory slot number
    pub(crate) slot: u32,
    /// Start guest address of the slot
    pub(crate) guest_addr: GuestAddress,
    /// Corresponding slice in host memory
    pub(crate) slice: VolatileSlice<'a, BS<'a, Option<AtomicBitmap>>>,
}

impl From<&GuestMemorySlot<'_>> for kvm_userspace_memory_region {
    fn from(mem_slot: &GuestMemorySlot) -> Self {
        let flags = if mem_slot.slice.bitmap().is_some() {
            KVM_MEM_LOG_DIRTY_PAGES
        } else {
            0
        };
        kvm_userspace_memory_region {
            flags,
            slot: mem_slot.slot,
            guest_phys_addr: mem_slot.guest_addr.raw_value(),
            memory_size: mem_slot.slice.len() as u64,
            userspace_addr: mem_slot.slice.ptr_guard().as_ptr() as u64,
        }
    }
}

impl<'a> GuestMemorySlot<'a> {
    /// Dumps the dirty pages in this slot onto the writer
    pub(crate) fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        kvm_bitmap: &[u64],
        page_size: usize,
    ) -> Result<(), MemoryError> {
        let firecracker_bitmap = self.slice.bitmap();
        let mut write_size = 0;
        let mut skip_size = 0;
        let mut dirty_batch_start = 0;

        let expected_bitmap_array_len = (self.slice.len() / page_size).div_ceil(64);
        if kvm_bitmap.len() > expected_bitmap_array_len {
            return Err(MemoryError::DirtyBitmapTooLarge);
        } else if kvm_bitmap.len() < expected_bitmap_array_len {
            return Err(MemoryError::DirtyBitmapTooSmall);
        }

        for (i, v) in kvm_bitmap.iter().enumerate() {
            for j in 0..64 {
                let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;
                let page_offset = ((i * 64) + j) * page_size;
                let is_firecracker_page_dirty = firecracker_bitmap.dirty_at(page_offset);

                // We process 64 pages at a time, however the number of pages
                // in the slot might not be a multiple of 64. We need to break
                // once we go past the last page that is actually part of the
                // region.
                if page_offset >= self.slice.len() {
                    // Ensure there are no more dirty bits after this point
                    if (v >> j) != 0 {
                        return Err(MemoryError::DirtyBitmapTooLarge);
                    }
                    break;
                }

                if is_kvm_page_dirty || is_firecracker_page_dirty {
                    // We are at the start of a new batch of dirty pages.
                    if skip_size > 0 {
                        // Seek forward over the unmodified pages.
                        let offset = skip_size
                            .try_into()
                            .map_err(|_| MemoryError::SlotSizeTooLarge)?;
                        writer
                            .seek(SeekFrom::Current(offset))
                            .map_err(MemoryError::SeekError)?;
                        dirty_batch_start = page_offset;
                        skip_size = 0;
                    }
                    write_size += page_size;
                } else {
                    // We are at the end of a batch of dirty pages.
                    if write_size > 0 {
                        // Dump the dirty pages.
                        let slice = &self.slice.subslice(dirty_batch_start, write_size)?;
                        writer.write_all_volatile(slice)?;
                        write_size = 0;
                    }
                    skip_size += page_size;
                }
            }
        }

        if write_size > 0 {
            writer.write_all_volatile(&self.slice.subslice(dirty_batch_start, write_size)?)?;
        }

        // Advance the cursor even if the trailing pages are clean, so that the
        // next slot starts writing at the correct offset.
        if skip_size > 0 {
            writer
                .seek(SeekFrom::Current(skip_size.try_into().unwrap()))
                .map_err(MemoryError::SeekError)?;
        }

        Ok(())
    }

    /// Makes the slot host memory PROT_NONE (true) or PROT_READ|PROT_WRITE (false)
    pub(crate) fn protect(&self, protected: bool) -> Result<(), MemoryError> {
        let prot = if protected {
            libc::PROT_NONE
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };
        // SAFETY: Parameters refer to an existing host memory region
        let ret = unsafe {
            libc::mprotect(
                self.slice.ptr_guard_mut().as_ptr().cast(),
                self.slice.len(),
                prot,
            )
        };
        if ret != 0 {
            Err(MemoryError::Mprotect(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
}

impl GuestRegionMmapExt {
    /// Adds a DRAM region which only contains a single plugged slot
    pub(crate) fn dram_from_mmap_region(region: GuestRegionMmap, slot: u32) -> Self {
        let slot_size = u64_to_usize(region.len());
        GuestRegionMmapExt {
            inner: region,
            region_type: GuestRegionType::Dram,
            slot_from: slot,
            slot_size,
            // 标记这个 region 已经接入 KVM
            plugged: Mutex::new(BitVec::repeat(true, 1)),
        }
    }

    /// Adds an hotpluggable region which can contain multiple slots and is initially unplugged
    pub(crate) fn hotpluggable_from_mmap_region(
        region: GuestRegionMmap,
        slot_from: u32,
        slot_size: usize,
    ) -> Self {
        let slot_cnt = (u64_to_usize(region.len())) / slot_size;

        GuestRegionMmapExt {
            inner: region,
            region_type: GuestRegionType::Hotpluggable,
            slot_from,
            slot_size,
            // 这里是 false 的，表示这些内存还没有被接入到 kvm 中
            // plugged 为 false 不会被注册到 kvm 中
            plugged: Mutex::new(BitVec::repeat(false, slot_cnt)),
        }
    }

    pub(crate) fn from_state(
        region: GuestRegionMmap,
        state: &GuestMemoryRegionState,
        slot_from: u32,
    ) -> Result<Self, MemoryError> {
        let slot_cnt = state.plugged.len();
        let region_len = u64_to_usize(region.len());
        let slot_size = region_len
            .checked_div(slot_cnt)
            .ok_or(MemoryError::ZeroSlots)?;
        if slot_size * slot_cnt != region_len {
            return Err(MemoryError::Unaligned {
                region_size: region.len(),
                slot_count: slot_cnt,
            });
        }

        Ok(GuestRegionMmapExt {
            inner: region,
            slot_size,
            region_type: state.region_type,
            slot_from,
            plugged: Mutex::new(BitVec::from_iter(state.plugged.iter())),
        })
    }

    /// Check whether the given guest address range falls within plugged slots.
    pub(crate) fn check_range_plugged(
        &self,
        caddr: MemoryRegionAddress,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        // caddr is guaranteed to be within the region by the caller
        // (try_for_each_region_in_range validates this).
        let from = self
            .start_addr()
            .checked_add(caddr.raw_value())
            .expect("caddr should be within the region");
        if self
            .slots_intersecting_range(from, len)
            .any(|(_, plugged)| !plugged)
        {
            return Err(GuestMemoryError::HostAddressNotAvailable);
        }
        Ok(())
    }

    pub(crate) fn slot_cnt(&self) -> u32 {
        u32::try_from(u64_to_usize(self.len()) / self.slot_size).unwrap()
    }

    pub(crate) fn mem_slot(&self, slot: u32) -> GuestMemorySlot<'_> {
        assert!(slot >= self.slot_from && slot < self.slot_from + self.slot_cnt());

        let offset = ((slot - self.slot_from) as u64) * (self.slot_size as u64);

        GuestMemorySlot {
            slot,
            guest_addr: self.start_addr().unchecked_add(offset),
            slice: self
                .inner
                .get_slice(MemoryRegionAddress(offset), self.slot_size)
                .expect("slot range should be valid"),
        }
    }

    /// Returns a snapshot of the slots and their state at the time of calling
    ///
    /// Note: to avoid TOCTOU races use only within VMM thread.
    pub(crate) fn slots(&self) -> impl Iterator<Item = (GuestMemorySlot<'_>, bool)> {
        self.plugged
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, b)| {
                (
                    self.mem_slot(self.slot_from + u32::try_from(i).unwrap()),
                    *b,
                )
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Returns a snapshot of the plugged slots at the time of calling
    ///
    /// Note: to avoid TOCTOU races use only within VMM thread.
    pub(crate) fn plugged_slots(&self) -> impl Iterator<Item = GuestMemorySlot<'_>> {
        self.slots()
            .filter(|(_, plugged)| *plugged)
            .map(|(slot, _)| slot)
    }

    pub(crate) fn slots_intersecting_range(
        &self,
        from: GuestAddress,
        len: usize,
    ) -> impl Iterator<Item = (GuestMemorySlot<'_>, bool)> {
        self.slots().filter(move |(slot, _)| {
            // Two intervals [a, b) and [c, d) intersect iff a < d && c < b.
            // This correctly handles the containment case where the slot fully
            // contains the range (or vice versa).
            let slot_start = slot.guest_addr;
            let Some(slot_end) = slot_start.checked_add(slot.slice.len() as u64) else {
                return false;
            };
            let Some(range_end) = from.checked_add(len as u64) else {
                return false;
            };
            slot_start < range_end && from < slot_end
        })
    }

    /// (un)plug a slot from an Hotpluggable memory region
    pub(crate) fn update_slot(
        &self,
        vm: &KvmVm,
        mem_slot: &GuestMemorySlot<'_>,
        plug: bool,
    ) -> Result<(), VmError> {
        // This function can only be called on hotpluggable regions!
        assert!(self.region_type == GuestRegionType::Hotpluggable);

        let mut bitmap_guard = self.plugged.lock().unwrap();
        let prev = bitmap_guard.replace((mem_slot.slot - self.slot_from) as usize, plug);
        // do not do anything if the state is what we're trying to set
        if prev == plug {
            return Ok(());
        }

        let mut kvm_region = kvm_userspace_memory_region::from(mem_slot);
        if plug {
            // make it accessible _before_ adding it to KVM
            mem_slot.protect(false)?;
            vm.set_user_memory_region(kvm_region)?;
        } else {
            // to remove it we need to pass a size of zero
            kvm_region.memory_size = 0;
            vm.set_user_memory_region(kvm_region)?;
            // make it protected _after_ removing it from KVM
            mem_slot.protect(true)?;
        }
        Ok(())
    }

    pub(crate) fn discard_range(
        &self,
        caddr: MemoryRegionAddress,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        let phys_address = self.get_host_address(caddr)?;

        match (self.inner.file_offset(), self.inner.flags()) {
            // If and only if we are resuming from a snapshot file, we have a file and it's mapped
            // private
            (Some(_), flags) if flags & libc::MAP_PRIVATE != 0 => {
                // Mmap a new anonymous region over the present one in order to create a hole
                // with zero pages.
                // This workaround is (only) needed after resuming from a snapshot file because the
                // guest memory is mmaped from file as private. In this case, MADV_DONTNEED on the
                // file only drops any anonymous pages in range, but subsequent accesses would read
                // whatever page is stored on the backing file. Mmapping anonymous pages ensures
                // it's zeroed.
                // SAFETY: The address and length are known to be valid.
                let ret = unsafe {
                    libc::mmap(
                        phys_address.cast(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_FIXED | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                        -1,
                        0,
                    )
                };
                if ret == libc::MAP_FAILED {
                    let os_error = std::io::Error::last_os_error();
                    error!("discard_range: mmap failed: {:?}", os_error);
                    Err(GuestMemoryError::IOError(os_error))
                } else {
                    Ok(())
                }
            }
            // Match either the case of an anonymous mapping, or the case
            // of a shared file mapping.
            // TODO: madvise(MADV_DONTNEED) doesn't actually work with memfd
            // (or in general MAP_SHARED of a fd). In those cases we should use
            // fallocate64(FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE).
            // We keep falling to the madvise branch to keep the previous behaviour.
            _ => {
                // Madvise the region in order to mark it as not used.
                // SAFETY: The address and length are known to be valid.
                let ret = unsafe { libc::madvise(phys_address.cast(), len, libc::MADV_DONTNEED) };
                if ret < 0 {
                    let os_error = std::io::Error::last_os_error();
                    error!("discard_range: madvise failed: {:?}", os_error);
                    Err(GuestMemoryError::IOError(os_error))
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl Deref for GuestRegionMmapExt {
    type Target = MmapRegion<Option<AtomicBitmap>>;

    fn deref(&self) -> &MmapRegion<Option<AtomicBitmap>> {
        &self.inner
    }
}

impl GuestMemoryRegionBytes for GuestRegionMmapExt {}

#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_possible_truncation)]
impl GuestMemoryRegion for GuestRegionMmapExt {
    type B = Option<AtomicBitmap>;

    fn len(&self) -> GuestUsize {
        self.inner.len()
    }

    fn start_addr(&self) -> GuestAddress {
        self.inner.start_addr()
    }

    fn bitmap(&self) -> BS<'_, Self::B> {
        self.inner.bitmap()
    }

    fn get_host_address(
        &self,
        addr: MemoryRegionAddress,
    ) -> vm_memory::guest_memory::Result<*mut u8> {
        self.inner.get_host_address(addr)
    }

    fn file_offset(&self) -> Option<&FileOffset> {
        self.inner.file_offset()
    }

    fn get_slice(
        &self,
        offset: MemoryRegionAddress,
        count: usize,
    ) -> vm_memory::guest_memory::Result<VolatileSlice<'_, BS<'_, Self::B>>> {
        self.inner.get_slice(offset, count)
    }
}

/// Creates a `Vec` of `GuestRegionMmap` with the given configuration
/// 就是做内存的 mmap
///
/// 当 file 是 None 时，表示使用匿名内存，那就 mmap 一段匿名内存就可以
///
/// 当 file 是 memfd 时，表示给 memfd 映射内存，那么还需要记录内存和 memfd 的对应关系
pub fn create(
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    mmap_flags: libc::c_int,
    file: Option<File>,
    track_dirty_pages: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    // 用于记录 region 对应 memfd 中的文件偏移
    // 比如内存大小为 4 GiB，那么会有 2 个 region，(0 - 3) 和 (4 - 5)
    // memfd 的大小是 4 GiB
    // region1 的偏移是 0 GiB，region2 的偏移是 3 GiB
    let mut offset = 0;


    // file 所有权要被多个 region 使用，所以需要使用 Arc 共享 file
    // file 是被 FileOffset 来引用的，下面的 Arc::clone(file) 就是在增加引用计数
    // file 被 FileOffset 使用，FileOffset 被 builder 使用，builder 被 GuestRegionMmap 使用
    let file = file.map(Arc::new);


    regions
        .map(|(start, size)| {
            let mut builder = MmapRegionBuilder::new_with_bitmap(
                size,
                // 如果为 true，为 region 创建脏页的 bitmap
                track_dirty_pages.then(|| AtomicBitmap::with_len(size)),
            )
            .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
            .with_mmap_flags(libc::MAP_NORESERVE | mmap_flags);


            // 如果存在 memfd，就在 builder 里加上这个 memfd file，并且记录了从这个 file 的开始偏移
            if let Some(ref file) = file {
                let file_offset = FileOffset::from_arc(Arc::clone(file), offset);

                builder = builder.with_file_offset(file_offset);
            }

            // 重新计算 offset
            offset = match offset.checked_add(size as u64) {
                None => return Err(MemoryError::OffsetTooLarge),
                Some(new_off) if new_off >= i64::MAX as u64 => {
                    return Err(MemoryError::OffsetTooLarge);
                }
                Some(new_off) => new_off,
            };

            // 记录 region 起始的地址和 mmap 后 firecracker 中虚拟内存的映射关系
            GuestRegionMmap::new(
                // 在 build 方法里真正调用 mmap 的系统调用
                builder.build().map_err(MemoryError::MmapRegionError)?,
                start,
            )
            .ok_or(MemoryError::VmMemoryError)
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Creates a GuestMemoryMmap with `size` in MiB backed by a memfd.
pub fn memfd_backed(
    regions: &[(GuestAddress, usize)],
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    // 计算 regions 总大小
    let size = regions.iter().map(|&(_, size)| size as u64).sum();
    // 创建匿名内存文件
    let memfd_file = create_memfd(size, huge_pages.into())?.into_file();

    create(
        regions.iter().copied(),
        libc::MAP_SHARED | huge_pages.mmap_flags(),
        Some(memfd_file),
        track_dirty_pages,
    )
}

/// Creates a GuestMemoryMmap from raw regions.
pub fn anonymous(
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    create(
        regions,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | huge_pages.mmap_flags(),
        None,
        track_dirty_pages,
    )
}

/// Creates a GuestMemoryMmap given a `file` containing the data
/// and a `state` containing mapping information.
pub fn snapshot_file(
    file: File,
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let regions: Vec<_> = regions.collect();
    let memory_size = regions
        .iter()
        .try_fold(0u64, |acc, (_, size)| acc.checked_add(*size as u64))
        .ok_or(MemoryError::OffsetTooLarge)?;
    let file_size = file.metadata().map_err(MemoryError::FileMetadata)?.len();

    // ensure we do not mmap beyond EOF. The kernel would allow that but a SIGBUS is triggered
    // on an attempted access to a page of the buffer that lies beyond the end of the mapped file.
    if memory_size > file_size {
        return Err(MemoryError::OffsetTooLarge);
    }

    create(
        regions.into_iter(),
        libc::MAP_PRIVATE,
        Some(file),
        track_dirty_pages,
    )
}

/// Defines the interface for snapshotting memory.
pub trait GuestMemoryExtension
where
    Self: Sized,
{
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState;

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize);

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile + std::io::Seek>(&self, writer: &mut T) -> Result<(), MemoryError>;

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> Result<(), MemoryError>;

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self);

    /// Store the dirty bitmap in internal store
    fn store_dirty_bitmap(&self, dirty_bitmap: &DirtyBitmap, page_size: usize);

    /// Apply a function to each region in a memory range
    fn try_for_each_region_in_range<F>(
        &self,
        addr: GuestAddress,
        range_len: usize,
        f: F,
    ) -> Result<(), GuestMemoryError>
    where
        F: FnMut(&GuestRegionMmapExt, MemoryRegionAddress, usize) -> Result<(), GuestMemoryError>;

    /// Discards a memory range, freeing up memory pages
    fn discard_range(&self, addr: GuestAddress, range_len: usize) -> Result<(), GuestMemoryError>;

    /// Check whether the given guest address range falls entirely within plugged memory.
    /// Returns Err if the address is not in any region or is in an unplugged slot.
    fn check_range_plugged(&self, addr: GuestAddress, len: usize) -> Result<(), GuestMemoryError>;
}

/// State of a guest memory region saved to file/buffer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryRegionState {
    // This should have been named `base_guest_addr` since it's _guest_ addr, but for
    // backward compatibility we have to keep this name. At least this comment should help.
    /// Base GuestAddress.
    pub base_address: u64,
    /// Region size.
    pub size: usize,
    /// Region type
    pub region_type: GuestRegionType,
    /// Plugged/unplugged status of each slot
    pub plugged: Vec<bool>,
}

/// Describes guest memory regions and their snapshot file mappings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryState {
    /// List of regions.
    pub regions: Vec<GuestMemoryRegionState>,
}

impl GuestMemoryState {
    /// Turns this [`GuestMemoryState`] into a description of guest memory regions as understood
    /// by the creation functions of [`GuestMemoryExtensions`]
    pub fn regions(&self) -> impl Iterator<Item = (GuestAddress, usize)> + '_ {
        self.regions
            .iter()
            .map(|region| (GuestAddress(region.base_address), region.size))
    }
}

impl GuestMemoryExtension for GuestMemoryMmap {
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState {
        let mut guest_memory_state = GuestMemoryState::default();
        self.iter().for_each(|region| {
            guest_memory_state.regions.push(GuestMemoryRegionState {
                base_address: region.start_addr().0,
                size: u64_to_usize(region.len()),
                region_type: region.region_type,
                plugged: region.plugged.lock().unwrap().iter().by_vals().collect(),
            });
        });
        guest_memory_state
    }

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize) {
        // ignore invalid ranges using .flatten()
        for slice in self.get_slices(addr, len).flatten() {
            slice.bitmap().mark_dirty(0, slice.len());
        }
    }

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile + std::io::Seek>(&self, writer: &mut T) -> Result<(), MemoryError> {
        self.iter()
            .flat_map(|region| region.slots())
            .try_for_each(|(mem_slot, plugged)| {
                if !plugged {
                    let ilen = i64::try_from(mem_slot.slice.len()).unwrap();
                    writer.seek(SeekFrom::Current(ilen)).unwrap();
                } else {
                    writer.write_all_volatile(&mem_slot.slice)?;
                }
                Ok(())
            })
            .map_err(MemoryError::WriteMemory)
    }

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> Result<(), MemoryError> {
        let page_size = host_page_size();

        let write_result =
            self.iter()
                .flat_map(|region| region.slots())
                .try_for_each(|(mem_slot, plugged)| {
                    if !plugged {
                        let ilen = i64::try_from(mem_slot.slice.len())
                            .map_err(|_| MemoryError::SlotSizeTooLarge)?;
                        writer
                            .seek(SeekFrom::Current(ilen))
                            .map_err(MemoryError::SeekError)?;
                    } else {
                        let kvm_bitmap = dirty_bitmap
                            .get(&mem_slot.slot)
                            .ok_or(MemoryError::DirtyBitmapNotFound(mem_slot.slot))?;
                        mem_slot.dump_dirty(writer, kvm_bitmap, page_size)?;
                    }
                    Ok(())
                });

        if write_result.is_err() {
            self.store_dirty_bitmap(dirty_bitmap, page_size);
        } else {
            self.reset_dirty();
        }

        write_result
    }

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self) {
        self.iter().for_each(|region| {
            if let Some(bitmap) = (**region).bitmap() {
                bitmap.reset();
            }
        })
    }

    /// Stores the dirty bitmap inside into the internal bitmap
    fn store_dirty_bitmap(&self, dirty_bitmap: &DirtyBitmap, page_size: usize) {
        self.iter()
            .flat_map(|region| region.plugged_slots())
            .for_each(|mem_slot| {
                let kvm_bitmap = dirty_bitmap.get(&mem_slot.slot).unwrap();
                let firecracker_bitmap = mem_slot.slice.bitmap();

                for (i, v) in kvm_bitmap.iter().enumerate() {
                    for j in 0..64 {
                        let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;

                        if is_kvm_page_dirty {
                            let page_offset = ((i * 64) + j) * page_size;

                            firecracker_bitmap.mark_dirty(page_offset, 1)
                        }
                    }
                }
            });
    }

    fn try_for_each_region_in_range<F>(
        &self,
        addr: GuestAddress,
        range_len: usize,
        mut f: F,
    ) -> Result<(), GuestMemoryError>
    where
        F: FnMut(&GuestRegionMmapExt, MemoryRegionAddress, usize) -> Result<(), GuestMemoryError>,
    {
        let mut cur = addr;
        let mut remaining = range_len;

        // iterate over all adjacent consecutive regions in range
        while let Some(region) = self.find_region(cur) {
            let start = region.to_region_addr(cur).unwrap();
            let len = std::cmp::min(
                // remaining bytes inside the region
                u64_to_usize(region.len() - start.raw_value()),
                // remaning bytes to discard
                remaining,
            );

            f(region, start, len)?;

            remaining -= len;
            if remaining == 0 {
                return Ok(());
            }

            cur = cur
                .checked_add(len as u64)
                .ok_or(GuestMemoryError::GuestAddressOverflow)?;
        }
        // if we exit the loop because we didn't find a region, return an error
        Err(GuestMemoryError::InvalidGuestAddress(cur))
    }

    fn discard_range(&self, addr: GuestAddress, range_len: usize) -> Result<(), GuestMemoryError> {
        self.try_for_each_region_in_range(addr, range_len, |region, start, len| {
            region.discard_range(start, len)
        })
    }

    fn check_range_plugged(&self, addr: GuestAddress, len: usize) -> Result<(), GuestMemoryError> {
        self.try_for_each_region_in_range(addr, len, |region, offset, chunk_len| {
            region.check_range_plugged(offset, chunk_len)
        })
    }
}

// 创建一个 mem_size 大小的匿名内存文件
// 并限制该文件的 seal 操作
fn create_memfd(
    mem_size: u64,
    hugetlb_size: Option<memfd::HugetlbSize>,
) -> Result<memfd::Memfd, MemoryError> {
    // Create a memfd.
    // 创建 memfd 的参数
    // 1. 大页的大小
    // 2. seal：是否允许添加限制，否则下面的添加限制的地方会失败
    let opts = memfd::MemfdOptions::default()
        .hugetlb(hugetlb_size)
        .allow_sealing(true);
    // 调用 Linux 的 memfd_create 系统调用创建 memfd
    let mem_file = opts.create("guest_mem").map_err(MemoryError::Memfd)?;

    // Resize to guest mem size.
    // 把匿名内存文件设置成 mem_size 大小
    mem_file
        .as_file()
        .set_len(mem_size)
        .map_err(MemoryError::MemfdSetLen)?;


    // 这里开始添加限制，不允许以后对 memfd 进行这些操作，防止 firecracker 或 vhost-user 修改 memfd 的大小
    // Add seals to prevent further resizing.
    let mut seals = memfd::SealsHashSet::new();
    seals.insert(memfd::FileSeal::SealShrink); // 禁止把文件缩小
    seals.insert(memfd::FileSeal::SealGrow); // 禁止把文件放大
    mem_file.add_seals(&seals).map_err(MemoryError::Memfd)?;

    // Prevent further sealing changes.
    mem_file
        .add_seal(memfd::FileSeal::SealSeal) // 禁止再对文件进行 Seal 操作
        .map_err(MemoryError::Memfd)?;

    Ok(mem_file)
}
