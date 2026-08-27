// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Handles routing to devices in an address space.

use std::cmp::Ordering;
use std::collections::btree_map::BTreeMap;
use std::sync::{Arc, Barrier, Mutex, RwLock, Weak};
use std::{error, fmt, result};

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: Send {
    /// Reads at `offset` from this device
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
}

/// Trait similar to [`BusDevice`] with the extra requirement that a device is `Send` and `Sync`.
#[allow(unused_variables)]
pub trait BusDeviceSync: Send + Sync {
    /// Reads at `offset` from this device
    fn read(&self, base: u64, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
}

impl<B: BusDevice> BusDeviceSync for Mutex<B> {
    /// Reads at `offset` from this device
    fn read(&self, base: u64, offset: u64, data: &mut [u8]) {
        self.lock()
            .expect("Failed to acquire device lock")
            .read(base, offset, data)
    }
    /// Writes at `offset` into this device
    fn write(&self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.lock()
            .expect("Failed to acquire device lock")
            .write(base, offset, data)
    }
}

/// Error type for [`Bus`]-related operations.
#[derive(Debug)]
pub enum BusError {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
    /// Failed to operate on zero sized range.
    ZeroSizedRange,
    /// Failed to find address range.
    MissingAddressRange,
    /// The supplied range is invalid.
    InvalidRange,
}

/// Result type for [`Bus`]-related operations.
pub type Result<T> = result::Result<T, BusError>;

impl fmt::Display for BusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bus_error: {self:?}")
    }
}

impl error::Error for BusError {}

/// Holds a base and end representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * end - The last address of the range (inclusive).
#[derive(Debug, Copy, Clone)]
pub struct BusRange {
    /// base address of a range within a [`Bus`]
    base: u64,
    /// last address of a range within a [`Bus`] (inclusive)
    end: u64,
}

#[allow(missing_docs)]
impl BusRange {
    pub fn new(base: u64, len: u64) -> Result<Self> {
        if len == 0 {
            return Err(BusError::ZeroSizedRange);
        }
        let end = base.checked_add(len - 1).ok_or(BusError::InvalidRange)?;
        Ok(BusRange { base, end })
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    /// Returns true if there is overlap with the given range.
    pub fn overlaps(&self, other: &BusRange) -> bool {
        self.base <= other.end && other.base <= self.end
    }
}

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.base == other.base
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.base.cmp(&other.base)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Default, Debug)]
pub struct Bus {
    devices: RwLock<BTreeMap<BusRange, Weak<dyn BusDeviceSync>>>,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: RwLock::new(BTreeMap::new()),
        }
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, Arc<dyn BusDeviceSync>)> {
        let devices = self.devices.read().unwrap();
        let (range, dev) = devices.range(..=BusRange::new(addr, 1).ok()?).next_back()?;
        dev.upgrade().map(|d| (*range, d.clone()))
    }

    #[allow(clippy::type_complexity)]
    /// Get a reference to a device residing inside the bus at address [`addr`].
    pub fn resolve(&self, addr: u64) -> Option<(u64, u64, Arc<dyn BusDeviceSync>)> {
        if let Some((range, dev)) = self.first_before(addr)
            && addr <= range.end()
        {
            let offset = addr - range.base();
            return Some((range.base(), offset, dev));
        }
        None
    }

    /// Insert a device into the [`Bus`] in the range [`addr`, `addr` + `len`].
    pub fn insert(&self, device: Arc<dyn BusDeviceSync>, base: u64, len: u64) -> Result<()> {
        let new_range = BusRange::new(base, len)?;

        // Reject all cases where the new device's range overlaps with an existing device.
        if self
            .devices
            .read()
            .unwrap()
            .iter()
            .any(|(range, _dev)| range.overlaps(&new_range))
        {
            return Err(BusError::Overlap);
        }

        if self
            .devices
            .write()
            .unwrap()
            .insert(new_range, Arc::downgrade(&device))
            .is_some()
        {
            return Err(BusError::Overlap);
        }

        Ok(())
    }

    /// Removes the device at the given address space range.
    pub fn remove(&self, base: u64, len: u64) -> Result<()> {
        let bus_range = BusRange::new(base, len)?;

        if self.devices.write().unwrap().remove(&bus_range).is_none() {
            return Err(BusError::MissingAddressRange);
        }

        Ok(())
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> Result<()> {
        if let Some((base, offset, dev)) = self.resolve(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            dev.read(base, offset, data);
            Ok(())
        } else {
            Err(BusError::MissingAddressRange)
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<Option<Arc<Barrier>>> {
        if let Some((base, offset, dev)) = self.resolve(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            Ok(dev.write(base, offset, data))
        } else {
            Err(BusError::MissingAddressRange)
        }
    }
}
