// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::convert::From;

use vm_memory::GuestMemoryError;

use super::{SECTOR_SHIFT, SECTOR_SIZE, VirtioBlockError, io as block_io};
use crate::devices::virtio::block::virtio::device::DiskProperties;
use crate::devices::virtio::block::virtio::metrics::BlockDeviceMetrics;
pub use crate::devices::virtio::generated::virtio_blk::{
    VIRTIO_BLK_ID_BYTES, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP,
    VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
};
use crate::devices::virtio::queue::DescriptorChain;
use crate::logger::{IncMetric, error};
use crate::rate_limiter::{RateLimiter, TokenType};
use crate::vstate::memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

#[derive(Debug, derive_more::From)]
pub enum IoErr {
    GetId(GuestMemoryError),
    PartialTransfer { completed: u32, expected: u32 },
    FileEngine(block_io::BlockIoError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    In,
    Out,
    Flush,
    GetDeviceID,
    Unsupported(u32),
}

impl From<u32> for RequestType {
    fn from(value: u32) -> Self {
        match value {
            VIRTIO_BLK_T_IN => RequestType::In,
            VIRTIO_BLK_T_OUT => RequestType::Out,
            VIRTIO_BLK_T_FLUSH => RequestType::Flush,
            VIRTIO_BLK_T_GET_ID => RequestType::GetDeviceID,
            t => RequestType::Unsupported(t),
        }
    }
}

#[derive(Debug)]
pub enum ProcessingResult {
    Submitted,
    Throttled,
    Executed(FinishedRequest),
}

#[derive(Debug)]
pub struct FinishedRequest {
    pub num_bytes_to_mem: u32,
    pub desc_idx: u16,
}

#[derive(Debug)]
enum Status {
    Ok { num_bytes_to_mem: u32 },
    IoErr { num_bytes_to_mem: u32, err: IoErr },
    Unsupported { op: u32 },
}

impl Status {
    fn from_data(data_len: u32, transferred_data_len: u32, data_to_mem: bool) -> Status {
        let num_bytes_to_mem = match data_to_mem {
            true => transferred_data_len,
            false => 0,
        };

        match transferred_data_len == data_len {
            true => Status::Ok { num_bytes_to_mem },
            false => Status::IoErr {
                num_bytes_to_mem,
                err: IoErr::PartialTransfer {
                    completed: transferred_data_len,
                    expected: data_len,
                },
            },
        }
    }
}

#[derive(Debug)]
pub struct PendingRequest {
    r#type: RequestType,
    data_len: u32,
    status_addr: GuestAddress,
    desc_idx: u16,
}

impl PendingRequest {
    fn write_status_and_finish(
        self,
        status: &Status,
        mem: &GuestMemoryMmap,
        block_metrics: &BlockDeviceMetrics,
    ) -> FinishedRequest {
        let (num_bytes_to_mem, status_code) = match status {
            Status::Ok { num_bytes_to_mem } => {
                (*num_bytes_to_mem, u8::try_from(VIRTIO_BLK_S_OK).unwrap())
            }
            Status::IoErr {
                num_bytes_to_mem,
                err,
            } => {
                block_metrics.invalid_reqs_count.inc();
                error!(
                    "Failed to execute {:?} virtio block request: {:?}",
                    self.r#type, err
                );
                (*num_bytes_to_mem, u8::try_from(VIRTIO_BLK_S_IOERR).unwrap())
            }
            Status::Unsupported { op } => {
                block_metrics.invalid_reqs_count.inc();
                error!("Received unsupported virtio block request: {}", op);
                (0, u8::try_from(VIRTIO_BLK_S_UNSUPP).unwrap())
            }
        };

        let num_bytes_to_mem = mem
            .write_obj(status_code, self.status_addr)
            .map(|_| {
                // Account for the status byte
                num_bytes_to_mem + 1
            })
            .unwrap_or_else(|err| {
                error!("Failed to write virtio block status: {:?}", err);
                // If we can't write the status, discard the virtio descriptor
                0
            });

        FinishedRequest {
            num_bytes_to_mem,
            desc_idx: self.desc_idx,
        }
    }

    pub fn finish(
        self,
        mem: &GuestMemoryMmap,
        res: Result<u32, IoErr>,
        block_metrics: &BlockDeviceMetrics,
    ) -> FinishedRequest {
        let status = match (res, self.r#type) {
            (Ok(transferred_data_len), RequestType::In) => {
                let status = Status::from_data(self.data_len, transferred_data_len, true);
                block_metrics.read_bytes.add(transferred_data_len.into());
                if let Status::Ok { .. } = status {
                    block_metrics.read_count.inc();
                }
                status
            }
            (Ok(transferred_data_len), RequestType::Out) => {
                let status = Status::from_data(self.data_len, transferred_data_len, false);
                block_metrics.write_bytes.add(transferred_data_len.into());
                if let Status::Ok { .. } = status {
                    block_metrics.write_count.inc();
                }
                status
            }
            (Ok(_), RequestType::Flush) => {
                block_metrics.flush_count.inc();
                Status::Ok {
                    num_bytes_to_mem: 0,
                }
            }
            (Ok(transferred_data_len), RequestType::GetDeviceID) => {
                Status::from_data(self.data_len, transferred_data_len, true)
            }
            (_, RequestType::Unsupported(op)) => Status::Unsupported { op },
            (Err(err), _) => Status::IoErr {
                num_bytes_to_mem: 0,
                err,
            },
        };

        self.write_status_and_finish(&status, mem, block_metrics)
    }
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}

// SAFETY: Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

impl RequestHeader {
    pub fn new(request_type: u32, sector: u64) -> RequestHeader {
        RequestHeader {
            request_type,
            _reserved: 0,
            sector,
        }
    }
    /// Reads the request header from GuestMemoryMmap starting at `addr`.
    ///
    /// Virtio 1.0 specifies that the data is transmitted by the driver in little-endian
    /// format. Firecracker currently runs only on little endian platforms so we don't
    /// need to do an explicit little endian read as all reads are little endian by default.
    /// When running on a big endian platform, this code should not compile, and support
    /// for explicit little endian reads is required.
    #[cfg(target_endian = "little")]
    fn read_from(memory: &GuestMemoryMmap, addr: GuestAddress) -> Result<Self, VirtioBlockError> {
        let request_header: RequestHeader = memory
            .read_obj(addr)
            .map_err(VirtioBlockError::GuestMemory)?;
        Ok(request_header)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub r#type: RequestType,
    pub data_len: u32,
    pub status_addr: GuestAddress,
    sector: u64,
    data_addr: GuestAddress,
}

impl Request {
    pub fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
        num_disk_sectors: u64,
    ) -> Result<Request, VirtioBlockError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(VirtioBlockError::UnexpectedWriteOnlyDescriptor);
        }

        let request_header = RequestHeader::read_from(mem, avail_desc.addr)?;
        let mut req = Request {
            r#type: RequestType::from(request_header.request_type),
            sector: request_header.sector,
            data_addr: GuestAddress(0),
            data_len: 0,
            status_addr: GuestAddress(0),
        };

        let data_desc;
        let status_desc;
        let desc = avail_desc
            .next_descriptor()
            .ok_or(VirtioBlockError::DescriptorChainTooShort)?;

        if !desc.has_next() {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.r#type != RequestType::Flush {
                return Err(VirtioBlockError::DescriptorChainTooShort);
            }
        } else {
            data_desc = desc;
            status_desc = data_desc
                .next_descriptor()
                .ok_or(VirtioBlockError::DescriptorChainTooShort)?;

            if data_desc.is_write_only() && req.r#type == RequestType::Out {
                return Err(VirtioBlockError::UnexpectedWriteOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.r#type == RequestType::In {
                return Err(VirtioBlockError::UnexpectedReadOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.r#type == RequestType::GetDeviceID {
                return Err(VirtioBlockError::UnexpectedReadOnlyDescriptor);
            }

            req.data_addr = data_desc.addr;
            req.data_len = data_desc.len;
        }

        // check request validity
        match req.r#type {
            RequestType::In | RequestType::Out => {
                // Check that the data length is a multiple of 512 as specified in the virtio
                // standard.
                if !req.data_len.is_multiple_of(SECTOR_SIZE) {
                    return Err(VirtioBlockError::InvalidDataLength);
                }
                let top_sector = req
                    .sector
                    .checked_add(u64::from(req.data_len) >> SECTOR_SHIFT)
                    .ok_or(VirtioBlockError::InvalidOffset)?;
                if top_sector > num_disk_sectors {
                    return Err(VirtioBlockError::InvalidOffset);
                }
            }
            RequestType::GetDeviceID if req.data_len < VIRTIO_BLK_ID_BYTES => {
                return Err(VirtioBlockError::InvalidDataLength);
            }
            _ => {}
        }

        // The status MUST always be writable.
        if !status_desc.is_write_only() {
            return Err(VirtioBlockError::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len < 1 {
            return Err(VirtioBlockError::DescriptorLengthTooSmall);
        }

        req.status_addr = status_desc.addr;

        Ok(req)
    }

    pub(crate) fn rate_limit(&self, rate_limiter: &mut RateLimiter) -> bool {
        // If limiter.consume() fails it means there is no more TokenType::Ops
        // budget and rate limiting is in effect.
        if !rate_limiter.consume(1, TokenType::Ops) {
            return true;
        }
        // Exercise the rate limiter only if this request is of data transfer type.
        if self.r#type == RequestType::In || self.r#type == RequestType::Out {
            // If limiter.consume() fails it means there is no more TokenType::Bytes
            // budget and rate limiting is in effect.
            if !rate_limiter.consume(u64::from(self.data_len), TokenType::Bytes) {
                // Revert the OPS consume().
                rate_limiter.manual_replenish(1, TokenType::Ops);
                return true;
            }
        }

        false
    }

    fn offset(&self) -> u64 {
        self.sector << SECTOR_SHIFT
    }

    fn to_pending_request(&self, desc_idx: u16) -> PendingRequest {
        PendingRequest {
            r#type: self.r#type,
            data_len: self.data_len,
            status_addr: self.status_addr,
            desc_idx,
        }
    }

    pub(crate) fn process(
        self,
        disk: &mut DiskProperties,
        desc_idx: u16,
        mem: &GuestMemoryMmap,
        block_metrics: &BlockDeviceMetrics,
    ) -> ProcessingResult {
        let pending = self.to_pending_request(desc_idx);
        let res = match self.r#type {
            RequestType::In => {
                let _metric = block_metrics.read_agg.record_latency_metrics();
                disk.file_engine
                    .read(self.offset(), mem, self.data_addr, self.data_len, pending)
            }
            RequestType::Out => {
                let _metric = block_metrics.write_agg.record_latency_metrics();
                disk.file_engine
                    .write(self.offset(), mem, self.data_addr, self.data_len, pending)
            }
            RequestType::Flush => disk.file_engine.flush(pending),
            RequestType::GetDeviceID => {
                let res = mem
                    .write_slice(&disk.image_id, self.data_addr)
                    .map(|_| VIRTIO_BLK_ID_BYTES)
                    .map_err(IoErr::GetId);
                return ProcessingResult::Executed(pending.finish(mem, res, block_metrics));
            }
            RequestType::Unsupported(_) => {
                return ProcessingResult::Executed(pending.finish(mem, Ok(0), block_metrics));
            }
        };

        match res {
            Ok(block_io::FileEngineOk::Submitted) => ProcessingResult::Submitted,
            Ok(block_io::FileEngineOk::Executed(res)) => {
                ProcessingResult::Executed(res.req.finish(mem, Ok(res.count), block_metrics))
            }
            Err(err) => {
                if err.error.is_throttling_err() {
                    ProcessingResult::Throttled
                } else {
                    ProcessingResult::Executed(err.req.finish(
                        mem,
                        Err(IoErr::FileEngine(err.error)),
                        block_metrics,
                    ))
                }
            }
        }
    }
}
