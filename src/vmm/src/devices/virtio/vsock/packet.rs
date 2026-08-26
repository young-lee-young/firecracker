// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

//! `VsockPacket` provides a thin wrapper over the buffers exchanged via virtio queues.
//! There are two components to a vsock packet, each using its own descriptor in a
//! virtio queue:
//! - the packet header; and
//! - the packet data/buffer.
//!
//! There is a 1:1 relation between descriptor chains and packets: the first (chain head) holds
//! the header, and an optional second descriptor holds the data. The second descriptor is only
//! present for data packets (VSOCK_OP_RW).
//!
//! `VsockPacket` wraps these two buffers and provides direct access to the data stored
//! in guest memory. This is done to avoid unnecessarily copying data from guest memory
//! to temporary buffers, before passing it on to the vsock backend.

use std::fmt::Debug;

use vm_memory::volatile_memory::Error;
use vm_memory::{GuestMemoryError, ReadVolatile, WriteVolatile};

use super::{VsockError, defs};
use crate::devices::virtio::iovec::{IoVecBuffer, IoVecBufferMut};
use crate::devices::virtio::queue::DescriptorChain;
use crate::vstate::memory::{ByteValued, GuestMemoryMmap};

// The vsock packet header is defined by the C struct:
//
// ```C
//     le64 src_cid;
//     le64 dst_cid;
//     le32 src_port;
//     le32 dst_port;
//     le32 len;
//     le16 type;
//     le16 op;
//     le32 flags;
//     le32 buf_alloc;
//     le32 fwd_cnt;
// } __attribute__((packed));
// ```
// We create a rust structure that mirrors it.
// The mirroring struct is only used privately by `VsockPacket`, that offers getter and setter
// methods, for each struct field, that will also handle the correct endianess.

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VsockPacketHeader {
    // Source CID.
    src_cid: u64,
    // Destination CID.
    dst_cid: u64,
    // Source port.
    src_port: u32,
    // Destination port.
    dst_port: u32,
    // Data length (in bytes) - may be 0, if there is no data buffer.
    len: u32,
    // Socket type. Currently, only connection-oriented streams are defined by the vsock protocol.
    type_: u16,
    // Operation ID - one of the VSOCK_OP_* values; e.g.
    // - VSOCK_OP_RW: a data packet;
    // - VSOCK_OP_REQUEST: connection request;
    // - VSOCK_OP_RST: forcefull connection termination;
    // etc (see `super::defs::uapi` for the full list).
    op: u16,
    // Additional options (flags) associated with the current operation (`op`).
    // Currently, only used with shutdown requests (VSOCK_OP_SHUTDOWN).
    flags: u32,
    // Size (in bytes) of the packet sender receive buffer (for the connection to which this packet
    // belongs).
    buf_alloc: u32,
    // Number of bytes the sender has received and consumed (for the connection to which this
    // packet belongs). For instance, for our Unix backend, this counter would be the total
    // number of bytes we have successfully written to a backing Unix socket.
    fwd_cnt: u32,
}

impl VsockPacketHeader {
    pub fn src_cid(&self) -> u64 {
        u64::from_le(self.src_cid)
    }

    pub fn set_src_cid(&mut self, cid: u64) -> &mut Self {
        self.src_cid = cid.to_le();
        self
    }

    pub fn dst_cid(&self) -> u64 {
        u64::from_le(self.dst_cid)
    }

    pub fn set_dst_cid(&mut self, cid: u64) -> &mut Self {
        self.dst_cid = cid.to_le();
        self
    }

    pub fn src_port(&self) -> u32 {
        u32::from_le(self.src_port)
    }

    pub fn set_src_port(&mut self, port: u32) -> &mut Self {
        self.src_port = port.to_le();
        self
    }

    pub fn dst_port(&self) -> u32 {
        u32::from_le(self.dst_port)
    }

    pub fn set_dst_port(&mut self, port: u32) -> &mut Self {
        self.dst_port = port.to_le();
        self
    }

    pub fn len(&self) -> u32 {
        u32::from_le(self.len)
    }

    pub fn set_len(&mut self, len: u32) -> &mut Self {
        self.len = len.to_le();
        self
    }

    pub fn type_(&self) -> u16 {
        u16::from_le(self.type_)
    }

    pub fn set_type(&mut self, type_: u16) -> &mut Self {
        self.type_ = type_.to_le();
        self
    }

    pub fn op(&self) -> u16 {
        u16::from_le(self.op)
    }

    pub fn set_op(&mut self, op: u16) -> &mut Self {
        self.op = op.to_le();
        self
    }

    pub fn flags(&self) -> u32 {
        u32::from_le(self.flags)
    }

    pub fn set_flags(&mut self, flags: u32) -> &mut Self {
        self.flags = flags.to_le();
        self
    }

    pub fn set_flag(&mut self, flag: u32) -> &mut Self {
        self.set_flags(self.flags() | flag);
        self
    }

    pub fn buf_alloc(&self) -> u32 {
        u32::from_le(self.buf_alloc)
    }

    pub fn set_buf_alloc(&mut self, buf_alloc: u32) -> &mut Self {
        self.buf_alloc = buf_alloc.to_le();
        self
    }

    pub fn fwd_cnt(&self) -> u32 {
        u32::from_le(self.fwd_cnt)
    }

    pub fn set_fwd_cnt(&mut self, fwd_cnt: u32) -> &mut Self {
        self.fwd_cnt = fwd_cnt.to_le();
        self
    }
}

/// The vsock packet header struct size (the struct is packed).
pub const VSOCK_PKT_HDR_SIZE: u32 = 44;

// SAFETY: `VsockPacketHeader` is a POD and contains no padding.
unsafe impl ByteValued for VsockPacketHeader {}

// /// Struct describing a single vsock packet.
// ///
// /// Encapsulates the virtio descriptor chain containing the packet through the `IoVecBuffer[Mut]`
// /// abstractions.
#[derive(Debug, Default)]
pub struct VsockPacketTx {
    /// A copy of the vsock packet's 44-byte header, held in hypervisor memory
    /// to minimize the number of accesses to guest memory. Can be written back
    /// to geust memory using [`VsockPacket::commit_hdr`] (only for RX buffers).
    pub hdr: VsockPacketHeader,
    /// The raw buffer, as it is contained in guest memory (containing both
    /// header and payload)
    buffer: IoVecBuffer,
}

impl VsockPacketTx {
    /// Create the packet wrapper from a TX virtq chain head.
    ///
    /// ## Errors
    /// Returns
    /// - [`VsockError::UnreadableDescriptor`] if the provided descriptor chain contains any
    ///   descriptor not marked as writable.
    /// - [`VsockError::DescChainTooShortForHeader`] if the descriptor chain's total buffer length
    ///   is insufficient to hold the 44 byte vsock header
    /// - [`VsockError::InvalidPktLen`] if the contained vsock header describes a vsock packet whose
    ///   length would exceed [`defs::MAX_PKT_BUR_SIZE`].
    /// - [`VsockError::DescChainTooShortForPacket`] if the contained vsock header describes a vsock
    ///   packet whose length exceeds the descriptor chain's actual total buffer length.
    pub fn parse(
        &mut self,
        mem: &GuestMemoryMmap,
        chain: DescriptorChain,
    ) -> Result<(), VsockError> {
        // SAFETY: This descriptor chain is only loaded once
        // virtio requests are handled sequentially so no two IoVecBuffers
        // are live at the same time, meaning this has exclusive ownership over the memory
        unsafe { self.buffer.load_descriptor_chain(mem, chain)? };

        let mut hdr = VsockPacketHeader::default();
        match self.buffer.read_exact_volatile_at(hdr.as_mut_slice(), 0) {
            Ok(()) => (),
            Err(Error::PartialBuffer { completed, .. }) => {
                return Err(VsockError::DescChainTooShortForHeader(completed));
            }
            Err(err) => return Err(VsockError::GuestMemoryMmap(err.into())),
        }

        if hdr.len > defs::MAX_PKT_BUF_SIZE {
            return Err(VsockError::InvalidPktLen(hdr.len));
        }

        if hdr.len > self.buffer.len() - VSOCK_PKT_HDR_SIZE {
            return Err(VsockError::DescChainTooShortForPacket(
                self.buffer.len(),
                hdr.len,
            ));
        }
        self.hdr = hdr;
        Ok(())
    }

    pub fn write_from_offset_to<T: WriteVolatile + Debug>(
        &self,
        dst: &mut T,
        offset: u32,
        count: u32,
    ) -> Result<u32, VsockError> {
        if count
            > self
                .buffer
                .len()
                .saturating_sub(VSOCK_PKT_HDR_SIZE)
                .saturating_sub(offset)
        {
            return Err(VsockError::GuestMemoryBounds);
        }

        self.buffer
            .read_volatile_at(dst, (offset + VSOCK_PKT_HDR_SIZE) as usize, count as usize)
            .map_err(|err| VsockError::GuestMemoryMmap(GuestMemoryError::from(err)))
            .and_then(|read| read.try_into().map_err(|_| VsockError::DescChainOverflow))
    }

    /// Returns the total length of this [`VsockPacket`]'s buffer (e.g. the amount of data bytes
    /// contained in this packet).
    ///
    /// Return value will equal the total length of the underlying descriptor chain's buffers,
    /// minus the length of the vsock header.
    pub fn buf_size(&self) -> u32 {
        self.buffer.len() - VSOCK_PKT_HDR_SIZE
    }
}

/// Struct describing a single vsock packet.
///
/// Encapsulates the virtio descriptor chain containing the packet through the `IoVecBuffer[Mut]`
/// abstractions.
#[derive(Debug)]
pub struct VsockPacketRx {
    /// A copy of the vsock packet's 44-byte header, held in hypervisor memory
    /// to minimize the number of accesses to guest memory. Can be written back
    /// to geust memory using [`VsockPacket::commit_hdr`] (only for RX buffers).
    pub hdr: VsockPacketHeader,
    /// The raw buffer, as it is contained in guest memory (containing both
    /// header and payload)
    buffer: IoVecBufferMut,
}

impl VsockPacketRx {
    /// Creates new VsockPacketRx.
    pub fn new() -> Result<Self, VsockError> {
        let buffer = IoVecBufferMut::new().map_err(VsockError::IovDeque)?;
        Ok(Self {
            hdr: Default::default(),
            buffer,
        })
    }

    /// Create the packet wrapper from an RX virtq chain head.
    ///
    /// ## Errors
    /// Returns [`VsockError::DescChainTooShortForHeader`] if the descriptor chain's total buffer
    /// length is insufficient to hold the 44 byte vsock header
    pub fn parse(
        &mut self,
        mem: &GuestMemoryMmap,
        chain: DescriptorChain,
    ) -> Result<(), VsockError> {
        // SAFETY: This descriptor chain is only loaded once
        // virtio requests are handled sequentially so no two IoVecBuffers
        // are live at the same time, meaning this has exclusive ownership over the memory
        unsafe { self.buffer.load_descriptor_chain(mem, chain)? };
        if self.buffer.len() < VSOCK_PKT_HDR_SIZE {
            return Err(VsockError::DescChainTooShortForHeader(
                self.buffer.len() as usize
            ));
        }
        self.hdr = VsockPacketHeader::default();
        Ok(())
    }

    /// Writes the local copy of the packet header to the guest memory.
    ///
    /// ## Errors
    /// The function returns [`VsockError::UnwritableDescriptor`] if this [`VsockPacket`]
    /// contains a guest-to-host (TX) packet. It returned [`VsockError::InvalidPktLen`] if the
    /// packet's payload as described by this [`VsockPacket`] would exceed
    /// [`defs::MAX_PKT_BUF_SIZE`].
    pub fn commit_hdr(&mut self) -> Result<(), VsockError> {
        if self.hdr.len > defs::MAX_PKT_BUF_SIZE {
            return Err(VsockError::InvalidPktLen(self.hdr.len));
        }
        self.buffer
            .write_all_volatile_at(self.hdr.as_slice(), 0)
            .map_err(GuestMemoryError::from)
            .map_err(VsockError::GuestMemoryMmap)
    }

    /// Returns the total length of this [`VsockPacket`]'s buffer (e.g. the amount of data bytes
    /// contained in this packet).
    ///
    /// Return value will equal the total length of the underlying descriptor chain's buffers,
    /// minus the length of the vsock header.
    pub fn buf_size(&self) -> u32 {
        self.buffer.len() - VSOCK_PKT_HDR_SIZE
    }

    pub fn read_at_offset_from<T: ReadVolatile + Debug>(
        &mut self,
        src: &mut T,
        offset: u32,
        count: u32,
    ) -> Result<u32, VsockError> {
        if count
            > self
                .buffer
                .len()
                .saturating_sub(VSOCK_PKT_HDR_SIZE)
                .saturating_sub(offset)
        {
            return Err(VsockError::GuestMemoryBounds);
        }

        self.buffer
            .write_volatile_at(src, (offset + VSOCK_PKT_HDR_SIZE) as usize, count as usize)
            .map_err(|err| VsockError::GuestMemoryMmap(GuestMemoryError::from(err)))
            .and_then(|read| read.try_into().map_err(|_| VsockError::DescChainOverflow))
    }
}
