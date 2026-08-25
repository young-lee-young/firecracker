// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides helper logic for parsing and writing protocol data units, and minimalist
//! implementations of a TCP listener, a TCP connection, and an HTTP/1.1 server.
pub mod pdu;
pub mod tcp;

use std::ops::Index;

pub use crate::dumbo::pdu::arp::{ETH_IPV4_FRAME_LEN, EthIPv4ArpFrame};
pub use crate::dumbo::pdu::ethernet::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetFrame, PAYLOAD_OFFSET as ETHERNET_PAYLOAD_OFFSET,
};
pub use crate::dumbo::pdu::ipv4::{IPv4Packet, PROTOCOL_TCP, PROTOCOL_UDP};
use crate::utils::net::mac::MacAddr;

/// Represents a generalization of a borrowed `[u8]` slice.
#[allow(clippy::len_without_is_empty)]
pub trait ByteBuffer: Index<usize, Output = u8> {
    /// Returns the length of the buffer.
    fn len(&self) -> usize;

    /// Reads `buf.len()` bytes from `self` into `buf`, starting at `offset`.
    ///
    /// # Panics
    ///
    /// Panics if `offset + buf.len()` > `self.len()`.
    fn read_to_slice(&self, offset: usize, buf: &mut [u8]);
}

impl ByteBuffer for [u8] {
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn read_to_slice(&self, offset: usize, buf: &mut [u8]) {
        let buf_len = buf.len();
        buf.copy_from_slice(&self[offset..offset + buf_len]);
    }
}

