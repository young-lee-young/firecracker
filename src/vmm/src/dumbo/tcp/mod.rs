// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for handling incoming TCP connections.

pub mod connection;
mod endpoint;
pub mod handler;

use std::fmt::Debug;
use std::num::Wrapping;

use crate::dumbo::pdu::bytes::NetworkBytes;
use crate::dumbo::pdu::tcp::{Flags as TcpFlags, TcpSegment};

/// The largest possible window size (requires the window scaling option).
pub const MAX_WINDOW_SIZE: u32 = 1_073_725_440;

/// The default maximum segment size (MSS) value, used when no MSS information is carried
/// over the initial handshake.
pub const MSS_DEFAULT: u16 = 536;

/// Describes whether a particular entity (a [`Connection`] for example) has segments to send.
///
/// [`Connection`]: connection/struct.Connection.html
#[derive(Debug, PartialEq, Eq)]
pub enum NextSegmentStatus {
    /// At least one segment is available immediately.
    Available,
    /// There's nothing to send.
    Nothing,
    /// A retransmission timeout (RTO) will trigger after the specified point in time.
    Timeout(u64),
}

/// Represents the configuration of the sequence number and `ACK` number fields for outgoing
/// `RST` segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RstConfig {
    /// The `RST` segment will carry the specified sequence number, and will not have
    /// the `ACK` flag set.
    Seq(u32),
    /// The `RST` segment will carry 0 as the sequence number, will have the `ACK` flag enabled,
    /// and the `ACK` number will be set to the specified value.
    Ack(u32),
}

impl RstConfig {
    /// Creates a `RstConfig` in response to the given segment.
    pub fn new<T: NetworkBytes + Debug>(s: &TcpSegment<T>) -> Self {
        if s.flags_after_ns().intersects(TcpFlags::ACK) {
            // If s contains an ACK number, we use that as the sequence number of the RST.
            RstConfig::Seq(s.ack_number())
        } else {
            // Otherwise we try to guess a valid ACK number for the RST like this.
            RstConfig::Ack(s.sequence_number().wrapping_add(s.payload_len().into()))
        }
    }

    /// Returns the sequence number, acknowledgement number, and TCP flags (not counting `NS`) that
    /// must be set on the outgoing `RST` segment.
    pub fn seq_ack_tcp_flags(self) -> (u32, u32, TcpFlags) {
        match self {
            RstConfig::Seq(seq) => (seq, 0, TcpFlags::RST),
            RstConfig::Ack(ack) => (0, ack, TcpFlags::RST | TcpFlags::ACK),
        }
    }
}

/// Returns true if `a` comes after `b` in the sequence number space, relative to the maximum
/// possible window size.
///
/// Please note this is not a connex binary relation; in other words, given two sequence numbers,
/// it's sometimes possible that `seq_after(a, b) || seq_after(b, a) == false`. This is why
/// `seq_after(a, b)` can't be defined as simply `!seq_at_or_after(b, a)`.
#[inline]
pub fn seq_after(a: Wrapping<u32>, b: Wrapping<u32>) -> bool {
    a != b && (a - b).0 < MAX_WINDOW_SIZE
}

/// Returns true if `a` comes after, or is at `b` in the sequence number space, relative to
/// the maximum possible window size.
///
/// Please note this is not a connex binary relation; in other words, given two sequence numbers,
/// it's sometimes possible that `seq_at_or_after(a, b) || seq_at_or_after(b, a) == false`. This
/// is why `seq_after(a, b)` can't be defined as simply `!seq_at_or_after(b, a)`.
#[inline]
pub fn seq_at_or_after(a: Wrapping<u32>, b: Wrapping<u32>) -> bool {
    (a - b).0 < MAX_WINDOW_SIZE
}

