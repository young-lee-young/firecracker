// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::{self, Debug};
use std::fs::File;
use std::io::Error as IoError;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};
use vmm_sys_util::ioctl_iow_nr;

use crate::devices::virtio::iovec::IoVecBuffer;
use crate::devices::virtio::net::generated;

// As defined in the Linux UAPI:
// https://elixir.bootlin.com/linux/v4.17/source/include/uapi/linux/if.h#L33
const IFACE_NAME_MAX_LEN: usize = 16;

/// List of errors the tap implementation can throw.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum TapError {
    /// Couldn't open /dev/net/tun: {0}
    OpenTun(IoError),
    /// Invalid interface name
    InvalidIfname,
    /// Error while creating ifreq structure: {0}. Invalid TUN/TAP Backend provided by {1}. Check our documentation on setting up the network devices.
    IfreqExecuteError(IoError, String),
    /// Error while setting the offload flags: {0}
    SetOffloadFlags(IoError),
    /// Error while setting size of the vnet header: {0}
    SetSizeOfVnetHdr(IoError),
}

const TUNTAP: ::std::os::raw::c_uint = 84;
ioctl_iow_nr!(TUNSETIFF, TUNTAP, 202, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETOFFLOAD, TUNTAP, 208, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETVNETHDRSZ, TUNTAP, 216, ::std::os::raw::c_int);

/// Handle for a network tap interface.
///
/// For now, this simply wraps the file descriptor for the tap device so methods
/// can run ioctls on the interface. The tap interface fd will be closed when
/// Tap goes out of scope, and the kernel will clean up the interface automatically.
#[derive(Debug)]
pub struct Tap {
    tap_file: File,
    pub(crate) if_name: [u8; IFACE_NAME_MAX_LEN],
}

// Returns a byte vector representing the contents of a null terminated C string which
// contains if_name.
fn build_terminated_if_name(if_name: &str) -> Result<[u8; IFACE_NAME_MAX_LEN], TapError> {
    // Convert the string slice to bytes, and shadow the variable,
    // since we no longer need the &str version.
    let if_name = if_name.as_bytes();

    if if_name.len() >= IFACE_NAME_MAX_LEN {
        return Err(TapError::InvalidIfname);
    }

    let mut terminated_if_name = [b'\0'; IFACE_NAME_MAX_LEN];
    terminated_if_name[..if_name.len()].copy_from_slice(if_name);

    Ok(terminated_if_name)
}

#[derive(Copy, Clone)]
pub struct IfReqBuilder(generated::ifreq);

impl fmt::Debug for IfReqBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IfReqBuilder {{ .. }}")
    }
}

impl IfReqBuilder {
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn if_name(mut self, if_name: &[u8; IFACE_NAME_MAX_LEN]) -> Self {
        // SAFETY: Since we don't call as_mut on the same union field more than once, this block is
        // safe.
        let ifrn_name = unsafe { self.0.ifr_ifrn.ifrn_name.as_mut() };
        ifrn_name.copy_from_slice(if_name.as_ref());

        self
    }

    pub(crate) fn flags(mut self, flags: i16) -> Self {
        self.0.ifr_ifru.ifru_flags = flags;
        self
    }

    pub(crate) fn execute<F: AsRawFd + Debug>(
        mut self,
        socket: &F,
        ioctl: u64,
    ) -> std::io::Result<generated::ifreq> {
        // SAFETY: ioctl is safe. Called with a valid socket fd, and we check the return.
        if unsafe { ioctl_with_mut_ref(socket, ioctl, &mut self.0) } < 0 {
            return Err(IoError::last_os_error());
        }

        Ok(self.0)
    }
}

impl Tap {
    /// Create a TUN/TAP device given the interface name.
    /// # Arguments
    ///
    /// * `if_name` - the name of the interface.
    pub fn open_named(if_name: &str) -> Result<Tap, TapError> {
        // SAFETY: Open calls are safe because we give a constant null-terminated
        // string and verify the result.
        let fd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(TapError::OpenTun(IoError::last_os_error()));
        }

        // SAFETY: We just checked that the fd is valid.
        let tuntap = unsafe { File::from_raw_fd(fd) };

        let terminated_if_name = build_terminated_if_name(if_name)?;
        let ifreq = IfReqBuilder::new()
            .if_name(&terminated_if_name)
            .flags(
                i16::try_from(generated::IFF_TAP | generated::IFF_NO_PI | generated::IFF_VNET_HDR)
                    .unwrap(),
            )
            .execute(&tuntap, TUNSETIFF())
            .map_err(|io_error| TapError::IfreqExecuteError(io_error, if_name.to_owned()))?;

        Ok(Tap {
            tap_file: tuntap,
            // SAFETY: Safe since only the name is accessed, and it's cloned out.
            if_name: unsafe { ifreq.ifr_ifrn.ifrn_name },
        })
    }

    /// Retrieve the interface's name as a str.
    pub fn if_name_as_str(&self) -> &str {
        let len = self
            .if_name
            .iter()
            .position(|x| *x == 0)
            .unwrap_or(IFACE_NAME_MAX_LEN);
        std::str::from_utf8(&self.if_name[..len]).unwrap_or("")
    }

    /// Set the offload flags for the tap interface.
    pub fn set_offload(&self, flags: c_uint) -> Result<(), TapError> {
        // SAFETY: ioctl is safe. Called with a valid tap fd, and we check the return.
        if unsafe { ioctl_with_val(&self.tap_file, TUNSETOFFLOAD(), c_ulong::from(flags)) } < 0 {
            return Err(TapError::SetOffloadFlags(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Set the size of the vnet hdr.
    pub fn set_vnet_hdr_size(&self, size: c_int) -> Result<(), TapError> {
        // SAFETY: ioctl is safe. Called with a valid tap fd, and we check the return.
        if unsafe { ioctl_with_ref(&self.tap_file, TUNSETVNETHDRSZ(), &size) } < 0 {
            return Err(TapError::SetSizeOfVnetHdr(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Write an `IoVecBuffer` to tap
    pub(crate) fn write_iovec(&mut self, buffer: &IoVecBuffer) -> Result<usize, IoError> {
        let iovcnt = i32::try_from(buffer.iovec_count()).unwrap();
        let iov = buffer.as_iovec_ptr();

        // SAFETY: `writev` is safe. Called with a valid tap fd, the iovec pointer and length
        // is provide by the `IoVecBuffer` implementation and we check the return value.
        let ret = unsafe { libc::writev(self.tap_file.as_raw_fd(), iov, iovcnt) };
        if ret == -1 {
            return Err(IoError::last_os_error());
        }
        Ok(usize::try_from(ret).unwrap())
    }

    /// Read from tap to an `IoVecBufferMut`
    pub(crate) fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> Result<usize, IoError> {
        let iov = buffer.as_mut_ptr();
        let iovcnt = buffer.len().try_into().unwrap();

        // SAFETY: `readv` is safe. Called with a valid tap fd, the iovec pointer and length
        // is provide by the `IoVecBufferMut` implementation and we check the return value.
        let ret = unsafe { libc::readv(self.tap_file.as_raw_fd(), iov, iovcnt) };
        if ret == -1 {
            return Err(IoError::last_os_error());
        }
        Ok(usize::try_from(ret).unwrap())
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.tap_file.as_raw_fd()
    }
}
