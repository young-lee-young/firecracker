// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::ops::Deref;
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;

use block_io::FileEngine;
use serde::{Deserialize, Serialize};
use vm_memory::ByteValued;
use vmm_sys_util::eventfd::EventFd;

use super::io::async_io;
use super::request::*;
use super::{BLOCK_QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE, VirtioBlockError, io as block_io};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::block::virtio::metrics::{BlockDeviceMetrics, BlockMetricsPerDevice};
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_blk::{
    VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_BLK_ID_BYTES,
};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::{InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::impl_device_type;
use crate::logger::{IncMetric, error, warn};
use crate::rate_limiter::{BucketUpdate, RateLimiter};
use crate::utils::u64_to_usize;
use crate::vmm_config::RateLimiterConfig;
use crate::vmm_config::drive::BlockDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// The engine file type, either Sync or Async (through io_uring).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileEngineType {
    /// Use an Async engine, based on io_uring.
    Async,
    /// Use a Sync engine, based on blocking system calls.
    #[default]
    Sync,
}

/// Helper object for setting up all `Block` fields derived from its backing file.
#[derive(Debug)]
pub struct DiskProperties {
    pub file_path: String,
    pub file_engine: FileEngine,
    pub nsectors: u64,
    pub image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
}

impl DiskProperties {
    // Helper function that opens the file with the proper access permissions
    fn open_file(disk_image_path: &str, is_disk_read_only: bool) -> Result<File, VirtioBlockError> {
        OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))
            .map_err(|x| VirtioBlockError::BackingFile(x, disk_image_path.to_string()))
    }

    // Helper function that gets the size of the file
    fn file_size(disk_image_path: &str, disk_image: &mut File) -> Result<u64, VirtioBlockError> {
        let disk_size = disk_image
            .seek(SeekFrom::End(0))
            .map_err(|x| VirtioBlockError::BackingFile(x, disk_image_path.to_string()))?;

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if disk_size % u64::from(SECTOR_SIZE) != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; the remainder will not be \
                 visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        Ok(disk_size)
    }

    /// Create a new file for the block device using a FileEngine
    pub fn new(
        disk_image_path: String,
        is_disk_read_only: bool,
        file_engine_type: FileEngineType,
    ) -> Result<Self, VirtioBlockError> {
        let mut disk_image = Self::open_file(&disk_image_path, is_disk_read_only)?;
        let disk_size = Self::file_size(&disk_image_path, &mut disk_image)?;
        let image_id = Self::build_disk_image_id(&disk_image);

        Ok(Self {
            file_path: disk_image_path,
            file_engine: FileEngine::from_file(disk_image, file_engine_type)
                .map_err(VirtioBlockError::FileEngine)?,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id,
        })
    }

    /// Update the path to the file backing the block device
    pub fn update(
        &mut self,
        disk_image_path: String,
        is_disk_read_only: bool,
    ) -> Result<(), VirtioBlockError> {
        let mut disk_image = Self::open_file(&disk_image_path, is_disk_read_only)?;
        let disk_size = Self::file_size(&disk_image_path, &mut disk_image)?;

        self.image_id = Self::build_disk_image_id(&disk_image);
        self.file_engine
            .update_file_path(disk_image)
            .map_err(VirtioBlockError::FileEngine)?;
        self.nsectors = disk_size >> SECTOR_SHIFT;
        self.file_path = disk_image_path;

        Ok(())
    }

    fn build_device_id(disk_file: &File) -> Result<String, VirtioBlockError> {
        let blk_metadata = disk_file
            .metadata()
            .map_err(VirtioBlockError::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> [u8; VIRTIO_BLK_ID_BYTES as usize] {
        let mut default_id = [0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(disk_id_string) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = disk_id_string.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].copy_from_slice(&disk_id[..bytes_to_copy]);
            }
        }
        default_id
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct ConfigSpace {
    pub capacity: u64,
}

// SAFETY: `ConfigSpace` contains only PODs in `repr(C)` or `repr(transparent)`, without padding.
unsafe impl ByteValued for ConfigSpace {}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VirtioBlockConfig {
    /// Unique identifier of the drive.
    pub drive_id: String,
    /// Part-UUID. Represents the unique id of the boot partition of this device. It is
    /// optional and it will be used only if the `is_root_device` field is true.
    pub partuuid: Option<String>,
    /// If set to true, it makes the current device the root block device.
    /// Setting this flag to true will mount the block device in the
    /// guest under /dev/vda unless the partuuid is present.
    pub is_root_device: bool,
    /// If set to true, the drive will ignore flush requests coming from
    /// the guest driver.
    #[serde(default)]
    pub cache_type: CacheType,

    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_read_only: bool,
    /// Path of the backing file on the host
    pub path_on_host: String,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
    /// The type of IO engine used by the device.
    #[serde(default)]
    #[serde(rename = "io_engine")]
    pub file_engine_type: FileEngineType,
}

impl TryFrom<&BlockDeviceConfig> for VirtioBlockConfig {
    type Error = VirtioBlockError;

    fn try_from(value: &BlockDeviceConfig) -> Result<Self, Self::Error> {
        if let (Some(path_on_host), None) = (&value.path_on_host, &value.socket) {
            Ok(Self {
                drive_id: value.drive_id.clone(),
                partuuid: value.partuuid.clone(),
                is_root_device: value.is_root_device,
                cache_type: value.cache_type,

                is_read_only: value.is_read_only.unwrap_or(false),
                path_on_host: path_on_host.clone(),
                rate_limiter: value.rate_limiter,
                file_engine_type: value.file_engine_type.unwrap_or_default(),
            })
        } else {
            Err(VirtioBlockError::Config)
        }
    }
}

impl From<VirtioBlockConfig> for BlockDeviceConfig {
    fn from(value: VirtioBlockConfig) -> Self {
        Self {
            drive_id: value.drive_id,
            partuuid: value.partuuid,
            is_root_device: value.is_root_device,
            cache_type: value.cache_type,

            is_read_only: Some(value.is_read_only),
            path_on_host: Some(value.path_on_host),
            rate_limiter: value.rate_limiter,
            file_engine_type: Some(value.file_engine_type),

            socket: None,
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
#[derive(Debug)]
pub struct VirtioBlock {
    // Virtio fields.
    pub avail_features: u64,
    pub acked_features: u64,
    pub config_space: ConfigSpace,
    pub activate_evt: EventFd,

    // Transport related fields.
    pub queues: Vec<Queue>,
    pub queue_evts: [EventFd; 1],
    pub device_state: DeviceState,

    // Implementation specific fields.
    pub id: String,
    pub partuuid: Option<String>,
    pub cache_type: CacheType,
    pub root_device: bool,
    pub read_only: bool,

    // Host file and properties.
    pub disk: DiskProperties,
    pub rate_limiter: RateLimiter,
    pub is_io_engine_throttled: bool,
    pub metrics: Arc<BlockDeviceMetrics>,
}

macro_rules! unwrap_async_file_engine_or_return {
    ($file_engine: expr) => {
        match $file_engine {
            FileEngine::Async(engine) => engine,
            FileEngine::Sync(_) => {
                error!("The block device doesn't use an async IO engine");
                return;
            }
        }
    };
}

impl VirtioBlock {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(config: VirtioBlockConfig) -> Result<VirtioBlock, VirtioBlockError> {
        let disk_properties = DiskProperties::new(
            config.path_on_host,
            config.is_read_only,
            config.file_engine_type,
        )?;

        let rate_limiter = config
            .rate_limiter
            .map(RateLimiterConfig::try_into)
            .transpose()
            .map_err(VirtioBlockError::RateLimiter)?
            .unwrap_or_default();

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if config.cache_type == CacheType::Writeback {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if config.is_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        // EFD_NONBLOCK 表示是一个非阻塞模式的 eventfd
        // 非阻塞表示：在读取的时候，如果没有事件，不会卡住等待，而是立即返回 EAGAIN 错误
        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?];

        let queues = BLOCK_QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let config_space = ConfigSpace {
            capacity: disk_properties.nsectors.to_le(),
        };

        Ok(VirtioBlock {
            avail_features,
            acked_features: 0u64,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,

            queues,
            queue_evts,
            device_state: DeviceState::Inactive,

            id: config.drive_id.clone(),
            partuuid: config.partuuid,
            cache_type: config.cache_type,
            root_device: config.is_root_device,
            read_only: config.is_read_only,

            disk: disk_properties,
            rate_limiter,
            is_io_engine_throttled: false,
            metrics: BlockMetricsPerDevice::alloc(config.drive_id),
        })
    }

    /// Returns a copy of a device config
    pub fn config(&self) -> VirtioBlockConfig {
        let rl: RateLimiterConfig = (&self.rate_limiter).into();
        VirtioBlockConfig {
            drive_id: self.id.clone(),
            path_on_host: self.disk.file_path.clone(),
            is_root_device: self.root_device,
            partuuid: self.partuuid.clone(),
            is_read_only: self.read_only,
            cache_type: self.cache_type,
            rate_limiter: rl.into_option(),
            file_engine_type: self.file_engine_type(),
        }
    }

    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.queue_evts[0].read() {
            error!("Failed to get queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if self.rate_limiter.is_blocked() {
            self.metrics.rate_limiter_throttled_events.inc();
        } else if self.is_io_engine_throttled {
            self.metrics.io_engine_throttled_events.inc();
        } else {
            self.process_virtio_queues().unwrap()
        }
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        self.process_queue(0)
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        self.metrics.rate_limiter_event_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        if self.rate_limiter.event_handler().is_ok() {
            self.process_queue(0).unwrap()
        }
    }

    /// Device specific function for peaking inside a queue and processing descriptors.
    pub fn process_queue(&mut self, queue_index: usize) -> Result<(), InvalidAvailIdx> {
        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();

        let queue = &mut self.queues[queue_index];
        let mut used_any = false;

        while let Some(head) = queue.pop_or_enable_notification()? {
            self.metrics.remaining_reqs_count.add(queue.len().into());
            let processing_result =
                match Request::parse(&head, &active_state.mem, self.disk.nsectors) {
                    Ok(request) => {
                        if request.rate_limit(&mut self.rate_limiter) {
                            // Stop processing the queue and return this descriptor chain to the
                            // avail ring, for later processing.
                            queue.undo_pop();
                            self.metrics.rate_limiter_throttled_events.inc();
                            break;
                        }

                        request.process(
                            &mut self.disk,
                            head.index,
                            &active_state.mem,
                            &self.metrics,
                        )
                    }
                    Err(err) => {
                        error!("Failed to parse available descriptor chain: {:?}", err);
                        self.metrics.execute_fails.inc();
                        ProcessingResult::Executed(FinishedRequest {
                            num_bytes_to_mem: 0,
                            desc_idx: head.index,
                        })
                    }
                };

            match processing_result {
                ProcessingResult::Submitted => {}
                ProcessingResult::Throttled => {
                    queue.undo_pop();
                    self.is_io_engine_throttled = true;
                    break;
                }
                ProcessingResult::Executed(finished) => {
                    used_any = true;
                    queue
                        .add_used(head.index, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                head.index, err
                            )
                        });
                }
            }
        }
        queue.advance_used_ring_idx();

        if used_any && queue.prepare_kick() {
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }

        if let FileEngine::Async(ref mut engine) = self.disk.file_engine
            && let Err(err) = engine.kick_submission_queue()
        {
            error!("BlockError submitting pending block requests: {:?}", err);
        }

        if !used_any {
            self.metrics.no_avail_buffer.inc();
        }

        Ok(())
    }

    fn process_async_completion_queue(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.disk.file_engine);

        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();
        let queue = &mut self.queues[0];

        loop {
            match engine.pop(&active_state.mem) {
                Err(error) => {
                    error!("Failed to read completed io_uring entry: {:?}", error);
                    break;
                }
                Ok(None) => break,
                Ok(Some(cqe)) => {
                    let res = cqe.result();
                    let user_data = cqe.user_data();

                    let (pending, res) = match res {
                        Ok(count) => (user_data, Ok(count)),
                        Err(error) => (
                            user_data,
                            Err(IoErr::FileEngine(block_io::BlockIoError::Async(
                                async_io::AsyncIoError::IO(error),
                            ))),
                        ),
                    };
                    let finished = pending.finish(&active_state.mem, res, &self.metrics);
                    queue
                        .add_used(finished.desc_idx, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                finished.desc_idx, err
                            )
                        });
                }
            }
        }
        queue.advance_used_ring_idx();

        if queue.prepare_kick() {
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }
    }

    pub fn process_async_completion_event(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.disk.file_engine);

        if let Err(err) = engine.completion_evt().read() {
            error!("Failed to get async completion event: {:?}", err);
        } else {
            self.process_async_completion_queue();

            if self.is_io_engine_throttled {
                self.is_io_engine_throttled = false;
                self.process_queue(0).unwrap()
            }
        }
    }

    /// Update the backing file and the config space of the block device.
    pub fn update_disk_image(&mut self, disk_image_path: String) -> Result<(), VirtioBlockError> {
        self.disk.update(disk_image_path, self.read_only)?;
        self.config_space.capacity = self.disk.nsectors.to_le(); // virtio_block_config_space();

        // Kick the driver to pick up the changes. (But only if the device is already activated).
        if self.is_activated() {
            self.interrupt_trigger()
                .trigger(VirtioInterruptType::Config)
                .unwrap();
        }

        self.metrics.update_count.inc();
        Ok(())
    }

    /// Updates the parameters for the rate limiter
    pub fn update_rate_limiter(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        self.rate_limiter.update_buckets(bytes, ops);
    }

    /// Retrieve the file engine type.
    pub fn file_engine_type(&self) -> FileEngineType {
        match self.disk.file_engine {
            FileEngine::Sync(_) => FileEngineType::Sync,
            FileEngine::Async(_) => FileEngineType::Async,
        }
    }

    fn drain_and_flush(&mut self, discard: bool) {
        if let Err(err) = self.disk.file_engine.drain_and_flush(discard) {
            error!("Failed to drain ops and flush block data: {:?}", err);
        }
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {
        if !self.is_activated() {
            return;
        }

        self.drain_and_flush(false);
        if let FileEngine::Async(ref _engine) = self.disk.file_engine {
            self.process_async_completion_queue();
        }
    }
}

impl VirtioDevice for VirtioBlock {
    impl_device_type!(VirtioDeviceType::Block);

    fn id(&self) -> &str {
        &self.id
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
    }

    fn config_as_bytes(&self) -> &[u8] {
        self.config_space.as_slice()
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let config_space_bytes = self.config_space.as_mut_slice();
        let start = usize::try_from(offset).ok();
        let end = start.and_then(|s| s.checked_add(data.len()));
        let Some(dst) = start
            .zip(end)
            .and_then(|(start, end)| config_space_bytes.get_mut(start..end))
        else {
            error!("Failed to write config space");
            self.metrics.cfg_fails.inc();
            return;
        };

        dst.copy_from_slice(data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        assert!(!self.is_activated());

        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        let event_idx = self.has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX));
        if event_idx {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        if self.activate_evt.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

impl Drop for VirtioBlock {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Unsafe => {
                if let Err(err) = self.disk.file_engine.drain(true) {
                    error!("Failed to drain ops on drop: {:?}", err);
                }
            }
            CacheType::Writeback => {
                self.drain_and_flush(true);
            }
        };
    }
}
