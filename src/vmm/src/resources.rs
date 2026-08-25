// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::From;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

use crate::cpu_config::templates::CustomCpuTemplate;
use crate::devices::virtio::device::VirtioDevice;
use crate::logger::{LoggerConfig, info};
use crate::mmds;
use crate::mmds::data_store::{Mmds, MmdsVersion};
use crate::mmds::ns::MmdsNetworkStack;
use crate::utils::mib_to_bytes;
use crate::utils::net::ipv4addr::is_link_local_valid;
use crate::vmm_config::TokenBucketConfig;
use crate::vmm_config::balloon::*;
use crate::vmm_config::boot_source::{
    BootConfig, BootSource, BootSourceConfig, BootSourceConfigError,
};
use crate::vmm_config::drive::*;
use crate::vmm_config::entropy::*;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::{MachineConfig, MachineConfigError, MachineConfigUpdate};
use crate::vmm_config::memory_hotplug::{MemoryHotplugConfig, MemoryHotplugConfigError};
use crate::vmm_config::metrics::{MetricsConfig, MetricsConfigError, init_metrics};
use crate::vmm_config::mmds::{MmdsConfig, MmdsConfigError};
use crate::vmm_config::net::*;
use crate::vmm_config::pmem::{PmemBuilder, PmemConfig, PmemConfigError};
use crate::vmm_config::serial::SerialConfig;
use crate::vmm_config::vsock::*;
use crate::vstate::memory;
use crate::vstate::memory::{GuestRegionMmap, MemoryError};

/// Errors encountered when configuring microVM resources.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ResourcesError {
    /// Balloon device error: {0}
    BalloonDevice(#[from] BalloonConfigError),
    /// Block device error: {0}
    BlockDevice(#[from] DriveError),
    /// Boot source error: {0}
    BootSource(#[from] BootSourceConfigError),
    /// File operation error: {0}
    File(#[from] std::io::Error),
    /// Invalid JSON: {0}
    InvalidJson(#[from] serde_json::Error),
    /// Logger error: {0}
    Logger(#[from] crate::logger::LoggerUpdateError),
    /// Metrics error: {0}
    Metrics(#[from] MetricsConfigError),
    /// MMDS error: {0}
    Mmds(#[from] mmds::data_store::MmdsDatastoreError),
    /// MMDS config error: {0}
    MmdsConfig(#[from] MmdsConfigError),
    /// Network device error: {0}
    NetDevice(#[from] NetworkInterfaceError),
    /// VM config error: {0}
    MachineConfig(#[from] MachineConfigError),
    /// Vsock device error: {0}
    VsockDevice(#[from] VsockConfigError),
    /// Entropy device error: {0}
    EntropyConfig(#[from] EntropyDeviceError),
    /// Pmem device error: {0}
    PmemConfig(#[from] PmemConfigError),
    /// Memory hotplug config error: {0}
    MemoryHotplugConfig(#[from] MemoryHotplugConfigError),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum CustomCpuTemplateOrPath {
    Path(PathBuf),
    Template(CustomCpuTemplate),
}

/// Used for configuring a vmm from one single json passed to the Firecracker process.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub struct VmmConfig {
    pub balloon: Option<BalloonDeviceConfig>,
    pub drives: Vec<BlockDeviceConfig>,
    pub boot_source: BootSourceConfig,
    pub cpu_config: Option<CustomCpuTemplateOrPath>,
    pub logger: Option<LoggerConfig>,
    pub machine_config: Option<MachineConfig>,
    pub metrics: Option<MetricsConfig>,
    pub mmds_config: Option<MmdsConfig>,
    #[serde(default)]
    pub network_interfaces: Vec<NetworkInterfaceConfig>,
    pub vsock: Option<VsockDeviceConfig>,
    pub entropy: Option<EntropyDeviceConfig>,
    #[serde(default, rename = "pmem")]
    pub pmem_devices: Vec<PmemConfig>,
    #[serde(skip)]
    pub serial_config: Option<SerialConfig>,
    pub memory_hotplug: Option<MemoryHotplugConfig>,
}

/// A data structure that encapsulates the device configurations
/// held in the Vmm.
#[derive(Debug, Default)]
pub struct VmResources {
    /// The vCpu and memory configuration for this microVM.
    pub machine_config: MachineConfig,
    /// The boot source spec (contains both config and builder) for this microVM.
    pub boot_source: BootSource,
    /// The block devices.
    pub block: BlockBuilder,
    /// The vsock device.
    pub vsock: VsockBuilder,
    /// The balloon device.
    pub balloon: BalloonBuilder,
    /// The network devices builder.
    pub net_builder: NetBuilder,
    /// The entropy device builder.
    pub entropy: EntropyDeviceBuilder,
    /// The pmem device configs.
    pub pmem: PmemBuilder,
    /// The memory hotplug configuration.
    pub memory_hotplug: Option<MemoryHotplugConfig>,
    /// The optional Mmds data store.
    // This is initialised on demand (if ever used), so that we don't allocate it unless it's
    // actually used.
    pub mmds: Option<Arc<Mutex<Mmds>>>,
    /// Data store limit for the mmds.
    pub mmds_size_limit: usize,
    /// Whether or not to load boot timer device.
    pub boot_timer: bool,
    /// Whether or not to use PCIe transport for VirtIO devices.
    pub pci_enabled: bool,
    /// Where serial console output should be written to
    pub serial_out_path: Option<PathBuf>,
    /// Optional rate limiter config for serial output.
    pub serial_rate_limiter_cfg: Option<TokenBucketConfig>,
}

impl VmResources {
    /// Returns a `TokenBucket` from the serial rate limiter config, if configured.
    pub fn serial_rate_limiter(&self) -> Option<crate::rate_limiter::TokenBucket> {
        self.serial_rate_limiter_cfg.as_ref().and_then(|cfg| {
            crate::rate_limiter::TokenBucket::new(
                cfg.size,
                cfg.one_time_burst.unwrap_or(0),
                cfg.refill_time,
            )
        })
    }

    /// Configures Vmm resources as described by the `config_json` param.
    pub fn from_json(
        config_json: &str,
        instance_info: &InstanceInfo,
        mmds_size_limit: usize,
        metadata_json: Option<&str>,
    ) -> Result<Self, ResourcesError> {
        let vmm_config = serde_json::from_str::<VmmConfig>(config_json)?;

        if let Some(logger_config) = vmm_config.logger {
            crate::logger::LOGGER.update(logger_config)?;
        }

        if let Some(metrics) = vmm_config.metrics {
            init_metrics(metrics)?;
        }

        let mut resources: Self = Self {
            mmds_size_limit,
            ..Default::default()
        };
        if let Some(machine_config) = vmm_config.machine_config {
            let machine_config = MachineConfigUpdate::from(machine_config);
            resources.update_machine_config(&machine_config)?;
        }

        if let Some(either) = vmm_config.cpu_config {
            match either {
                CustomCpuTemplateOrPath::Path(path) => {
                    let cpu_config_json =
                        std::fs::read_to_string(path).map_err(ResourcesError::File)?;
                    let cpu_template = CustomCpuTemplate::try_from(cpu_config_json.as_str())?;
                    resources.set_custom_cpu_template(cpu_template);
                }
                CustomCpuTemplateOrPath::Template(template) => {
                    resources.set_custom_cpu_template(template)
                }
            }
        }

        resources.build_boot_source(vmm_config.boot_source)?;

        for drive_config in vmm_config.drives.into_iter() {
            resources.set_block_device(drive_config)?;
        }

        for net_config in vmm_config.network_interfaces.into_iter() {
            resources.build_net_device(net_config)?;
        }

        if let Some(vsock_config) = vmm_config.vsock {
            resources.set_vsock_device(vsock_config)?;
        }

        if let Some(balloon_config) = vmm_config.balloon {
            resources.set_balloon_device(balloon_config)?;
        }

        // Init the data store from file, if present.
        if let Some(data) = metadata_json {
            resources.locked_mmds_or_default()?.put_data(
                serde_json::from_str(data).expect("MMDS error: metadata provided not valid json"),
            )?;
            info!("Successfully added metadata to mmds from file");
        }

        if let Some(mmds_config) = vmm_config.mmds_config {
            resources.set_mmds_config(mmds_config, &instance_info.id)?;
        }

        if let Some(entropy_device_config) = vmm_config.entropy {
            resources.build_entropy_device(entropy_device_config)?;
        }

        for pmem_config in vmm_config.pmem_devices.into_iter() {
            resources.build_pmem_device(pmem_config)?;
        }

        if let Some(serial_cfg) = vmm_config.serial_config {
            resources.serial_out_path = serial_cfg.serial_out_path;
            resources.serial_rate_limiter_cfg = serial_cfg.rate_limiter;
        }

        if let Some(memory_hotplug_config) = vmm_config.memory_hotplug {
            resources.set_memory_hotplug_config(memory_hotplug_config)?;
        }

        Ok(resources)
    }

    /// If not initialised, create the mmds data store with the default config.
    pub fn mmds_or_default(&mut self) -> Result<&Arc<Mutex<Mmds>>, MmdsConfigError> {
        Ok(self
            .mmds
            .get_or_insert(Arc::new(Mutex::new(Mmds::try_new(self.mmds_size_limit)?))))
    }

    /// If not initialised, create the mmds data store with the default config.
    pub fn locked_mmds_or_default(&mut self) -> Result<MutexGuard<'_, Mmds>, MmdsConfigError> {
        let mmds = self.mmds_or_default()?;
        Ok(mmds.lock().expect("Poisoned lock"))
    }

    /// Add a custom CPU template to the VM resources
    /// to configure vCPUs.
    pub fn set_custom_cpu_template(&mut self, cpu_template: CustomCpuTemplate) {
        self.machine_config.set_custom_cpu_template(cpu_template);
    }

    /// Updates the configuration of the microVM.
    pub fn update_machine_config(
        &mut self,
        update: &MachineConfigUpdate,
    ) -> Result<(), MachineConfigError> {
        let updated = self.machine_config.update(update)?;

        // The VM cannot have a memory size smaller than the target size
        // of the balloon device, if present.
        if self.balloon.get().is_some()
            && updated.mem_size_mib
                < self
                    .balloon
                    .get_config()
                    .map_err(|_| MachineConfigError::InvalidVmState)?
                    .amount_mib as usize
        {
            return Err(MachineConfigError::IncompatibleBalloonSize);
        }

        self.machine_config = updated;

        Ok(())
    }

    // Repopulate the MmdsConfig based on information from the data store
    // and the associated net devices.
    fn mmds_config(&self) -> Option<MmdsConfig> {
        // If the data store is not initialised, we can be sure that the user did not configure
        // mmds.
        let mmds = self.mmds.as_ref()?;

        let mut mmds_config = None;
        let net_devs_with_mmds: Vec<_> = self
            .net_builder
            .iter()
            .filter(|net| net.lock().expect("Poisoned lock").mmds_ns().is_some())
            .collect();

        if !net_devs_with_mmds.is_empty() {
            let mmds_guard = mmds.lock().expect("Poisoned lock");
            let mut inner_mmds_config = MmdsConfig {
                version: mmds_guard.version(),
                network_interfaces: vec![],
                ipv4_address: None,
                imds_compat: mmds_guard.imds_compat(),
            };

            for net_dev in net_devs_with_mmds {
                let net = net_dev.lock().unwrap();
                inner_mmds_config
                    .network_interfaces
                    .push(net.id().to_string());
                // Only need to get one ip address, as they will all be equal.
                if inner_mmds_config.ipv4_address.is_none() {
                    // Safe to unwrap the mmds_ns as the filter() explicitly checks for
                    // its existence.
                    inner_mmds_config.ipv4_address = Some(net.mmds_ns().unwrap().ipv4_addr());
                }
            }

            mmds_config = Some(inner_mmds_config);
        }

        mmds_config
    }

    /// Sets a balloon device to be attached when the VM starts.
    pub fn set_balloon_device(
        &mut self,
        config: BalloonDeviceConfig,
    ) -> Result<(), BalloonConfigError> {
        // The balloon cannot have a target size greater than the size of
        // the guest memory.
        if config.amount_mib as usize > self.machine_config.mem_size_mib {
            return Err(BalloonConfigError::TooManyPagesRequested);
        }

        self.balloon.set(config)
    }

    /// Obtains the boot source hooks (kernel fd, command line creation and validation).
    pub fn build_boot_source(
        &mut self,
        boot_source_cfg: BootSourceConfig,
    ) -> Result<(), BootSourceConfigError> {
        // 这里即保存 config，也保存 builder，其实两个保存的东西是一样的
        // 只是 config 是静态的数据，比如 kernel 的路径、启动命令的字符串
        // 但是 builder 是保存了 kernel 文件对象、cmdline 对象
        self.boot_source = BootSource {
            builder: Some(BootConfig::new(&boot_source_cfg)?),
            config: boot_source_cfg,
        };

        Ok(())
    }

    /// Inserts a block to be attached when the VM starts.
    // Only call this function as part of user configuration.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    pub fn set_block_device(
        &mut self,
        block_device_config: BlockDeviceConfig,
    ) -> Result<(), DriveError> {
        let has_pmem_root = self.pmem.has_root_device();
        self.block.insert(block_device_config, has_pmem_root)
    }

    /// Builds a network device to be attached when the VM starts.
    pub fn build_net_device(
        &mut self,
        body: NetworkInterfaceConfig,
    ) -> Result<(), NetworkInterfaceError> {
        let _ = self.net_builder.build(body)?;
        Ok(())
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn set_vsock_device(&mut self, config: VsockDeviceConfig) -> Result<(), VsockConfigError> {
        self.vsock.insert(config)
    }

    /// Builds an entropy device to be attached when the VM starts.
    pub fn build_entropy_device(
        &mut self,
        body: EntropyDeviceConfig,
    ) -> Result<(), EntropyDeviceError> {
        self.entropy.insert(body)
    }

    /// Builds a pmem device to be attached when the VM starts.
    pub fn build_pmem_device(&mut self, body: PmemConfig) -> Result<(), PmemConfigError> {
        let has_block_root = self.block.has_root_device();
        self.pmem.build(body, has_block_root)
    }

    /// Sets the memory hotplug configuration.
    pub fn set_memory_hotplug_config(
        &mut self,
        config: MemoryHotplugConfig,
    ) -> Result<(), MemoryHotplugConfigError> {
        config.validate()?;
        self.memory_hotplug = Some(config);
        Ok(())
    }

    /// Setter for mmds config.
    pub fn set_mmds_config(
        &mut self,
        config: MmdsConfig,
        instance_id: &str,
    ) -> Result<(), MmdsConfigError> {
        self.set_mmds_network_stack_config(&config)?;
        self.set_mmds_basic_config(config.version, config.imds_compat, instance_id)?;

        Ok(())
    }

    /// Updates MMDS-related config other than MMDS network stack.
    pub fn set_mmds_basic_config(
        &mut self,
        version: MmdsVersion,
        imds_compat: bool,
        instance_id: &str,
    ) -> Result<(), MmdsConfigError> {
        let mut mmds_guard = self.locked_mmds_or_default()?;
        mmds_guard.set_version(version);
        mmds_guard.set_imds_compat(imds_compat);
        mmds_guard.set_aad(instance_id);

        Ok(())
    }

    // Updates MMDS Network Stack for network interfaces to allow forwarding
    // requests to MMDS (or not).
    fn set_mmds_network_stack_config(
        &mut self,
        config: &MmdsConfig,
    ) -> Result<(), MmdsConfigError> {
        // Check IPv4 address validity.
        let ipv4_addr = match config.ipv4_addr() {
            Some(ipv4_addr) if is_link_local_valid(ipv4_addr) => Ok(ipv4_addr),
            None => Ok(MmdsNetworkStack::default_ipv4_addr()),
            _ => Err(MmdsConfigError::InvalidIpv4Addr),
        }?;

        let network_interfaces = config.network_interfaces();
        // Ensure that at least one network ID is specified.
        if network_interfaces.is_empty() {
            return Err(MmdsConfigError::EmptyNetworkIfaceList);
        }

        // Ensure all interface IDs specified correspond to existing net devices.
        if !network_interfaces.iter().all(|id| {
            self.net_builder
                .iter()
                .any(|device| device.lock().expect("Poisoned lock").id() == id)
        }) {
            return Err(MmdsConfigError::InvalidNetworkInterfaceId);
        }

        // Safe to unwrap because we've just made sure that it's initialised.
        let mmds = self.mmds_or_default()?.clone();

        // Create `MmdsNetworkStack` and configure the IPv4 address for
        // existing built network devices whose names are defined in the
        // network interface ID list.
        for net_device in self.net_builder.iter() {
            let mut net_device_lock = net_device.lock().expect("Poisoned lock");
            if network_interfaces.contains(&net_device_lock.id) {
                net_device_lock.configure_mmds_network_stack(ipv4_addr, mmds.clone());
            } else {
                net_device_lock.disable_mmds_network_stack();
            }
        }

        Ok(())
    }

    /// Allocates the given guest memory regions.
    ///
    /// If vhost-user-blk devices are in use, allocates memfd-backed shared memory, otherwise
    /// prefers anonymous memory for performance reasons.
    fn allocate_memory_regions(
        &self,
        regions: &[(GuestAddress, usize)],
    ) -> Result<Vec<GuestRegionMmap>, MemoryError> {
        // 遍历所有的 block 设备，判断是否有使用 vhost-user-blk 这种设备
        let vhost_user_device_used = self
            .block
            .devices
            .iter()
            .any(|b| b.lock().expect("Poisoned lock").is_vhost_user());


        // 这里介绍下 vhost-user-blk 的工作原理
        //
        // guest -> virtio-blk 请求 -> Firecracker -> Unix socket + 共享内存 -> vhost-user 后端 -> 真正读写操作
        //
        // 通过 memfd 这种共享内存的方式，guest 物理内存、Firecracker 虚拟内存、vhost-user 就使用了同一段内存
        // guest 写入的 virtio-blk 的 IO 数据，在 vhost-user 后端可以直接读取处理


        // Page faults are more expensive for shared memory mapping, including  memfd.
        // For this reason, we only back guest memory with a memfd
        // if a vhost-user-blk device is configured in the VM, otherwise we fall back to
        // an anonymous private memory.
        //
        // The vhost-user-blk branch is not currently covered by integration tests in Rust,
        // because that would require running a backend process. If in the future we converge to
        // a single way of backing guest memory for vhost-user and non-vhost-user cases,
        // that would not be worth the effort.
        // 如果使用了 vhost-user-blk 设备，创建共享内存文件（memfd），如果没有，那就创建匿名内存
        if vhost_user_device_used {
            memory::memfd_backed(
                regions,
                self.machine_config.track_dirty_pages,
                self.machine_config.huge_pages,
            )
        } else {
            memory::anonymous(
                regions.iter().copied(),
                self.machine_config.track_dirty_pages,
                self.machine_config.huge_pages,
            )
        }
    }

    /// Allocates guest memory in a configuration most appropriate for these [`VmResources`].
    pub fn allocate_guest_memory(&self) -> Result<Vec<GuestRegionMmap>, MemoryError> {
        // 这里是处理 guest 中的 region 分布
        // 假如是 4 GiB，那么 regions 是 (0 GiB - 3 GiB) 和 (4 GiB - 5 GiB)
        let regions =
            crate::arch::arch_memory_regions(mib_to_bytes(self.machine_config.mem_size_mib));

        // 这里是在 firecracker 中为 guest 分配内存
        self.allocate_memory_regions(&regions)
    }

    /// Allocates a single guest memory region.
    /// 这里是给热插拔来使用的，这里只有一段 region
    pub fn allocate_memory_region(
        &self,
        start: GuestAddress,
        size: usize,
    ) -> Result<GuestRegionMmap, MemoryError> {
        Ok(self
            .allocate_memory_regions(&[(start, size)])?
            .pop()
            .unwrap())
    }
}

impl From<&VmResources> for VmmConfig {
    fn from(resources: &VmResources) -> Self {
        VmmConfig {
            balloon: resources.balloon.get_config().ok(),
            drives: resources.block.configs(),
            boot_source: resources.boot_source.config.clone(),
            cpu_config: None,
            logger: None,
            machine_config: Some(resources.machine_config.clone()),
            metrics: None,
            mmds_config: resources.mmds_config(),
            network_interfaces: resources.net_builder.configs(),
            vsock: resources.vsock.config(),
            entropy: resources.entropy.config(),
            pmem_devices: resources.pmem.configs.clone(),
            // serial_config is marked serde(skip) so that it doesnt end up in snapshots.
            serial_config: None,
            memory_hotplug: resources.memory_hotplug.clone(),
        }
    }
}
