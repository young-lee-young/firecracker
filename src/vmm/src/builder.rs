// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enables pre-boot setup, instantiation and booting of a Firecracker VMM.

use std::fmt::Debug;
use std::io;
#[cfg(feature = "gdb")]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use event_manager::SubscriberOps;
use linux_loader::cmdline::Cmdline as LoaderKernelCmdline;
use userfaultfd::Uffd;
use utils::time::TimestampUs;
use vm_allocator::AllocPolicy;
use vm_memory::GuestAddress;

#[cfg(target_arch = "aarch64")]
use crate::Vcpu;
use crate::arch::{ConfigurationError, configure_system_for_boot, load_kernel};
#[cfg(target_arch = "aarch64")]
use crate::construct_kvm_mpidrs;
use crate::cpu_config::templates::{GetCpuTemplate, GetCpuTemplateError, GuestConfigError};
#[cfg(target_arch = "x86_64")]
use crate::device_manager;
use crate::device_manager::pci_mngr::PciManagerError;
use crate::device_manager::{
    AttachDeviceError, DeviceManager, DeviceManagerCreateError, DeviceManagerPersistError,
    DeviceRestoreArgs,
};
use crate::devices::virtio::balloon::Balloon;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::mem::{VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB, VirtioMem};
use crate::devices::virtio::net::Net;
use crate::devices::virtio::pmem::device::Pmem;
use crate::devices::virtio::rng::Entropy;
use crate::devices::virtio::vsock::{Vsock, VsockUnixBackend};
#[cfg(feature = "gdb")]
use crate::gdb;
use crate::initrd::{InitrdConfig, InitrdError};
use crate::logger::debug;
#[cfg(target_arch = "aarch64")]
use crate::logger::warn;
use crate::persist::{MicrovmState, MicrovmStateError};
use crate::resources::VmResources;
use crate::seccomp::BpfThreadMap;
use crate::snapshot::Persist;
use crate::utils::mib_to_bytes;
use crate::vmm_config::boot_source::{
    DEFAULT_KERNEL_CMDLINE, append_root_device_cmdline, build_cmdline,
};
use crate::vmm_config::instance_info::{InstanceInfo, VmState};
use crate::vmm_config::machine_config::MachineConfigError;
use crate::vmm_config::memory_hotplug::MemoryHotplugConfig;
use crate::vmm_config::pmem::PmemConfig;
use crate::vstate::kvm::{Kvm, KvmError};
use crate::vstate::memory::GuestRegionMmap;
#[cfg(target_arch = "aarch64")]
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vcpu::VcpuError;
use crate::vstate::vm::{KvmVm, Vm, VmError};
use crate::{EventManager, Vmm, VmmError};

/// Errors associated with starting the instance.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StartMicrovmError {
    /// Unable to attach block device to Vmm: {0}
    AttachBlockDevice(io::Error),
    /// Could not attach device: {0}
    AttachDevice(#[from] AttachDeviceError),
    /// System configuration error: {0}
    ConfigureSystem(#[from] ConfigurationError),
    /// Failed to create device manager: {0}
    CreateDeviceManager(#[from] DeviceManagerCreateError),
    /// Failed to create guest config: {0}
    CreateGuestConfig(#[from] GuestConfigError),
    /// Cannot create network device: {0}
    CreateNetDevice(crate::devices::virtio::net::NetError),
    /// Cannot create pmem device: {0}
    CreatePmemDevice(#[from] crate::devices::virtio::pmem::device::PmemError),
    /// Cannot create RateLimiter: {0}
    CreateRateLimiter(io::Error),
    /// Error creating legacy device: {0}
    #[cfg(target_arch = "x86_64")]
    CreateLegacyDevice(device_manager::legacy::LegacyDeviceError),
    /// Error enabling PCIe support: {0}
    EnablePciDevices(#[from] PciManagerError),
    /// Error enabling pvtime on vcpu: {0}
    #[cfg(target_arch = "aarch64")]
    EnablePVTime(crate::arch::VcpuArchError),
    /// Invalid Memory Configuration: {0}
    GuestMemory(crate::vstate::memory::MemoryError),
    /// Error with initrd initialization: {0}.
    Initrd(#[from] InitrdError),
    /// Internal error while starting microVM: {0}
    Internal(#[from] VmmError),
    /// Failed to get CPU template: {0}
    GetCpuTemplate(#[from] GetCpuTemplateError),
    /// Invalid kernel command line: {0}
    KernelCmdline(String),
    /// Kvm error: {0}
    Kvm(#[from] KvmError),
    /// Cannot load command line string: {0}
    LoadCommandline(linux_loader::loader::Error),
    /// Cannot start microvm without kernel configuration.
    MissingKernelConfig,
    /// Cannot start microvm without guest mem_size config.
    MissingMemSizeConfig,
    /// No seccomp filter for thread category: {0}
    MissingSeccompFilters(String),
    /// The net device configuration is missing the tap device.
    NetDeviceNotConfigured,
    /// Cannot open the block device backing file: {0}
    OpenBlockDevice(io::Error),
    /// Cannot restore microvm state: {0}
    RestoreMicrovmState(MicrovmStateError),
    /// Cannot set vm resources: {0}
    SetVmResources(MachineConfigError),
    /// Cannot create the entropy device: {0}
    CreateEntropyDevice(crate::devices::virtio::rng::EntropyError),
    /// Failed to allocate guest resource: {0}
    AllocateResources(#[from] vm_allocator::Error),
    /// Error starting GDB debug session: {0}
    #[cfg(feature = "gdb")]
    GdbServer(gdb::target::GdbTargetError),
    /// Error cloning Vcpu fds
    #[cfg(feature = "gdb")]
    VcpuFdCloneError(#[from] crate::vstate::vcpu::CopyKvmFdError),
    /// Error with the KvmVm object: {0}
    KvmVm(#[from] VmError),
}

/// It's convenient to automatically convert `linux_loader::cmdline::Error`s
/// to `StartMicrovmError`s.
impl std::convert::From<linux_loader::cmdline::Error> for StartMicrovmError {
    fn from(err: linux_loader::cmdline::Error) -> StartMicrovmError {
        StartMicrovmError::KernelCmdline(err.to_string())
    }
}

/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// The built microVM and all the created vCPUs start off in the paused state.
/// To boot the microVM and run those vCPUs, `Vmm::resume_vm()` needs to be
/// called.
pub fn build_microvm_for_boot(
    instance_info: &InstanceInfo,
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
) -> Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    // Timestamp for measuring microVM boot duration.
    let request_ts = TimestampUs::default();


    // 借用 boot 的 builder，也就是 BootConfig
    let boot_config = vm_resources
        .boot_source
        .builder
        .as_ref()
        .ok_or(StartMicrovmError::MissingKernelConfig)?;


    // 从 firecracker 的虚拟内存中给 guest 分配内存
    let guest_memory = vm_resources
        .allocate_guest_memory()
        .map_err(StartMicrovmError::GuestMemory)?;


    // Clone the command-line so that a failed boot doesn't pollute the original.
    // If the user didn't provide boot_args, use the KVM-specific default.
    // 如果用户没有提供 cmdline，那么使用默认的 cmdline
    #[allow(unused_mut)]
    let mut boot_cmdline = match boot_config.cmdline.clone() {
        Some(cmdline) => cmdline,
        None => build_cmdline(DEFAULT_KERNEL_CMDLINE)?,
    };


    let cpu_template = vm_resources
        .machine_config
        .cpu_template
        .get_cpu_template()?;


    // 创建 KVM 实例
    let kvm = Kvm::new(cpu_template.kvm_capabilities.clone())?;


    // Set up KVM VM and register memory regions.
    // Build custom CPU config if a custom template is provided.
    // 创建 VM 实例
    let mut vm = KvmVm::new(kvm)?;


    // 创建 vCPU
    let mut vcpus = vm.create_vcpus(vm_resources.machine_config.vcpu_count)?;


    // 把上面 mmap 出来的内存，注册到 kvm 中
    vm.register_dram_memory_regions(guest_memory)?;


    // Allocate memory as soon as possible to make hotpluggable memory available to all consumers,
    // before they clone the GuestMemoryMmap object
    // 判断用户是否使用了内存热插拔
    // 这里整体上和用户申请的内存的逻辑是一样的
    let virtio_mem_addr = if let Some(memory_hotplug) = &vm_resources.memory_hotplug {
        // 这里是从 guest 的物理地址中，申请了一段内存空间
        // addr 是这段地址的起始地址
        let addr = allocate_virtio_mem_address(&vm, memory_hotplug.total_size_mib)?;


        // 这里是对这段内存在 firecracker 的虚拟机地址空间进行 mmap
        let hotplug_memory_region = vm_resources
            .allocate_memory_region(addr, mib_to_bytes(memory_hotplug.total_size_mib))
            .map_err(StartMicrovmError::GuestMemory)?;

        // 把这段内存注册到 kvm 里面
        vm.register_hotpluggable_memory_region(
            hotplug_memory_region,
            mib_to_bytes(memory_hotplug.slot_size_mib),
        )?;
        Some(addr)
    } else {
        None
    };


    let kvm_vm = Arc::new(vm);
    let vm = Vm::Kvm(kvm_vm.clone());


    // 拿到内存数据结构
    let guest_memory = kvm_vm.guest_memory();
    // TODO Lee P2 这两个读取还需要详细看
    // 把内核读到内存
    let entry_point = load_kernel(&boot_config.kernel_file, guest_memory)?;
    // 把 initrd 读到内存
    let initrd = InitrdConfig::from_config(boot_config, guest_memory)?;


    // 下面都是 IO 虚拟化相关的逻辑了
    // 在这里学习下 IO 虚拟化相关的知识


    // MMIO（Memory-Mapped I/O）工作原理
    // 我们以 block 举例
    // 1. firecracker 在 MMIO32 这段地址 (3 GiB - 4 GiB) 分配一段空间作为 blk 的 MMIO 寄存器区域，并且注册到 firecracker 的 mmio_bus
    // 2. 通过启动时的内核参数告诉 virtio-blk 这段地址
    // 3. guest 在写入时，把数据写入 guest RAM 区域，把 blk 需要的寄存器信息写入 MMIO 区域（起始没有真正写入，只是触发了一次 CPU 的异常）
    // 4. CPU 发现 MMIO 这段区域不是 RAM 区域，触发 VM Exit，陷入到 KVM
    // 5. KVM 给到 firecracker 处理，这里有 2 种处理方法
    //    1. KVM 通过 ioeventfd（KVM + Linux eventfd） 把事件通知 firecracker，firecracker EventManager 来处理
    //    2. 直接把 firecracker vCPU 调用的 kvm_run 方法返回，firecracker 收到 VcpuExit::MmioWrite，交给 mmio_bus 处理
    // 6. firecracker 读取 virtqueue，开始处理读写请求
    // TODO Lee P1 学习下 Linux eventfd 机制

    // Port IO 工作原理
    // 1. 在创建 vCPU 时，会配置 VMCS（virtual machine control structure，这是 intel 的配置，AMD 中叫 VMCB，virtual machine control block）
    // 2. guest 执行 IN/OUT 指令，比如 outb %al, $0x3f8（把 al 机粗气的数据写入 0x3f8 Port，串口）
    // 3. CPU 在执行时，会检查这个 Port 是否被拦截
    // 4. 陷入到 KVM 里处理
    // 5. KVM 给到 firecracker 处理，kvm run 会返回 KVM_EXIT_IO，再交给 pio_bus 处理
    // TODO Lee P1 看看内核中 KVM 创建 vCPU 时 VMCS/VMCB 是怎么处理的


    // TODO Lee P0 需要学习 virtio 相关的东西


    let mut device_manager = DeviceManager::new(
        event_manager,
        kvm_vm.vcpus_exit_evt(),
        &kvm_vm,
        vm_resources.serial_out_path.as_ref(),
        vm_resources.serial_rate_limiter(),
    )?;


    // pci_enabled 是通过 api 参数传进来的
    // 这个参数会决定 attach_virtio_device 中是加入一个 PCI 设备还是一个 MMIO 好的设备
    if vm_resources.pci_enabled {
        device_manager.enable_pci(&kvm_vm)?;
    } else {
        boot_cmdline.insert("pci", "off")?;
    }


    // The boot timer device needs to be the first device attached in order
    // to maintain the same MMIO address referenced in the documentation
    // and tests.
    if vm_resources.boot_timer {
        device_manager.attach_boot_timer_device(&kvm_vm, request_ts)?;
    }


    // 内存气球
    if let Some(balloon) = vm_resources.balloon.get() {
        attach_balloon_device(
            &mut device_manager,
            &vm,
            &mut boot_cmdline,
            balloon,
            event_manager,
        )?;
    }


    // 块设备
    attach_block_devices(
        &mut device_manager,
        &vm,
        &mut boot_cmdline,
        vm_resources.block.devices.iter(),
        event_manager,
    )?;


    attach_net_devices(
        &mut device_manager,
        &vm,
        &mut boot_cmdline,
        vm_resources.net_builder.iter(),
        event_manager,
    )?;


    // 内存持久化为文件
    attach_pmem_devices(
        &mut device_manager,
        &vm,
        &mut boot_cmdline,
        &vm_resources.pmem.configs,
        event_manager,
    )?;


    // 用于 host 和 guest 之间通信
    if let Some(unix_vsock) = vm_resources.vsock.get() {
        attach_unixsock_vsock_device(
            &mut device_manager,
            &vm,
            &mut boot_cmdline,
            unix_vsock,
            event_manager,
        )?;
    }


    // 就是 virtio 下面的 rng 目录，提供随机数种子
    // rng：Random Number Generator
    if let Some(entropy) = vm_resources.entropy.get() {
        attach_entropy_device(
            &mut device_manager,
            &vm,
            &mut boot_cmdline,
            entropy,
            event_manager,
        )?;
    }


    // Attach virtio-mem device if configured
    // 用于内存的热插拔
    if let Some(memory_hotplug) = &vm_resources.memory_hotplug {
        attach_virtio_mem_device(
            &mut device_manager,
            &vm,
            &mut boot_cmdline,
            memory_hotplug,
            event_manager,
            virtio_mem_addr.expect("address should be allocated"),
        )?;
    }

    #[cfg(target_arch = "aarch64")]
    device_manager.attach_legacy_devices_aarch64(
        &kvm_vm,
        event_manager,
        &mut boot_cmdline,
        vm_resources.serial_out_path.as_ref(),
        vm_resources.serial_rate_limiter(),
    )?;

    device_manager.attach_vmgenid_device(&kvm_vm)?;
    device_manager.attach_vmclock_device(&kvm_vm)?;

    #[cfg(target_arch = "aarch64")]
    if vcpus[0].kvm_vcpu.supports_pvtime() {
        setup_pvtime(&mut kvm_vm.resource_allocator(), &mut vcpus)?;
    } else {
        warn!("Vcpus do not support pvtime, steal time will not be reported to guest");
    }

    // 配置系统启动所需的东西
    configure_system_for_boot(
        kvm_vm.kvm(),
        &kvm_vm,
        &mut device_manager,
        vcpus.as_mut(),
        &vm_resources.machine_config,
        &cpu_template,
        entry_point,
        &initrd,
        boot_cmdline,
    )?;

    let vmm = Vmm {
        instance_info: instance_info.clone(),
        machine_config: vm_resources.machine_config.clone(),
        boot_source_config: vm_resources.boot_source.config.clone(),
        shutdown_exit_code: None,
        vm,
        device_manager,
    };
    let vmm = Arc::new(Mutex::new(vmm));

    #[cfg(feature = "gdb")]
    let (gdb_tx, gdb_rx) = mpsc::channel();

    #[cfg(feature = "gdb")]
    vcpus
        .iter_mut()
        .for_each(|vcpu| vcpu.attach_debug_info(gdb_tx.clone()));

    // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    kvm_vm
        .start_vcpus(
            vcpus,
            seccomp_filters
                .get("vcpu")
                .ok_or_else(|| StartMicrovmError::MissingSeccompFilters("vcpu".to_string()))?
                .clone(),
        )
        .map_err(VmmError::VcpuStart)?;
    vmm.lock().unwrap().instance_info.state = VmState::Paused;

    #[cfg(feature = "gdb")]
    if let Some(gdb_socket_path) = &vm_resources.machine_config.gdb_socket_path {
        gdb::gdb_thread(vmm.clone(), gdb_rx, entry_point.entry_addr, gdb_socket_path)
            .map_err(StartMicrovmError::GdbServer)?;
    } else {
        debug!("No GDB socket provided not starting gdb server.");
    }

    event_manager.add_subscriber(vmm.clone());

    Ok(vmm)
}

/// Builds and boots a microVM based on the current Firecracker VmResources configuration.
///
/// This is the default build recipe, one could build other microVM flavors by using the
/// independent functions in this module instead of calling this recipe.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
pub fn build_and_boot_microvm(
    instance_info: &InstanceInfo,
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
) -> Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    debug!("event_start: build microvm for boot");
    let vmm = build_microvm_for_boot(instance_info, vm_resources, event_manager, seccomp_filters)?;
    debug!("event_end: build microvm for boot");
    // The vcpus start off in the `Paused` state, let them run.
    debug!("event_start: boot microvm");
    vmm.lock().unwrap().resume_vm()?;
    debug!("event_end: boot microvm");
    Ok(vmm)
}

/// Error type for [`build_microvm_from_snapshot`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BuildMicrovmFromSnapshotError {
    /// Failed to create microVM and vCPUs: {0}
    CreateMicrovmAndVcpus(#[from] StartMicrovmError),
    /// Could not access KVM: {0}
    KvmAccess(#[from] vmm_sys_util::errno::Error),
    /// Error configuring the TSC, frequency not present in the given snapshot.
    TscFrequencyNotPresent,
    #[cfg(target_arch = "x86_64")]
    /// Could not get TSC to check if TSC scaling was required with the snapshot: {0}
    GetTsc(#[from] crate::arch::GetTscError),
    #[cfg(target_arch = "x86_64")]
    /// Could not set TSC scaling within the snapshot: {0}
    SetTsc(#[from] crate::arch::SetTscError),
    /// Failed to restore microVM state: {0}
    RestoreState(#[from] crate::vstate::vm::KvmVmError),
    /// Failed to update microVM configuration: {0}
    VmUpdateConfig(#[from] MachineConfigError),
    /// Failed to restore MMIO device: {0}
    RestoreMmioDevice(#[from] MicrovmStateError),
    /// Failed to start vCPUs as no vCPU seccomp filter found.
    MissingVcpuSeccompFilters,
    /// Failed to start vCPUs: {0}
    StartVcpus(#[from] crate::StartVcpusError),
    /// Failed to restore vCPUs: {0}
    RestoreVcpus(#[from] VcpuError),
    /// Failed to restore devices: {0}
    RestoreDevices(#[from] DeviceManagerPersistError),
    /// clock_realtime is not supported on aarch64.
    UnsupportedClockRealtime,
}

/// Builds and starts a microVM based on the provided MicrovmState.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
#[allow(clippy::too_many_arguments)]
pub fn build_microvm_from_snapshot(
    instance_info: &InstanceInfo,
    event_manager: &mut EventManager,
    microvm_state: MicrovmState,
    guest_memory: Vec<GuestRegionMmap>,
    uffd: Option<Uffd>,
    seccomp_filters: &BpfThreadMap,
    vm_resources: &mut VmResources,
    clock_realtime: bool,
) -> Result<Arc<Mutex<Vmm>>, BuildMicrovmFromSnapshotError> {
    // Build Vmm.
    debug!("event_start: build microvm from snapshot");

    let kvm = Kvm::new(microvm_state.kvm_state.kvm_cap_modifiers.clone())
        .map_err(StartMicrovmError::Kvm)?;
    // Set up KVM VM and register memory regions.
    // Build custom CPU config if a custom template is provided.
    let mut vm = KvmVm::new(kvm).map_err(StartMicrovmError::KvmVm)?;

    let mut vcpus = vm
        .create_vcpus(vm_resources.machine_config.vcpu_count)
        .map_err(StartMicrovmError::KvmVm)?;

    vm.restore_memory_regions(guest_memory, &microvm_state.vm_state.memory)
        .map_err(StartMicrovmError::KvmVm)?;

    #[cfg(target_arch = "x86_64")]
    {
        // Scale TSC to match, extract the TSC freq from the state if specified
        if let Some(state_tsc) = microvm_state.vcpu_states[0].tsc_khz {
            // Scale the TSC frequency for all VCPUs. If a TSC frequency is not specified in the
            // snapshot, by default it uses the host frequency.
            if vcpus[0].kvm_vcpu.is_tsc_scaling_required(state_tsc)? {
                for vcpu in &vcpus {
                    vcpu.kvm_vcpu.set_tsc_khz(state_tsc)?;
                }
            }
        }
    }

    // Restore vcpus kvm state.
    for (vcpu, state) in vcpus.iter_mut().zip(microvm_state.vcpu_states.iter()) {
        vcpu.kvm_vcpu
            .restore_state(state)
            .map_err(VcpuError::VcpuResponse)
            .map_err(BuildMicrovmFromSnapshotError::RestoreVcpus)?;
    }

    #[cfg(target_arch = "aarch64")]
    {
        if clock_realtime {
            return Err(BuildMicrovmFromSnapshotError::UnsupportedClockRealtime);
        }
        let mpidrs = construct_kvm_mpidrs(&microvm_state.vcpu_states);
        // Restore kvm vm state.
        vm.restore_state(&mpidrs, &microvm_state.vm_state)?;
    }

    // Restore kvm vm state.
    #[cfg(target_arch = "x86_64")]
    vm.restore_state(&microvm_state.vm_state, clock_realtime)?;

    // Restore the boot source config paths.
    vm_resources.boot_source.config = microvm_state.vm_info.boot_source;

    vm.set_uffd(uffd);

    let kvm_vm = Arc::new(vm);
    let vm = Vm::Kvm(kvm_vm.clone());

    // Restore devices states.
    // Restoring VMGenID injects an interrupt in the guest to notify it about the new generation
    // ID. As a result, we need to restore DeviceManager after restoring the KVM state, otherwise
    // the injected interrupt will be overwritten.
    let device_ctor_args = DeviceRestoreArgs {
        mem: kvm_vm.guest_memory(),
        vm: &kvm_vm,
        event_manager,
        vm_resources,
        instance_id: &instance_info.id,
        vcpus_exit_evt: kvm_vm.vcpus_exit_evt(),
    };
    #[allow(unused_mut)]
    let mut device_manager =
        DeviceManager::restore(device_ctor_args, &microvm_state.device_states)?;

    let vmm = Vmm {
        instance_info: instance_info.clone(),
        machine_config: vm_resources.machine_config.clone(),
        boot_source_config: vm_resources.boot_source.config.clone(),
        shutdown_exit_code: None,
        vm,
        device_manager,
    };

    // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    kvm_vm.start_vcpus(
        vcpus,
        seccomp_filters
            .get("vcpu")
            .ok_or(BuildMicrovmFromSnapshotError::MissingVcpuSeccompFilters)?
            .clone(),
    )?;

    let vmm = Arc::new(Mutex::new(vmm));
    vmm.lock().unwrap().instance_info.state = VmState::Paused;
    event_manager.add_subscriber(vmm.clone());

    debug!("event_end: build microvm from snapshot");

    Ok(vmm)
}

/// 64 bytes due to alignment requirement in 3.1 of https://www.kernel.org/doc/html/v5.8/virt/kvm/devices/vcpu.html#attribute-kvm-arm-vcpu-pvtime-ipa
#[cfg(target_arch = "aarch64")]
const STEALTIME_STRUCT_MEM_SIZE: u64 = 64;

/// Helper method to allocate steal time region
#[cfg(target_arch = "aarch64")]
fn allocate_pvtime_region(
    resource_allocator: &mut ResourceAllocator,
    vcpu_count: usize,
    policy: vm_allocator::AllocPolicy,
) -> Result<GuestAddress, StartMicrovmError> {
    let size = STEALTIME_STRUCT_MEM_SIZE * vcpu_count as u64;
    let addr = resource_allocator
        .system_memory
        .allocate(size, STEALTIME_STRUCT_MEM_SIZE, policy)
        .map_err(StartMicrovmError::AllocateResources)?
        .start();
    Ok(GuestAddress(addr))
}

/// Sets up pvtime for all vcpus
#[cfg(target_arch = "aarch64")]
fn setup_pvtime(
    resource_allocator: &mut ResourceAllocator,
    vcpus: &mut [Vcpu],
) -> Result<(), StartMicrovmError> {
    // Alloc sys mem for steal time region
    let pvtime_mem: GuestAddress = allocate_pvtime_region(
        resource_allocator,
        vcpus.len(),
        vm_allocator::AllocPolicy::LastMatch,
    )?;

    // Register all vcpus with pvtime device
    for (i, vcpu) in vcpus.iter_mut().enumerate() {
        vcpu.kvm_vcpu
            .enable_pvtime(GuestAddress(
                pvtime_mem.0 + i as u64 * STEALTIME_STRUCT_MEM_SIZE,
            ))
            .map_err(StartMicrovmError::EnablePVTime)?;
    }

    Ok(())
}

fn attach_entropy_device(
    device_manager: &mut DeviceManager,
    vm: &Vm,
    cmdline: &mut LoaderKernelCmdline,
    entropy_device: &Arc<Mutex<Entropy>>,
    event_manager: &mut EventManager,
) -> Result<(), AttachDeviceError> {
    let id = entropy_device
        .lock()
        .expect("Poisoned lock")
        .id()
        .to_string();

    device_manager.attach_virtio_device(
        vm,
        id,
        entropy_device.clone(),
        cmdline,
        event_manager,
        false,
    )
}

fn allocate_virtio_mem_address(
    vm: &KvmVm,
    total_size_mib: usize,
) -> Result<GuestAddress, StartMicrovmError> {
    let addr = vm
        .resource_allocator()
        // 从 512 GiB 后开始找合适的内存
        .past_mmio64_memory
        .allocate(
            mib_to_bytes(total_size_mib) as u64,
            // 起始地址必须是 128 MiB 的整数倍
            mib_to_bytes(VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB) as u64,
            AllocPolicy::FirstMatch,
        )?
        .start();
    Ok(GuestAddress(addr))
}

fn attach_virtio_mem_device(
    device_manager: &mut DeviceManager,
    vm: &Vm,
    cmdline: &mut LoaderKernelCmdline,
    config: &MemoryHotplugConfig,
    event_manager: &mut EventManager,
    addr: GuestAddress,
) -> Result<(), StartMicrovmError> {
    let kvm_vm = vm
        .as_kvm()
        .cloned()
        .ok_or(AttachDeviceError::NotSupported)?;
    let virtio_mem = Arc::new(Mutex::new(
        VirtioMem::new(
            kvm_vm,
            addr,
            config.total_size_mib,
            config.block_size_mib,
            config.slot_size_mib,
        )
        .map_err(|e| StartMicrovmError::Internal(VmmError::VirtioMem(e)))?,
    ));

    let id = virtio_mem.lock().expect("Poisoned lock").id().to_string();
    device_manager.attach_virtio_device(
        vm,
        id,
        virtio_mem.clone(),
        cmdline,
        event_manager,
        false,
    )?;
    Ok(())
}

fn attach_block_devices<'a, I: Iterator<Item = &'a Arc<Mutex<Block>>> + Debug>(
    device_manager: &mut DeviceManager,
    vm: &Vm,
    cmdline: &mut LoaderKernelCmdline,
    blocks: I,
    event_manager: &mut EventManager,
) -> Result<(), StartMicrovmError> {
    for block in blocks {
        // 这个 id 是用户传进来的
        let (id, is_vhost_user) = {
            let locked = block.lock().expect("Poisoned lock");

            // 如果是 root 设备，给 cmdline 加上一个 root=xxx 的参数，作为启动盘
            if locked.root_device() {
                append_root_device_cmdline(
                    cmdline,
                    locked.partuuid().as_deref(),
                    locked.read_only(),
                )?;
            }
            (locked.id().to_string(), locked.is_vhost_user())
        };

        // The device mutex mustn't be locked here otherwise it will deadlock.
        device_manager.attach_virtio_device(
            vm,
            id,
            block.clone(),
            cmdline,
            event_manager,
            is_vhost_user,
        )?;
    }
    Ok(())
}

fn attach_net_devices<'a, I: Iterator<Item = &'a Arc<Mutex<Net>>> + Debug>(
    device_manager: &mut DeviceManager,
    vm: &Vm,
    cmdline: &mut LoaderKernelCmdline,
    net_devices: I,
    event_manager: &mut EventManager,
) -> Result<(), StartMicrovmError> {
    for net_device in net_devices {
        let id = net_device.lock().expect("Poisoned lock").id().to_string();
        // The device mutex mustn't be locked here otherwise it will deadlock.
        device_manager.attach_virtio_device(
            vm,
            id,
            net_device.clone(),
            cmdline,
            event_manager,
            false,
        )?;
    }
    Ok(())
}

fn attach_pmem_devices(
    device_manager: &mut DeviceManager,
    vm: &Vm,
    cmdline: &mut LoaderKernelCmdline,
    configs: &[PmemConfig],
    event_manager: &mut EventManager,
) -> Result<(), StartMicrovmError> {
    let kvm_vm = vm.as_kvm().ok_or(AttachDeviceError::NotSupported)?;
    for (i, config) in configs.iter().enumerate() {
        if config.root_device {
            cmdline.insert_str(format!("root=/dev/pmem{i}"))?;
            match config.read_only {
                true => cmdline.insert_str("ro")?,
                false => cmdline.insert_str("rw")?,
            }
        }
        let id = config.id.clone();
        let pmem = Pmem::new(kvm_vm.clone(), config.clone())?;
        let device = Arc::new(Mutex::new(pmem));

        device_manager.attach_virtio_device(vm, id, device, cmdline, event_manager, false)?;
    }
    Ok(())
}

fn attach_unixsock_vsock_device(
    device_manager: &mut DeviceManager,
    vm: &Vm,
    cmdline: &mut LoaderKernelCmdline,
    unix_vsock: &Arc<Mutex<Vsock<VsockUnixBackend>>>,
    event_manager: &mut EventManager,
) -> Result<(), AttachDeviceError> {
    let id = String::from(unix_vsock.lock().expect("Poisoned lock").id());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    device_manager.attach_virtio_device(vm, id, unix_vsock.clone(), cmdline, event_manager, false)
}

fn attach_balloon_device(
    device_manager: &mut DeviceManager,
    vm: &Vm,
    cmdline: &mut LoaderKernelCmdline,
    balloon: &Arc<Mutex<Balloon>>,
    event_manager: &mut EventManager,
) -> Result<(), AttachDeviceError> {
    let _kvm_vm = vm.as_kvm().ok_or(AttachDeviceError::NotSupported)?;
    let id = String::from(balloon.lock().expect("Poisoned lock").id());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    device_manager.attach_virtio_device(vm, id, balloon.clone(), cmdline, event_manager, false)
}
