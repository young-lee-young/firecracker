// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_IRQCHIP_IOAPIC;
use kvm_bindings::{
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_MSI_VALID_DEVID, KvmIrqRouting,
    kvm_irq_routing_entry, kvm_userspace_memory_region,
};
use kvm_ioctls::VmFd;
use serde::{Deserialize, Serialize};
use userfaultfd::Uffd;
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;

use crate::arch::{GSI_MSI_END, host_page_size};
pub use crate::arch::{KvmVm, KvmVmError, VmState};
use crate::logger::{debug, info};
use crate::persist::CreateSnapshotError;
use crate::vmm_config::snapshot::SnapshotType;
use crate::vstate::bus::Bus;
use crate::vstate::interrupts::{InterruptError, MsixVector, MsixVectorConfig, MsixVectorGroup};
use crate::vstate::kvm::Kvm;
use crate::vstate::memory::{
    GuestMemory, GuestMemoryExtension, GuestMemoryMmap, GuestMemoryRegion, GuestMemoryState,
    GuestRegionMmap, GuestRegionMmapExt, MemoryError,
};
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vcpu::{StartThreadedError, VcpuError, VcpuHandle};
use crate::{DirtyBitmap, Vcpu, mem_size_mib};

/// Error type for [`KvmVm::start_vcpus`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StartVcpusError {
    /// Failed to set terminal mode: {0}
    SetTerminalMode(#[from] vmm_sys_util::errno::Error),
    /// Vcpu handle error: {0}
    VcpuHandle(#[from] StartThreadedError),
}

#[derive(Debug, Serialize, Deserialize)]
/// A struct representing an interrupt line used by some device of the microVM
pub struct RoutingEntry {
    entry: kvm_irq_routing_entry,
    masked: bool,
}

/// Architecture independent parts of a VM.
#[derive(Debug)]
pub struct VmCommon {
    /// The KVM file descriptor used to access this KvmVm.
    pub fd: VmFd,
    max_memslots: u32,
    /// The guest memory of this KvmVm.
    pub guest_memory: GuestMemoryMmap,
    next_kvm_slot: AtomicU32,
    /// Interrupts used by KvmVm's devices
    pub interrupts: Mutex<HashMap<u32, RoutingEntry>>,
    /// Allocator for VM resources
    pub resource_allocator: Mutex<ResourceAllocator>,
    /// MMIO bus
    pub mmio_bus: Arc<Bus>,
    /// The global KVM state (fd + capabilities).
    pub kvm: Kvm,
    /// Userfaultfd kept open for snapshot restore.
    pub uffd: Option<Uffd>,
    /// Handles to vCPU threads.
    pub vcpus_handles: Mutex<Vec<VcpuHandle>>,
    /// Event fd written to by vCPUs on exit.
    pub vcpus_exit_evt: EventFd,
}

/// Errors associated with the wrappers over KVM ioctls.
/// Needs `rustfmt::skip` to make multiline comments work
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmError {
    /// Cannot set the memory regions: {0}
    SetUserMemoryRegion(kvm_ioctls::Error),
    /// Failed to create VM: {0}
    CreateVm(kvm_ioctls::Error),
    /// Failed to get KVM's dirty log: {0}
    GetDirtyLog(kvm_ioctls::Error),
    /// {0}
    Arch(#[from] KvmVmError),
    /// Error during eventfd operations: {0}
    EventFd(std::io::Error),
    /// Failed to create vcpu: {0}
    CreateVcpu(VcpuError),
    /// The number of configured slots is bigger than the maximum reported by KVM: {0}
    NotEnoughMemorySlots(u32),
    /// Failed to add a memory region: {0}
    InsertRegion(#[from] vm_memory::GuestRegionCollectionError),
    /// Error calling mincore: {0}
    Mincore(vmm_sys_util::errno::Error),
    /// ResourceAllocator error: {0}
    ResourceAllocator(#[from] vm_allocator::Error),
    /// MemoryError error: {0}
    MemoryError(#[from] MemoryError),
}

/// VM abstraction: either a KVM-based VM or (in the future) a Nitro Enclave.
#[derive(Debug)]
pub enum Vm {
    /// KVM-backed virtual machine.
    Kvm(Arc<KvmVm>),
}

impl Vm {
    /// Returns the name of the VM type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Vm::Kvm(_) => "Kvm",
        }
    }

    /// Returns a reference to the inner KVM VM, or `None` if this is not a KVM VM.
    pub fn as_kvm(&self) -> Option<&Arc<KvmVm>> {
        match self {
            Vm::Kvm(v) => Some(v),
        }
    }
}

/// Contains KvmVm functions that are usable across CPU architectures
impl KvmVm {
    /// Create a KVM VM
    pub fn create_common(kvm: Kvm) -> Result<VmCommon, VmError> {
        // 这里解释了为什么要重试，因为在系统负载高的情况下，内核会返回 EINTR 失败，防止用户程序一致等待

        // It is known that KVM_CREATE_VM occasionally fails with EINTR on heavily loaded machines
        // with many VMs.
        //
        // The behavior itself that KVM_CREATE_VM can return EINTR is intentional. This is because
        // the KVM_CREATE_VM path includes mm_take_all_locks() that is CPU intensive and all CPU
        // intensive syscalls should check for pending signals and return EINTR immediately to allow
        // userland to remain interactive.
        // https://lists.nongnu.org/archive/html/qemu-devel/2014-01/msg01740.html
        //
        // However, it is empirically confirmed that, even though there is no pending signal,
        // KVM_CREATE_VM returns EINTR.
        // https://lore.kernel.org/qemu-devel/8735e0s1zw.wl-maz@kernel.org/
        //
        // To mitigate it, QEMU does an infinite retry on EINTR that greatly improves reliabiliy:
        // - https://github.com/qemu/qemu/commit/94ccff133820552a859c0fb95e33a539e0b90a75
        // - https://github.com/qemu/qemu/commit/bbde13cd14ad4eec18529ce0bf5876058464e124
        //
        // Similarly, we do retries up to 5 times. Although Firecracker clients are also able to
        // retry, they have to start Firecracker from scratch. Doing retries in Firecracker makes
        // recovery faster and improves reliability.
        const MAX_ATTEMPTS: u32 = 5;
        let mut attempt = 1;
        let fd = loop {
            // 创建 VM，最多重试 5 次
            match kvm.fd.create_vm() {
                Ok(fd) => break fd,
                Err(e) if e.errno() == libc::EINTR && attempt < MAX_ATTEMPTS => {
                    info!("Attempt #{attempt} of KVM_CREATE_VM returned EINTR");
                    // Exponential backoff (1us, 2us, 4us, and 8us => 15us in total)
                    std::thread::sleep(std::time::Duration::from_micros(2u64.pow(attempt - 1)));
                }
                Err(e) => return Err(VmError::CreateVm(e)),
            }

            attempt += 1;
        };

        // 创建非阻塞的 eventfd，用于通知 vcpu 退出
        let vcpus_exit_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::EventFd)?;

        Ok(VmCommon {
            fd,
            // 每个 region 是一个 slot，这里获取 KVM 支持最大多少个 slot
            max_memslots: kvm.max_nr_memslots(),
            // 内存信息，这里初始化了一个空壳
            guest_memory: GuestMemoryMmap::default(),
            // 内存的 slot 编号, 从 0 开始
            next_kvm_slot: AtomicU32::new(0),
            interrupts: Mutex::new(HashMap::with_capacity(GSI_MSI_END as usize + 1)),
            resource_allocator: Mutex::new(ResourceAllocator::new()),
            mmio_bus: Arc::new(Bus::new()),
            kvm,
            uffd: None,
            vcpus_handles: Mutex::new(Vec::new()),
            vcpus_exit_evt,
        })
    }

    /// Creates the specified number of [`Vcpu`]s.
    ///
    /// Each vCPU gets a clone of the `vcpus_exit_evt` EventFd stored on this KvmVm.
    pub fn create_vcpus(&mut self, vcpu_count: u8) -> Result<Vec<Vcpu>, VmError> {
        self.arch_pre_create_vcpus(vcpu_count)?;

        let mut vcpus = Vec::with_capacity(vcpu_count as usize);

        for cpu_idx in 0..vcpu_count {
            // vCPU eventfd，所有的 vCPU 使用的是同一个
            let exit_evt = self
                .vcpus_exit_evt()
                .try_clone()
                .map_err(VmError::EventFd)?;

            // 真正创建 vCPU
            // 这里 cpu_idx 是重点，这会使得 guest 中的 vcpu 和 firecracker 中的 vcpu 结构体对应上
            // 以后哪个 vcpu 执行了操作，会在 firecracker 中对应的 vcpu 中处理
            let vcpu = Vcpu::new(cpu_idx, self, exit_evt).map_err(VmError::CreateVcpu)?;
            vcpus.push(vcpu);
        }

        self.arch_post_create_vcpus(vcpu_count)?;

        Ok(vcpus)
    }

    /// Returns a reference to the [`Kvm`] instance.
    pub fn kvm(&self) -> &Kvm {
        &self.common.kvm
    }

    /// Returns a reference to the vCPU exit [`EventFd`].
    pub fn vcpus_exit_evt(&self) -> &EventFd {
        &self.common.vcpus_exit_evt
    }

    /// Returns a locked reference to the vCPU handles.
    pub fn vcpus_handles(&self) -> MutexGuard<'_, Vec<VcpuHandle>> {
        self.common.vcpus_handles.lock().expect("Poisoned lock")
    }

    /// Sets the userfaultfd (used during snapshot restore).
    pub fn set_uffd(&mut self, uffd: Option<Uffd>) {
        self.common.uffd = uffd;
    }

    /// Starts the microVM vCPUs.
    ///
    /// Sets the terminal to raw/non-blocking mode, then spawns a thread per vCPU
    /// and stores the resulting handles. The barrier is used to synchronize TLS
    /// initialization across all vCPU threads before returning.
    pub fn start_vcpus(
        self: &Arc<Self>,
        mut vcpus: Vec<Vcpu>,
        vcpu_seccomp_filter: Arc<crate::seccomp::BpfProgram>,
    ) -> Result<(), StartVcpusError> {
        let vcpu_count = vcpus.len();
        // vcpu_count + 当前线程
        // 因为下面 start_threaded 方法中涉及到并发，所以需要这个，就类似 Go 中的 sync.WaitGroup 类似
        let barrier = Arc::new(Barrier::new(vcpu_count + 1));


        // 处理标准输出
        let stdin = std::io::stdin().lock();
        // raw mode
        stdin.set_raw_mode().inspect_err(|&err| {
            crate::logger::warn!("Cannot set raw mode for the terminal. {:?}", err);
        })?;
        // 非阻塞模式
        stdin.set_non_block(true).inspect_err(|&err| {
            crate::logger::warn!("Cannot set non block for the terminal. {:?}", err);
        })?;


        // 到这里时 vcpus_handles 还是空的，只是初始化了一下
        let mut handles = self.vcpus_handles();
        // 扩大容量 vcpu_count 这么大
        handles.reserve(vcpu_count);


        // drain 表示从 vcpus 取出元素，并且从 vcpus 中移除
        for mut vcpu in vcpus.drain(..) {


            // 这里所有的 vCPU 都会使用同一个 mmio_bus 和 pio_bus
            // 哪个 vCPU 触发了读写操作，都会由 firecracker 中对应的 vCPU 来处理
            vcpu.set_mmio_bus(self.common.mmio_bus.clone());

            #[cfg(target_arch = "x86_64")]
            vcpu.set_pio_bus(self.pio_bus.clone());


            // start_threaded 返回了一个 vcpu handle，放到 handles 里面
            handles.push(vcpu.start_threaded(
                self,
                vcpu_seccomp_filter.clone(),
                barrier.clone(),
            )?);
        }


        // 好像是释放 vcpus_handles 里面的锁 
        drop(handles);


        // 这里会等待所有的 vcpu_count 个线程执行完
        barrier.wait();


        Ok(())
    }

    /// Sends a pause event to all vCPUs and waits for acknowledgement.
    pub fn pause_vcpus(&self) -> Result<(), crate::VmmError> {
        let mut handles = self.vcpus_handles();


        // 通过 handles 给所有的 vCPU 发送 Pause 事件
        handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(crate::VcpuEvent::Pause))
            .map_err(|_| crate::VmmError::VcpuMessage)?;


        // 接收所有的 vCPU 线程的响应，如果有一个线程的响应不是 Paused，那么整个都失败
        if handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .any(|response| !matches!(response, Ok(crate::VcpuResponse::Paused)))
        {
            return Err(crate::VmmError::VcpuMessage);
        }
        Ok(())
    }

    /// Sends a resume event to all vCPUs and waits for acknowledgement.
    /// 这里也很简单了，就是向 vCPU 线程发送 Resume 事件
    /// 然后在 vCPU 的状态机来处理
    pub fn resume_vcpus(&self) -> Result<(), crate::VmmError> {
        let mut handles = self.vcpus_handles();
        handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(crate::VcpuEvent::Resume))
            .map_err(|_| crate::VmmError::VcpuMessage)?;

        if handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .any(|response| !matches!(response, Ok(crate::VcpuResponse::Resumed)))
        {
            return Err(crate::VmmError::VcpuMessage);
        }
        Ok(())
    }

    /// Saves vCPU states by requesting each vCPU thread to serialize its state.
    pub fn save_vcpu_states(
        &self,
    ) -> Result<Vec<crate::vstate::vcpu::VcpuState>, crate::persist::MicrovmStateError> {
        use crate::persist::MicrovmStateError;


        // 这里会给 vCPU 线程发送 SaveState 事件
        // 这个事件还是在 vCPU 的状态机里面来处理
        let mut handles = self.vcpus_handles();
        for handle in handles.iter_mut() {
            handle
                .send_event(crate::VcpuEvent::SaveState)
                .map_err(MicrovmStateError::SignalVcpu)?;
        }


        // 等待所有的事件返回响应
        let vcpu_responses = handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .collect::<Result<Vec<crate::VcpuResponse>, _>>()
            .map_err(|_| MicrovmStateError::UnexpectedVcpuResponse)?;

        
        // 检查所有的事件处理的是否成功
        // 成功的话会收集 vCPU 的状态
        vcpu_responses
            .into_iter()
            .map(|response| match response {
                crate::VcpuResponse::SavedState(state) => Ok(*state),
                crate::VcpuResponse::Error(err) => Err(MicrovmStateError::SaveVcpuState(err)),
                crate::VcpuResponse::NotAllowed(reason) => {
                    Err(MicrovmStateError::NotAllowed(reason))
                }
                _ => Err(MicrovmStateError::UnexpectedVcpuResponse),
            })
            .collect()
    }

    /// Dumps CPU configuration from all vCPU threads.
    pub fn dump_cpu_config_states(
        &self,
    ) -> Result<Vec<crate::cpu_config::templates::CpuConfiguration>, crate::DumpCpuConfigError>
    {
        use crate::DumpCpuConfigError;

        let mut handles = self.vcpus_handles();
        for handle in handles.iter_mut() {
            handle
                .send_event(crate::VcpuEvent::DumpCpuConfig)
                .map_err(DumpCpuConfigError::SendEvent)?;
        }

        let vcpu_responses = handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .collect::<Result<Vec<crate::VcpuResponse>, _>>()
            .map_err(|_| DumpCpuConfigError::UnexpectedResponse)?;

        vcpu_responses
            .into_iter()
            .map(|response| match response {
                crate::VcpuResponse::DumpedCpuConfig(cpu_config) => Ok(*cpu_config),
                crate::VcpuResponse::Error(err) => Err(DumpCpuConfigError::DumpCpuConfig(err)),
                crate::VcpuResponse::NotAllowed(reason) => {
                    Err(DumpCpuConfigError::NotAllowed(reason))
                }
                _ => Err(DumpCpuConfigError::UnexpectedResponse),
            })
            .collect()
    }

    /// Sends finish events to all vCPU threads and joins them.
    pub fn shutdown_vcpus(&self) {
        let mut handles = self.vcpus_handles();
        for (idx, handle) in handles.iter_mut().enumerate() {
            if let Err(err) = handle.send_event(crate::VcpuEvent::Finish) {
                crate::logger::error!("Failed to send VcpuEvent::Finish to vCPU {}: {}", idx, err);
            }
        }
        // Join the vCPU threads by running VcpuHandle::drop().
        handles.clear();
    }

    /// Reserves the next `slot_cnt` contiguous kvm slot ids and returns the first one
    pub fn next_kvm_slot(&self, slot_cnt: u32) -> Option<u32> {
        let next = self
            .common
            .next_kvm_slot
            .fetch_add(slot_cnt, Ordering::Relaxed);
        if self.common.max_memslots <= next {
            None
        } else {
            Some(next)
        }
    }

    pub(crate) fn set_user_memory_region(
        &self,
        region: kvm_userspace_memory_region,
    ) -> Result<(), VmError> {
        // SAFETY: Safe because the fd is a valid KVM file descriptor.
        unsafe {
            self.fd()
                .set_user_memory_region(region)
                .map_err(VmError::SetUserMemoryRegion)
        }
    }

    fn register_memory_region(&mut self, region: Arc<GuestRegionMmapExt>) -> Result<(), VmError> {
        // 给 vm 结构体的 common.guest_memory 插入一条 region 信息
        let new_guest_memory = self
            .common
            .guest_memory
            .insert_region(Arc::clone(&region))?;

        // 如果启用了热插拔内存则一个 region 可能有多个 slot
        // TODO Lee P1 内存热插拔学习，这个 slots 方法实现还要好好看看
        region
            .slots()
            // plugged 为 false 是不会被注册到 KVM 中的
            .try_for_each(|(ref slot, plugged)| match plugged {
                // 真正调用 KVM 的系统调用把内存注册进去
                // if the slot is plugged, add it to kvm user memory regions
                true => self.set_user_memory_region(slot.into()),

                // 把这段内存给保护起来，不让 Firecracker 使用
                // 主要是保护热插拔的内存
                // if the slot is not plugged, protect accesses to it
                false => slot.protect(true).map_err(VmError::MemoryError),
            })?;

        self.common.guest_memory = new_guest_memory;

        Ok(())
    }

    /// Register a list of new memory regions to this [`KvmVm`].
    pub fn register_dram_memory_regions(
        &mut self,
        regions: Vec<GuestRegionMmap>,
    ) -> Result<(), VmError> {
        for region in regions {
            // 申请一个 KVM memory slot
            let next_slot = self
                .next_kvm_slot(1)
                .ok_or(VmError::NotEnoughMemorySlots(self.common.max_memslots))?;


            // 就是吧 region 給包装下
            // 添加一些 slot 索引、大小、类型 这些信息
            let arcd_region =
                Arc::new(GuestRegionMmapExt::dram_from_mmap_region(region, next_slot));

            self.register_memory_region(arcd_region)?
        }

        Ok(())
    }

    /// Register a new hotpluggable region to this [`KvmVm`].
    pub fn register_hotpluggable_memory_region(
        &mut self,
        region: GuestRegionMmap,
        slot_size: usize,
    ) -> Result<(), VmError> {
        // 断言可以完整切成多个 slot
        // caller should ensure the slot size divides the region length.
        assert!(region.len().is_multiple_of(slot_size as u64));


        // 计算下这段内存可以拆分成多少个 slot，默认每个 slot 128 MiB
        let slot_cnt = (region.len() / (slot_size as u64))
            .try_into()
            .map_err(|_| VmError::NotEnoughMemorySlots(self.common.max_memslots))?;


        // 申请 slot_cnt 个 slot
        let slot_from = self
            .next_kvm_slot(slot_cnt)
            .ok_or(VmError::NotEnoughMemorySlots(self.common.max_memslots))?;


        // 还是把 region 包装一下，和普通的内存是一样的
        let arcd_region = Arc::new(GuestRegionMmapExt::hotpluggable_from_mmap_region(
            region, slot_from, slot_size,
        ));


        // 向 KVM 中注册
        self.register_memory_region(arcd_region)
    }

    /// Register a list of new memory regions to this [`KvmVm`].
    ///
    /// Note: regions and state.regions need to be in the same order.
    pub fn restore_memory_regions(
        &mut self,
        regions: Vec<GuestRegionMmap>,
        state: &GuestMemoryState,
    ) -> Result<(), VmError> {
        for (region, state) in regions.into_iter().zip(state.regions.iter()) {
            let slot_cnt = state
                .plugged
                .len()
                .try_into()
                .map_err(|_| VmError::NotEnoughMemorySlots(self.common.max_memslots))?;

            let next_slot = self
                .next_kvm_slot(slot_cnt)
                .ok_or(VmError::NotEnoughMemorySlots(self.common.max_memslots))?;

            let arcd_region = Arc::new(GuestRegionMmapExt::from_state(region, state, next_slot)?);

            self.register_memory_region(arcd_region)?
        }

        Ok(())
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.common.fd
    }

    /// Gets a reference to this [`KvmVm`]'s [`GuestMemoryMmap`] object
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.common.guest_memory
    }

    /// Gets a mutable reference to this [`KvmVm`]'s [`ResourceAllocator`] object
    pub fn resource_allocator(&self) -> MutexGuard<'_, ResourceAllocator> {
        self.common
            .resource_allocator
            .lock()
            .expect("Poisoned lock")
    }

    /// Resets the KVM dirty bitmap for each of the guest's memory regions.
    pub fn reset_dirty_bitmap(&self) {
        self.guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
            .for_each(|mem_slot| {
                let _ = self.fd().get_dirty_log(mem_slot.slot, mem_slot.slice.len());
            });
    }

    /// Retrieves the KVM dirty bitmap for each of the guest's memory regions.
    pub fn get_dirty_bitmap(&self) -> Result<DirtyBitmap, VmError> {
        self.guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
            .map(|mem_slot| {
                let bitmap = match mem_slot.slice.bitmap() {
                    Some(_) => self
                        .fd()
                        .get_dirty_log(mem_slot.slot, mem_slot.slice.len())
                        .map_err(VmError::GetDirtyLog)?,
                    None => mincore_bitmap(
                        mem_slot.slice.ptr_guard_mut().as_ptr(),
                        mem_slot.slice.len(),
                    )?,
                };
                Ok((mem_slot.slot, bitmap))
            })
            .collect()
    }

    /// Takes a snapshot of the virtual machine running inside the given [`Vmm`] and saves it to
    /// `mem_file_path`.
    ///
    /// If `snapshot_type` is [`SnapshotType::Diff`], and `mem_file_path` exists and is a snapshot
    /// file of matching size, then the diff snapshot will be directly merged into the existing
    /// snapshot. Otherwise, existing files are simply overwritten.
    pub(crate) fn snapshot_memory_to_file(
        &self,
        mem_file_path: &Path,
        snapshot_type: SnapshotType,
    ) -> Result<(), CreateSnapshotError> {
        use self::CreateSnapshotError::*;

        // Need to check this here, as we create the file in the line below
        let file_existed = mem_file_path.exists();

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(mem_file_path)
            .map_err(|err| MemoryBackingFile("open", err))?;

        // Determine what size our total memory area is.
        let mem_size_mib = mem_size_mib(self.guest_memory());
        let expected_size = mem_size_mib * 1024 * 1024;

        if file_existed {
            let file_size = file
                .metadata()
                .map_err(|e| MemoryBackingFile("get_metadata", e))?
                .len();

            // Here we only truncate the file if the size mismatches.
            // - For full snapshots, the entire file's contents will be overwritten anyway. We have
            //   to avoid truncating here to deal with the edge case where it represents the
            //   snapshot file from which this very microVM was loaded (as modifying the memory file
            //   would be reflected in the mmap of the file, meaning a truncate operation would zero
            //   out guest memory, and thus corrupt the VM).
            // - For diff snapshots, we want to merge the diff layer directly into the file.
            if file_size != expected_size {
                file.set_len(0)
                    .map_err(|err| MemoryBackingFile("truncate", err))?;
            }
        }

        // Set the length of the file to the full size of the memory area.
        file.set_len(expected_size)
            .map_err(|e| MemoryBackingFile("set_length", e))?;

        match snapshot_type {
            SnapshotType::Diff => {
                let dirty_bitmap = self.get_dirty_bitmap()?;
                self.guest_memory().dump_dirty(&mut file, &dirty_bitmap)?;
            }
            SnapshotType::Full => {
                self.guest_memory().dump(&mut file)?;
                self.reset_dirty_bitmap();
                self.guest_memory().reset_dirty();
            }
        };

        file.flush()
            .map_err(|err| MemoryBackingFile("flush", err))?;
        file.sync_all()
            .map_err(|err| MemoryBackingFile("sync_all", err))
    }

    /// Register a device IRQ
    pub fn register_irq(&self, fd: &EventFd, gsi: u32) -> Result<(), errno::Error> {
        // 真正向 KVM 给 device 注册一个中断，用于 firecracker 通知 KVM 给 guest 发送中断
        self.common.fd.register_irqfd(fd, gsi)?;

        let mut entry = kvm_irq_routing_entry {
            gsi,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            ..Default::default()
        };
        #[cfg(target_arch = "x86_64")]
        {
            entry.u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC;
        }
        #[cfg(target_arch = "aarch64")]
        {
            entry.u.irqchip.irqchip = 0;
        }
        entry.u.irqchip.pin = gsi;

        // 把中断记录到 vm 的 interrupts 字段中
        // 中断号是 key
        self.common
            .interrupts
            .lock()
            .expect("Poisoned lock")
            .insert(
                gsi,
                RoutingEntry {
                    entry,
                    masked: false,
                },
            );
        Ok(())
    }

    /// Register an MSI device interrupt
    pub fn register_msi(
        &self,
        route: &MsixVector,
        masked: bool,
        config: MsixVectorConfig,
    ) -> Result<(), errno::Error> {
        let mut entry = kvm_irq_routing_entry {
            gsi: route.gsi,
            type_: KVM_IRQ_ROUTING_MSI,
            ..Default::default()
        };
        entry.u.msi.address_lo = config.low_addr;
        entry.u.msi.address_hi = config.high_addr;
        entry.u.msi.data = config.data;

        if self.common.fd.check_extension(kvm_ioctls::Cap::MsiDevid) {
            entry.flags = KVM_MSI_VALID_DEVID;
            entry.u.msi.__bindgen_anon_1.devid = config.devid.into();
        }

        self.common
            .interrupts
            .lock()
            .expect("Poisoned lock")
            .insert(route.gsi, RoutingEntry { entry, masked });

        Ok(())
    }

    /// Create a group of MSI-X interrupts
    pub fn create_msix_group(
        vm: Arc<KvmVm>,
        count: u16,
    ) -> Result<MsixVectorGroup, InterruptError> {
        debug!("Creating new MSI group with {count} vectors");
        let mut vectors = Vec::with_capacity(count as usize);
        for gsi in vm
            .resource_allocator()
            .allocate_gsi_msi(count as u32)?
            .iter()
        {
            vectors.push(MsixVector::new(*gsi, false)?);
        }

        Ok(MsixVectorGroup { vm, vectors })
    }

    /// Set GSI routes to KVM
    pub fn set_gsi_routes(&self) -> Result<(), InterruptError> {
        let entries = self.common.interrupts.lock().expect("Poisoned lock");
        let mut routes = KvmIrqRouting::new(0)?;

        for entry in entries.values() {
            if entry.masked {
                continue;
            }
            routes.push(entry.entry)?;
        }

        self.common.fd.set_gsi_routing(&routes)?;
        Ok(())
    }
}

/// Use `mincore(2)` to overapproximate the dirty bitmap for the given memslot. To be used
/// if a diff snapshot is requested, but dirty page tracking wasn't enabled.
fn mincore_bitmap(addr: *mut u8, len: usize) -> Result<Vec<u64>, VmError> {
    // TODO: Once Host 5.10 goes out of support, we can make this more robust and work on
    // swap-enabled systems, by doing mlock2(MLOCK_ONFAULT)/munlock() in this function (to
    // force swapped-out pages to get paged in, so that mincore will consider them incore).
    // However, on AMD (m6a/m7a) 5.10, doing so introduces a 100%/30ms regression to snapshot
    // creation, even if swap is disabled, so currently it cannot be done.

    // Mincore always works at PAGE_SIZE granularity, even if the VMA we are dealing with
    // is a hugetlbfs VMA (e.g. to report a single hugepage as "present", mincore will
    // give us 512 4k markers with the lowest bit set).
    let page_size = host_page_size();
    let mut mincore_bitmap = vec![0u8; len / page_size];
    let mut bitmap = vec![0u64; (len / page_size).div_ceil(64)];

    // SAFETY: The safety invariants of GuestRegionMmap ensure that region.as_ptr() is a valid
    // userspace mapping of size region.len() bytes. The bitmap has exactly one byte for each
    // page in this userspace mapping. Note that mincore does not operate on bitmaps like
    // KVM_MEM_LOG_DIRTY_PAGES, but rather it uses 8 bits per page (e.g. 1 byte), setting the
    // least significant bit to 1 if the page corresponding to a byte is in core (available in
    // the page cache and resolvable via just a minor page fault).
    let r = unsafe { libc::mincore(addr.cast(), len, mincore_bitmap.as_mut_ptr()) };

    if r != 0 {
        return Err(VmError::Mincore(vmm_sys_util::errno::Error::last()));
    }

    for (page_idx, b) in mincore_bitmap.iter().enumerate() {
        bitmap[page_idx / 64] |= (*b as u64 & 0x1) << (page_idx as u64 % 64);
    }

    Ok(bitmap)
}
