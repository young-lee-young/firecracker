// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::os::fd::AsRawFd;
use std::sync::atomic::{Ordering, fence};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::sync::{Arc, Barrier};
use std::time::Duration;
use std::{fmt, io, thread};

use kvm_bindings::{KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN};
use kvm_ioctls::{VcpuExit, VcpuFd};
use libc::{c_int, c_void, siginfo_t};
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;

use crate::FcExitCode;
pub use crate::arch::{KvmVcpu, KvmVcpuConfigureError, KvmVcpuError, Peripherals, VcpuState};
use crate::cpu_config::templates::{CpuConfiguration, GuestConfigError};
#[cfg(feature = "gdb")]
use crate::gdb::target::{GdbTargetError, get_raw_tid};
use crate::logger::{IncMetric, METRICS, error, info, warn};
use crate::seccomp::{BpfProgram, BpfProgramRef};
use crate::utils::signal::{Killable, register_signal_handler, sigrtmin};
use crate::utils::sm::StateMachine;
use crate::vstate::bus::Bus;
use crate::vstate::vm::KvmVm;

/// Signal number (SIGRTMIN) used to kick Vcpus.
pub const VCPU_RTSIG_OFFSET: i32 = 0;

/// Maximum time to wait for a vCPU thread to exit when dropping its handle.
const VCPU_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VcpuError {
    /// Error creating vcpu config: {0}
    VcpuConfig(GuestConfigError),
    /// Received error signaling kvm exit: {0}
    FaultyKvmExit(String),
    /// Failed to signal vcpu: {0}
    SignalVcpu(vmm_sys_util::errno::Error),
    /// Unexpected kvm exit received: {0}
    UnhandledKvmExit(String),
    /// Failed to run action on vcpu: {0}
    VcpuResponse(KvmVcpuError),
    /// Cannot spawn a new vCPU thread: {0}
    VcpuSpawn(io::Error),
    /// Vcpu not present in TLS
    VcpuTlsNotPresent,
    /// Error with gdb request sent
    #[cfg(feature = "gdb")]
    GdbRequest(GdbTargetError),
}

/// Encapsulates configuration parameters for the guest vCPUS.
#[derive(Debug)]
pub struct VcpuConfig {
    /// Number of guest VCPUs.
    /// CPU 的数量
    pub vcpu_count: u8,
    /// Enable simultaneous multithreading in the CPUID configuration.
    /// 是否使用超线程
    pub smt: bool,
    /// Configuration for vCPU
    pub cpu_config: CpuConfiguration,
}

/// Error type for [`Vcpu::start_threaded`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StartThreadedError {
    /// Failed to spawn vCPU thread: {0}
    Spawn(std::io::Error),
    /// Failed to clone kvm Vcpu fd: {0}
    CopyFd(CopyKvmFdError),
}

/// Error type for [`Vcpu::copy_kvm_vcpu_fd`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CopyKvmFdError {
    /// Error with libc dup of kvm Vcpu fd
    DupError(#[from] std::io::Error),
    /// Error creating the Vcpu from the duplicated Vcpu fd
    CreateVcpuError(#[from] kvm_ioctls::Error),
}

/// A wrapper around creating and using a vcpu.
#[derive(Debug)]
pub struct Vcpu {
    /// Access to kvm-arch specific functionality.
    pub kvm_vcpu: KvmVcpu,

    /// File descriptor for vcpu to trigger exit event on vmm.
    exit_evt: EventFd,
    /// Debugger emitter for gdb events
    #[cfg(feature = "gdb")]
    gdb_event: Option<Sender<usize>>,
    /// The receiving end of events channel owned by the vcpu side.
    event_receiver: Receiver<VcpuEvent>,
    /// The transmitting end of the events channel which will be given to the handler.
    event_sender: Option<Sender<VcpuEvent>>,
    /// The receiving end of the responses channel which will be given to the handler.
    response_receiver: Option<Receiver<VcpuResponse>>,
    /// The transmitting end of the responses channel owned by the vcpu side.
    response_sender: Sender<VcpuResponse>,
}

impl Vcpu {
    /// Registers a signal handler which kicks the vcpu running on the current thread, if there is
    /// one.
    fn register_kick_signal_handler(&mut self) {
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
            // We write to the immediate_exit from other thread, so make sure the read in the
            // KVM_RUN sees the up to date value
            fence(Ordering::Acquire);
        }
        register_signal_handler(sigrtmin() + VCPU_RTSIG_OFFSET, handle_signal)
            .expect("Failed to register vcpu signal handler");
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `index` - Represents the 0-based CPU index between [0, max vcpus).
    /// * `vm` - The vm to which this vcpu will get attached.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    pub fn new(index: u8, vm: &KvmVm, exit_evt: EventFd) -> Result<Self, VcpuError> {
        let (event_sender, event_receiver) = channel();
        let (response_sender, response_receiver) = channel();

        // 调用 KVM 系统调用创建 vCPU
        let kvm_vcpu = KvmVcpu::new(index, vm).unwrap();

        Ok(Vcpu {
            exit_evt,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
            #[cfg(feature = "gdb")]
            gdb_event: None,
            kvm_vcpu,
        })
    }

    /// Sets a MMIO bus for this vcpu.
    pub fn set_mmio_bus(&mut self, mmio_bus: Arc<Bus>) {
        self.kvm_vcpu.peripherals.mmio_bus = Some(mmio_bus);
    }

    /// Attaches the fields required for debugging
    #[cfg(feature = "gdb")]
    pub fn attach_debug_info(&mut self, gdb_event: Sender<usize>) {
        self.gdb_event = Some(gdb_event);
    }

    /// Obtains a copy of the VcpuFd
    pub fn copy_kvm_vcpu_fd(&self, vm: &KvmVm) -> Result<VcpuFd, CopyKvmFdError> {
        // SAFETY: We own this fd so it is considered safe to clone
        let r = unsafe { libc::dup(self.kvm_vcpu.fd.as_raw_fd()) };
        if r < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: We assert this is a valid fd by checking the result from the dup
        unsafe { Ok(vm.fd().create_vcpu_from_rawfd(r)?) }
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vcpu.
    pub fn start_threaded(
        mut self,
        vm: &KvmVm,
        seccomp_filter: Arc<BpfProgram>,
        barrier: Arc<Barrier>,
    ) -> Result<VcpuHandle, StartThreadedError> {
        let event_sender = self.event_sender.take().expect("vCPU already started");
        let response_receiver = self.response_receiver.take().unwrap();
        let vcpu_fd = self
            .copy_kvm_vcpu_fd(vm)
            .map_err(StartThreadedError::CopyFd)?;
        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.kvm_vcpu.index))
            .spawn(move || {
                let filter = &*seccomp_filter;
                self.register_kick_signal_handler();
                // Synchronization to make sure thread local data is initialized.
                barrier.wait();
                self.run(filter);
            })
            .map_err(StartThreadedError::Spawn)?;

        Ok(VcpuHandle::new(
            event_sender,
            response_receiver,
            vcpu_fd,
            vcpu_thread,
        ))
    }

    /// Main loop of the vCPU thread.
    ///
    /// Runs the vCPU in KVM context in a loop. Handles KVM_EXITs then goes back in.
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&mut self, seccomp_filter: BpfProgramRef) {
        // Load seccomp filters for this vCPU thread.
        // Execution panics if filters cannot be loaded, use --no-seccomp if skipping filters
        // altogether is the desired behaviour.
        if let Err(err) = crate::seccomp::apply_filter(seccomp_filter) {
            panic!(
                "Failed to set the requested seccomp filters on vCPU {}: Error: {}",
                self.kvm_vcpu.index, err
            );
        }

        // Start running the machine state in the `Paused` state.
        StateMachine::run(self, Self::paused);
    }

    // This is the main loop of the `Running` state.
    fn running(&mut self) -> StateMachine<Self> {
        // This loop is here just for optimizing the emulation path.
        // No point in ticking the state machine if there are no external events.
        loop {
            match self.run_emulation() {
                // Emulation ran successfully, continue.
                Ok(VcpuEmulation::Handled) => (),
                // Emulation was interrupted, check external events.
                Ok(VcpuEmulation::Interrupted) => break,
                // The guest requested a SHUTDOWN or RESET. This is ARM
                // specific. On x86 the i8042 emulation signals the main thread
                // directly without calling Vcpu::exit().
                Ok(VcpuEmulation::Stopped) => return self.exit(FcExitCode::Ok),
                // If the emulation requests a pause lets do this
                #[cfg(feature = "gdb")]
                Ok(VcpuEmulation::Paused) => {
                    #[cfg(target_arch = "x86_64")]
                    self.kvm_vcpu.kvmclock_ctrl();
                    return StateMachine::next(Self::paused);
                }
                // Emulation errors lead to vCPU exit.
                Err(_) => return self.exit(FcExitCode::GenericError),
            }
        }

        // By default don't change state.
        let mut state = StateMachine::next(Self::running);

        // Break this emulation loop on any transition request/external event.
        match self.event_receiver.try_recv() {
            // Running ---- Pause ----> Paused
            Ok(VcpuEvent::Pause) => {
                // Nothing special to do.
                self.response_sender
                    .send(VcpuResponse::Paused)
                    .expect("vcpu channel unexpectedly closed");

                #[cfg(target_arch = "x86_64")]
                self.kvm_vcpu.kvmclock_ctrl();

                // Move to 'paused' state.
                state = StateMachine::next(Self::paused);
            }
            Ok(VcpuEvent::Resume) => {
                self.response_sender
                    .send(VcpuResponse::Resumed)
                    .expect("vcpu channel unexpectedly closed");
            }
            // SaveState cannot be performed on a running Vcpu.
            Ok(VcpuEvent::SaveState) => {
                self.response_sender
                    .send(VcpuResponse::NotAllowed(String::from(
                        "save/restore unavailable while running",
                    )))
                    .expect("vcpu channel unexpectedly closed");
            }
            // DumpCpuConfig cannot be performed on a running Vcpu.
            Ok(VcpuEvent::DumpCpuConfig) => {
                self.response_sender
                    .send(VcpuResponse::NotAllowed(String::from(
                        "cpu config dump is unavailable while running",
                    )))
                    .expect("vcpu channel unexpectedly closed");
            }
            Ok(VcpuEvent::Finish) => return StateMachine::finish(),
            // Unhandled exit of the other end.
            Err(TryRecvError::Disconnected) => {
                // Move to 'exited' state.
                state = self.exit(FcExitCode::GenericError);
            }
            // All other events or lack thereof have no effect on current 'running' state.
            Err(TryRecvError::Empty) => (),
        }

        state
    }

    // This is the main loop of the `Paused` state.
    fn paused(&mut self) -> StateMachine<Self> {
        match self.event_receiver.recv() {
            // Paused ---- Resume ----> Running
            Ok(VcpuEvent::Resume) => {
                if self.kvm_vcpu.fd.get_kvm_run().immediate_exit == 1u8 {
                    warn!(
                        "Received a VcpuEvent::Resume message with immediate_exit enabled. \
                         immediate_exit was disabled before proceeding"
                    );
                    self.kvm_vcpu.fd.set_kvm_immediate_exit(0);
                }
                self.response_sender
                    .send(VcpuResponse::Resumed)
                    .expect("vcpu channel unexpectedly closed");
                // Move to 'running' state.
                StateMachine::next(Self::running)
            }
            Ok(VcpuEvent::Pause) => {
                self.response_sender
                    .send(VcpuResponse::Paused)
                    .expect("vcpu channel unexpectedly closed");
                StateMachine::next(Self::paused)
            }
            Ok(VcpuEvent::SaveState) => {
                // Save vcpu state.
                self.kvm_vcpu
                    .save_state()
                    .map(|vcpu_state| {
                        self.response_sender
                            .send(VcpuResponse::SavedState(Box::new(vcpu_state)))
                            .expect("vcpu channel unexpectedly closed");
                    })
                    .unwrap_or_else(|err| {
                        self.response_sender
                            .send(VcpuResponse::Error(VcpuError::VcpuResponse(err)))
                            .expect("vcpu channel unexpectedly closed");
                    });

                StateMachine::next(Self::paused)
            }
            Ok(VcpuEvent::DumpCpuConfig) => {
                self.kvm_vcpu
                    .dump_cpu_config()
                    .map(|cpu_config| {
                        self.response_sender
                            .send(VcpuResponse::DumpedCpuConfig(Box::new(cpu_config)))
                            .expect("vcpu channel unexpectedly closed");
                    })
                    .unwrap_or_else(|err| {
                        self.response_sender
                            .send(VcpuResponse::Error(VcpuError::VcpuResponse(err)))
                            .expect("vcpu channel unexpectedly closed");
                    });

                StateMachine::next(Self::paused)
            }
            Ok(VcpuEvent::Finish) => StateMachine::finish(),
            // Unhandled exit of the other end.
            Err(_) => {
                // Move to 'exited' state.
                self.exit(FcExitCode::GenericError)
            }
        }
    }

    // Transition to the exited state and finish on command.
    // Note that this function isn't called when the guest asks for a CPU
    // reset via the i8042 controller on x86.
    fn exit(&mut self, exit_code: FcExitCode) -> StateMachine<Self> {
        // 向 vCPU 退出 eventfd 中写入数据
        if let Err(err) = self.exit_evt.write(1) {
            METRICS.vcpu.failures.inc();
            error!("Failed signaling vcpu exit event: {}", err);
        }
        // From this state we only accept going to finished.
        loop {
            self.response_sender
                .send(VcpuResponse::Exited(exit_code))
                .expect("vcpu channel unexpectedly closed");
            // Wait for and only accept 'VcpuEvent::Finish'.
            if let Ok(VcpuEvent::Finish) = self.event_receiver.recv() {
                break;
            }
        }
        StateMachine::finish()
    }

    /// Runs the vCPU in KVM context and handles the kvm exit reason.
    ///
    /// Returns error or enum specifying whether emulation was handled or interrupted.
    pub fn run_emulation(&mut self) -> Result<VcpuEmulation, VcpuError> {
        if self.kvm_vcpu.fd.get_kvm_run().immediate_exit == 1u8 {
            warn!("Requested a vCPU run with immediate_exit enabled. The operation was skipped");
            self.kvm_vcpu.fd.set_kvm_immediate_exit(0);
            return Ok(VcpuEmulation::Interrupted);
        }

        match self.kvm_vcpu.fd.run() {
            Err(ref err) if err.errno() == libc::EINTR => {
                self.kvm_vcpu.fd.set_kvm_immediate_exit(0);
                // Notify that this KVM_RUN was interrupted.
                Ok(VcpuEmulation::Interrupted)
            }
            #[cfg(feature = "gdb")]
            Ok(VcpuExit::Debug(_)) => {
                if let Some(gdb_event) = &self.gdb_event {
                    gdb_event
                        .send(get_raw_tid(self.kvm_vcpu.index.into()))
                        .expect("Unable to notify gdb event");
                }

                Ok(VcpuEmulation::Paused)
            }
            emulation_result => handle_kvm_exit(&mut self.kvm_vcpu.peripherals, emulation_result),
        }
    }
}

/// Handle the return value of a call to [`VcpuFd::run`] and update our emulation accordingly
fn handle_kvm_exit(
    peripherals: &mut Peripherals,
    emulation_result: Result<VcpuExit, errno::Error>,
) -> Result<VcpuEmulation, VcpuError> {
    match emulation_result {
        Ok(run) => match run {
            VcpuExit::MmioRead(addr, data) => {
                data.fill(0);
                if let Some(mmio_bus) = &peripherals.mmio_bus {
                    let _metric = METRICS.vcpu.exit_mmio_read_agg.record_latency_metrics();
                    if let Err(err) = mmio_bus.read(addr, data) {
                        warn!("Invalid MMIO read @ {addr:#x}:{:#x}: {err}", data.len());
                    }
                    METRICS.vcpu.exit_mmio_read.inc();
                }
                Ok(VcpuEmulation::Handled)
            }
            VcpuExit::MmioWrite(addr, data) => {
                if let Some(mmio_bus) = &peripherals.mmio_bus {
                    let _metric = METRICS.vcpu.exit_mmio_write_agg.record_latency_metrics();
                    if let Err(err) = mmio_bus.write(addr, data) {
                        warn!("Invalid MMIO read @ {addr:#x}:{:#x}: {err}", data.len());
                    }
                    METRICS.vcpu.exit_mmio_write.inc();
                }
                Ok(VcpuEmulation::Handled)
            }
            // Documentation specifies that below kvm exits are considered
            // errors.
            VcpuExit::FailEntry(hardware_entry_failure_reason, cpu) => {
                // Hardware entry failure.
                METRICS.vcpu.failures.inc();
                error!(
                    "Received KVM_EXIT_FAIL_ENTRY signal: {} on cpu {}",
                    hardware_entry_failure_reason, cpu
                );
                Err(VcpuError::FaultyKvmExit(format!(
                    "{:?}",
                    VcpuExit::FailEntry(hardware_entry_failure_reason, cpu)
                )))
            }
            VcpuExit::InternalError => {
                // Failure from the Linux KVM subsystem rather than from the hardware.
                METRICS.vcpu.failures.inc();
                error!("Received KVM_EXIT_INTERNAL_ERROR signal");
                Err(VcpuError::FaultyKvmExit(format!(
                    "{:?}",
                    VcpuExit::InternalError
                )))
            }
            VcpuExit::SystemEvent(event_type, event_flags) => match event_type {
                KVM_SYSTEM_EVENT_RESET | KVM_SYSTEM_EVENT_SHUTDOWN => {
                    info!(
                        "Received KVM_SYSTEM_EVENT: type: {}, event: {:?}",
                        event_type, event_flags
                    );
                    Ok(VcpuEmulation::Stopped)
                }
                _ => {
                    METRICS.vcpu.failures.inc();
                    error!(
                        "Received KVM_SYSTEM_EVENT signal type: {}, flag: {:?}",
                        event_type, event_flags
                    );
                    Err(VcpuError::FaultyKvmExit(format!(
                        "{:?}",
                        VcpuExit::SystemEvent(event_type, event_flags)
                    )))
                }
            },
            arch_specific_reason => {
                // run specific architecture emulation.
                peripherals.run_arch_emulation(arch_specific_reason)
            }
        },
        // The unwrap on raw_os_error can only fail if we have a logic
        // error in our code in which case it is better to panic.
        Err(ref err) => match err.errno() {
            libc::EAGAIN => Ok(VcpuEmulation::Handled),
            libc::ENOSYS => {
                METRICS.vcpu.failures.inc();
                error!("Received ENOSYS error because KVM failed to emulate an instruction.");
                Err(VcpuError::FaultyKvmExit(
                    "Received ENOSYS error because KVM failed to emulate an instruction."
                        .to_string(),
                ))
            }
            _ => {
                METRICS.vcpu.failures.inc();
                error!("Failure during vcpu run: {}", err);
                Err(VcpuError::FaultyKvmExit(format!("{}", err)))
            }
        },
    }
}

/// List of events that the Vcpu can receive.
#[derive(Debug, Clone)]
pub enum VcpuEvent {
    /// The vCPU thread will end when receiving this message.
    Finish,
    /// Pause the Vcpu.
    Pause,
    /// Event to resume the Vcpu.
    Resume,
    /// Event to save the state of a paused Vcpu.
    SaveState,
    /// Event to dump CPU configuration of a paused Vcpu.
    DumpCpuConfig,
}

/// List of responses that the Vcpu reports.
pub enum VcpuResponse {
    /// Requested action encountered an error.
    Error(VcpuError),
    /// Vcpu is stopped.
    Exited(FcExitCode),
    /// Requested action not allowed.
    NotAllowed(String),
    /// Vcpu is paused.
    Paused,
    /// Vcpu is resumed.
    Resumed,
    /// Vcpu state is saved.
    SavedState(Box<VcpuState>),
    /// Vcpu is in the state where CPU config is dumped.
    DumpedCpuConfig(Box<CpuConfiguration>),
}

impl fmt::Debug for VcpuResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::VcpuResponse::*;
        match self {
            Paused => write!(f, "VcpuResponse::Paused"),
            Resumed => write!(f, "VcpuResponse::Resumed"),
            Exited(code) => write!(f, "VcpuResponse::Exited({:?})", code),
            SavedState(_) => write!(f, "VcpuResponse::SavedState"),
            Error(err) => write!(f, "VcpuResponse::Error({:?})", err),
            NotAllowed(reason) => write!(f, "VcpuResponse::NotAllowed({})", reason),
            DumpedCpuConfig(_) => write!(f, "VcpuResponse::DumpedCpuConfig"),
        }
    }
}

/// Wrapper over Vcpu that hides the underlying interactions with the Vcpu thread.
#[derive(Debug)]
pub struct VcpuHandle {
    event_sender: Sender<VcpuEvent>,
    response_receiver: Receiver<VcpuResponse>,
    /// VcpuFd
    pub vcpu_fd: VcpuFd,
    // Rust JoinHandles have to be wrapped in Option if you ever plan on 'join()'ing them.
    // We want to be able to join these threads in tests.
    vcpu_thread: Option<thread::JoinHandle<()>>,
}

/// Error type for [`VcpuHandle::send_event`].
#[derive(Debug, derive_more::From, thiserror::Error)]
#[error("Failed to signal vCPU: {0}")]
pub struct VcpuSendEventError(pub vmm_sys_util::errno::Error);

impl VcpuHandle {
    /// Creates a new [`VcpuHandle`].
    ///
    /// # Arguments
    /// + `event_sender`: [`Sender`] to communicate [`VcpuEvent`] to control the vcpu.
    /// + `response_received`: [`Received`] from which the vcpu's responses can be read.
    /// + `vcpu_thread`: A [`JoinHandle`] for the vcpu thread.
    pub fn new(
        event_sender: Sender<VcpuEvent>,
        response_receiver: Receiver<VcpuResponse>,
        vcpu_fd: VcpuFd,
        vcpu_thread: thread::JoinHandle<()>,
    ) -> Self {
        Self {
            event_sender,
            response_receiver,
            vcpu_fd,
            vcpu_thread: Some(vcpu_thread),
        }
    }
    /// Sends event to vCPU.
    ///
    /// # Errors
    ///
    /// When [`vmm_sys_util::linux::signal::Killable::kill`] errors.
    pub fn send_event(&mut self, event: VcpuEvent) -> Result<(), VcpuSendEventError> {
        // Use expect() to crash if the other thread closed this channel.
        self.event_sender
            .send(event)
            .expect("event sender channel closed on vcpu end.");
        // Kick the vcpu so it picks up the message.
        // Add a fence to ensure the write is visible to the vpu thread
        self.vcpu_fd.set_kvm_immediate_exit(1);
        fence(Ordering::Release);
        self.vcpu_thread
            .as_ref()
            // Safe to unwrap since constructor make this 'Some'.
            .unwrap()
            .kill(sigrtmin() + VCPU_RTSIG_OFFSET)?;
        Ok(())
    }

    /// Returns a reference to the [`Received`] from which the vcpu's responses can be read.
    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }
}

// Wait for the Vcpu thread to finish execution
impl Drop for VcpuHandle {
    fn drop(&mut self) {
        // The vCPU thread owns the response sender, so the channel disconnects
        // once it exits. Wait for that disconnect (draining any stale responses)
        // with a timeout rather than joining unconditionally, so a thread that
        // never finished (e.g. a missed Finish event) fails fast instead of
        // hanging teardown forever.
        let thread = self.vcpu_thread.take().unwrap();
        loop {
            match self.response_receiver.recv_timeout(VCPU_JOIN_TIMEOUT) {
                // Sender dropped: the thread has exited.
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    let name = thread.thread().name().unwrap_or("<unnamed>");
                    panic!("Timed out waiting for vCPU thread '{name}' to exit")
                }
                // Unexpected: a response was still queued at teardown. Discard
                // it and keep waiting for the thread to exit.
                Ok(response) => {
                    warn!("Discarding unexpected vCPU response during teardown: {response:?}");
                }
            }
        }
        thread.join().unwrap();
    }
}

/// Vcpu emulation state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VcpuEmulation {
    /// Handled.
    Handled,
    /// Interrupted.
    Interrupted,
    /// Stopped.
    Stopped,
    /// Pause request
    #[cfg(feature = "gdb")]
    Paused,
}
