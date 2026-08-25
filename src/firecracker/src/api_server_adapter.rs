// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::thread;

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use vmm::logger::{ProcessTimeReporter, error_unrestricted, info_unrestricted, warn_unrestricted};
use vmm::rpc_interface::{
    ApiRequest, ApiResponse, BuildMicrovmFromRequestsError, PrebootApiController,
    RuntimeApiController, VmmAction,
};
use vmm::seccomp::BpfThreadMap;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::{EventManager, FcExitCode, Vmm};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::api_server::{ApiServer, HttpServer, ServerError};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ApiServerError {
    /// Failed to build MicroVM: {0}.
    BuildMicroVmError(BuildMicrovmFromRequestsError),
    /// MicroVM stopped with an error: {0:?}
    MicroVMStoppedWithError(FcExitCode),
    /// Failed to open the API socket at: {0}. Check that it is not already used.
    FailedToBindSocket(String),
    /// Failed to bind and run the HTTP server: {0}
    FailedToBindAndRunHttpServer(ServerError),
    /// Failed to build MicroVM from Json: {0}
    BuildFromJson(crate::BuildFromJsonError),
    /// Missing vmm seccomp filter
    MissingSeccompFilter,
    /// Failed to install vmm seccomp filter: {0}
    SeccompFilter(vmm::seccomp::InstallationError),
}

#[derive(Debug)]
struct ApiServerAdapter {
    api_event_fd: EventFd,
    from_api: Receiver<ApiRequest>,
    to_api: Sender<ApiResponse>,
    controller: RuntimeApiController,
    request: Option<ApiRequest>,
}

impl ApiServerAdapter {
    /// Runs the vmm to completion, while any arising control events are deferred
    /// to a `RuntimeApiController`.
    fn run_microvm(
        api_event_fd: EventFd,
        from_api: Receiver<ApiRequest>,
        to_api: Sender<ApiResponse>,
        vmm: Arc<Mutex<Vmm>>,
        event_manager: &mut EventManager,
    ) -> Result<(), ApiServerError> {
        // api_adapter 用来把 API 线程接入 VMM 的 event_manager
        // API 请求通过 channel 传递，api_event_fd 只负责通知/唤醒 event_manager
        // 让 VMM 线程在 epoll 事件中感知到 "有 API 请求需要处理"
        let api_adapter = Arc::new(Mutex::new(Self {
            api_event_fd,
            from_api,
            to_api,
            controller: RuntimeApiController::new(vmm.clone()),
            request: None,
        }));

        // 把 api 加入到时间通知里面
        event_manager.add_subscriber(api_adapter.clone());

        loop {
            // run() 方法就是在处理 epoll 事件
            event_manager
                .run()
                .expect("EventManager events driver fatal error");

            // 真正处理 api 的事件
            api_adapter
                .lock()
                .expect("Poisoned lock")
                .handle_request(event_manager);

            match vmm.lock().unwrap().shutdown_exit_code() {
                Some(FcExitCode::Ok) => break,
                Some(exit_code) => return Err(ApiServerError::MicroVMStoppedWithError(exit_code)),
                None => continue,
            }
        }
        Ok(())
    }

    fn _handle_request(&mut self, req_action: VmmAction, event_manager: &mut EventManager) {
        let response = self.controller.handle_request(req_action, event_manager);
        // Send back the result.
        self.to_api
            .send(Box::new(response))
            .map_err(|_| ())
            .expect("one-shot channel closed");
    }

    fn handle_request(&mut self, event_manager: &mut EventManager) {
        if let Some(api_request) = self.request.take() {
            let request_is_pause = *api_request == VmmAction::Pause;
            self._handle_request(*api_request, event_manager);

            // If the latest req is a pause request, temporarily switch to a mode where we
            // do blocking `recv`s on the `from_api` receiver in a loop, until we get
            // unpaused. The device emulation is implicitly paused since we do not
            // relinquish control to the event manager because we're not returning from
            // `process`.
            if request_is_pause {
                // This loop only attempts to process API requests, so things like the
                // metric flush timerfd handling are frozen as well.
                loop {
                    let req = self.from_api.recv().expect("Error receiving API request.");
                    let req_is_resume = *req == VmmAction::Resume;
                    self._handle_request(*req, event_manager);
                    if req_is_resume {
                        break;
                    }
                }
            }
        }
    }
}
impl MutEventSubscriber for ApiServerAdapter {
    /// Handle a read event (EPOLLIN).
    // event mamager 在处理 epoll 事件后，会调用 process 方法
    fn process(&mut self, event: Events, _: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        // source == self.api_event_fd.as_raw_fd() 判断 epoll 事件的 fd 是不是 api_event_fd
        // event_set == EventSet::IN 判断 fd 是否是可读事件
        if source == self.api_event_fd.as_raw_fd() && event_set == EventSet::IN {
            // 为了清理掉这次通知
            let _ = self.api_event_fd.read();
            // 从管道接受数据
            match self.from_api.try_recv() {
                // 这里的处理，只是放到了 request 里面，后面再取出来 handle_request
                Ok(api_request) => {
                    self.request = Some(api_request);
                }
                Err(TryRecvError::Empty) => {
                    warn_unrestricted!("Got a spurious notification from api thread");
                }
                Err(TryRecvError::Disconnected) => {
                    panic!("The channel's sending half was disconnected. Cannot receive data.");
                }
            };
        } else {
            error_unrestricted!("Spurious EventManager event for handler: ApiServerAdapter");
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.api_event_fd, EventSet::IN)) {
            error_unrestricted!("Failed to register activate event: {}", err);
        }
    }
}



/**
EventFd 整体工作原理

假设你发了：

PUT /actions
{ "action_type": "InstanceStart" }

API thread 做的大概是：

1. 解析 HTTP body
2. 得到 VmmAction::StartMicroVm
3. to_vmm.send(ApiRequest)
4. api_event_fd.write(1)
5. 等 from_vmm.recv() 拿响应

VMM thread 做的是：

1. epoll/event_manager 监听到 api_event_fd 可读
2. api_event_fd.read()
3. from_api.try_recv()
4. 拿到 ApiRequest
5. 执行对应 VMM action
6. to_api.send(ApiResponse)
 */
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_with_api(
    seccomp_filters: &mut BpfThreadMap,
    config_json: Option<String>,
    bind_path: PathBuf,
    instance_info: InstanceInfo,
    process_time_reporter: ProcessTimeReporter,
    boot_timer_enabled: bool,
    pci_enabled: bool,
    api_payload_limit: usize,
    mmds_size_limit: usize,
    metadata_json: Option<&str>,
) -> Result<(), ApiServerError> {
    // EventFd 作用：用来在线程之间通信
    // fd 用来发送通知，channel 用来传递消息


    // FD to notify of API events. This is a blocking eventfd by design.
    // It is used in the config/pre-boot loop which is a simple blocking loop
    // which only consumes API events.
    // API 线程告诉 VMM 线程：我已经把一个请求放进 channel 了，你来取
    // EFD_SEMAPHORE 表示每次调用 read() 方法只减 1
    let api_event_fd = EventFd::new(libc::EFD_SEMAPHORE).expect("Cannot create API Eventfd.");

    // FD used to signal API thread to stop/shutdown.
    // VMM 线程通知 API 线程退出
    let api_kill_switch = EventFd::new(libc::EFD_NONBLOCK).expect("Cannot create API kill switch.");


    // Channels for both directions between Vmm and Api threads.
    // api -> vmm 的管道，api 持有 to_vmm，vmm 持有 from_api
    let (to_vmm, from_api) = channel();
    // vmm -> api 的管道，vmm 持有 to_api，api 持有 from_vmm
    let (to_api, from_vmm) = channel();

    let to_vmm_event_fd = api_event_fd
        .try_clone()
        .expect("Failed to clone API event FD");
    let api_seccomp_filter = seccomp_filters
        .remove("api")
        .expect("Missing seccomp filter for API thread.");

    // bind_path 就是监听的 socket，就是 --api-sock 传进来的那个参数
    let mut server = match HttpServer::new(&bind_path) {
        Ok(s) => s,
        Err(ServerError::IOError(inner)) if inner.kind() == std::io::ErrorKind::AddrInUse => {
            let sock_path = bind_path.display().to_string();
            return Err(ApiServerError::FailedToBindSocket(sock_path));
        }
        Err(err) => {
            return Err(ApiServerError::FailedToBindAndRunHttpServer(err));
        }
    };
    info_unrestricted!("Listening on API socket ({bind_path:?}).");

    let api_kill_switch_clone = api_kill_switch
        .try_clone()
        .expect("Failed to clone API kill switch");

    server
        .add_kill_switch(api_kill_switch_clone)
        .expect("Cannot add HTTP server kill switch");

    // 启动 API 线程
    // Start the separate API thread.
    let api_thread = thread::Builder::new()
        // fc_api 就是 ps -T -p 这个命令看到的 CMD
        .name("fc_api".to_owned())
        .spawn(move || {
            // run 方法是真正在处理 api 请求
            ApiServer::new(to_vmm, from_vmm, to_vmm_event_fd).run(
                server,
                process_time_reporter,
                &api_seccomp_filter,
                api_payload_limit,
            );
        })
        .expect("API thread spawn failed.");

    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Configure, build and start the microVM.
    let build_result = match config_json {
        Some(json) => super::build_microvm_from_json(
            seccomp_filters,
            &mut event_manager,
            json,
            instance_info,
            boot_timer_enabled,
            pci_enabled,
            mmds_size_limit,
            metadata_json,
        )
        .map_err(ApiServerError::BuildFromJson),
        // 在执行 build_microvm_from_requests 时，event_manager 还没有 run
        // 也就是 InstanceStart 前的请求会被 build_microvm_from_requests 处理
        // InstanceStart 后的请求就由 event_manager 处理
        None => PrebootApiController::build_microvm_from_requests(
            seccomp_filters,
            &mut event_manager,
            instance_info,
            &from_api,
            &to_api,
            &api_event_fd,
            boot_timer_enabled,
            pci_enabled,
            mmds_size_limit,
            metadata_json,
        )
        .map_err(ApiServerError::BuildMicroVmError),
    };

    // INVARIANT: seccomp must be applied before entering the event loop.
    // No guest-facing operations may occur between builder return and filter installation.
    let result = build_result.and_then(|vmm| {
        vmm::seccomp::apply_filter(
            seccomp_filters
                .get("vmm")
                .ok_or(ApiServerError::MissingSeccompFilter)?,
        )
        .map_err(ApiServerError::SeccompFilter)?;

        ApiServerAdapter::run_microvm(api_event_fd, from_api, to_api, vmm, &mut event_manager)
    });

    api_kill_switch.write(1).unwrap();
    // This call to thread::join() should block until the API thread has processed the
    // shutdown-internal and returns from its function.
    // API 一直在这里卡住，知道收到退出信号
    api_thread.join().expect("Api thread should join");

    result
}
