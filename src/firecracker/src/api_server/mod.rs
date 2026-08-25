// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements the interface for intercepting API requests, forwarding them to the VMM
//! and responding to the user.
//! It is constructed on top of an HTTP Server that uses Unix Domain Sockets and `EPOLL` to
//! handle multiple connections on the same thread.

pub mod parsed_request;
pub mod request;

use std::fmt::Debug;
use std::sync::mpsc;

pub use micro_http::{Body, HttpServer, Request, Response, ServerError, StatusCode, Version};
use parsed_request::{ParsedRequest, RequestAction};
use serde_json::json;
use utils::time::{ClockType, get_time_us};
use vmm::logger::{
    ProcessTimeReporter, debug, error_unrestricted, info_unrestricted, warn_unrestricted,
};
use vmm::rpc_interface::{ApiRequest, ApiResponse, VmmAction};
use vmm::seccomp::BpfProgramRef;
use vmm_sys_util::eventfd::EventFd;

/// Structure associated with the API server implementation.
#[derive(Debug)]
pub struct ApiServer {
    /// Sender which allows passing messages to the VMM.
    api_request_sender: mpsc::Sender<ApiRequest>,
    /// Receiver which collects messages from the VMM.
    vmm_response_receiver: mpsc::Receiver<ApiResponse>,
    /// FD on which we notify the VMM that we have sent at least one
    /// `VmmRequest`.
    to_vmm_fd: EventFd,
}

impl ApiServer {
    /// Constructor for `ApiServer`.
    ///
    /// Returns the newly formed `ApiServer`.
    pub fn new(
        api_request_sender: mpsc::Sender<ApiRequest>,
        vmm_response_receiver: mpsc::Receiver<ApiResponse>,
        to_vmm_fd: EventFd,
    ) -> Self {
        ApiServer {
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
        }
    }

    /// Runs the Api Server.
    ///
    /// # Arguments
    ///
    /// * `path` - the socket path on which the server will wait for requests.
    /// * `start_time_us` - the timestamp for when the process was started in us.
    /// * `start_time_cpu_us` - the timestamp for when the process was started in CPU us.
    /// * `seccomp_filter` - the seccomp filter to apply.
    pub fn run(
        &mut self,
        mut server: HttpServer,
        process_time_reporter: ProcessTimeReporter,
        seccomp_filter: BpfProgramRef,
        api_payload_limit: usize,
    ) {
        // Set the api payload size limit.
        server.set_payload_max_size(api_payload_limit);

        // Load seccomp filters on the API thread.
        // Execution panics if filters cannot be loaded, use --no-seccomp if skipping filters
        // altogether is the desired behaviour.
        if let Err(err) = vmm::seccomp::apply_filter(seccomp_filter) {
            panic!(
                "Failed to set the requested seccomp filters on the API thread: {}",
                err
            );
        }

        server.start_server().expect("Cannot start HTTP server");
        info_unrestricted!("API server started.");

        // Store process start time metric.
        process_time_reporter.report_start_time();
        // Store process CPU start time metric.
        process_time_reporter.report_cpu_start_time();

        loop {
            // 拿到 HTTP 请求，request_vec 是已经解析好的请求
            // 每次轮询可能会拿到多个请求
            let request_vec = match server.requests() {
                Ok(vec) => vec,
                Err(ServerError::ShutdownEvent) => {
                    server.flush_outgoing_writes();
                    debug!("shutdown request received, API server thread ending.");
                    return;
                }
                Err(err) => {
                    // print request error, but keep server running
                    error_unrestricted!("API Server error on retrieving incoming request: {}", err);
                    continue;
                }
            };
            for server_request in request_vec {
                // Use `self.handle_request()` as the processing callback.
                let response = server_request.process(|request| self.handle_request(request));
                if let Err(err) = server.respond(response) {
                    error_unrestricted!("API Server encountered an error on response: {}", err);
                };
            }
        }
    }

    /// Handles an API request received through the associated socket.
    pub fn handle_request(&mut self, request: &Request) -> Response {
        // 在这里 try_from 真正走到了 router 里面，在 route 到的方法里去处理请求
        match ParsedRequest::try_from(request).map(|r| r.into_parts()) {
            // req_action 和 parsing_info 是 try_from 方法返回的
            Ok((req_action, mut parsing_info)) => {

                let mut response = match req_action {
                    // serve_vmm_action_request 把 API 中生成 VmmAction 给到 vmm 去处理
                    RequestAction::Sync(vmm_action) => self.serve_vmm_action_request(vmm_action),
                };
                if let Some(message) = parsing_info.take_deprecation_message() {
                    warn_unrestricted!("{}", message);
                    response.set_deprecation();
                }
                response
            }
            Err(err) => {
                error_unrestricted!("{:?}", err);
                err.into()
            }
        }
    }

    fn serve_vmm_action_request(&mut self, vmm_action: Box<VmmAction>) -> Response {
        // 这里很好的说明了线程间通信的原理
        // api_request_sender 就是 run_with_api 中的 to_vmm，往管道里放了一个 vmm_action 消息
        self.api_request_sender
            .send(vmm_action)
            .expect("Failed to send VMM message");

        // to_vmm_fd 就是 run_with_api 中的 api_event_fd，往 fd 发送一个通知
        self.to_vmm_fd.write(1).expect("Cannot update send VMM fd");

        // vmm_response_receiver 就是 run_with_api 中的 from_vmm，等待从管道中收数据
        let vmm_outcome = *(self.vmm_response_receiver.recv().expect("VMM disconnected"));

        let response = ParsedRequest::convert_to_response(&vmm_outcome);
        response
    }

    /// An HTTP response which also includes a body.
    pub(crate) fn json_response<T: Into<String> + Debug>(status: StatusCode, body: T) -> Response {
        let mut response = Response::new(Version::Http11, status);
        response.set_body(Body::new(body.into()));
        response
    }

    fn json_fault_message<T: AsRef<str> + serde::Serialize + Debug>(msg: T) -> String {
        json!({ "fault_message": msg }).to_string()
    }
}
