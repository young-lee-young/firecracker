// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use micro_http::{Body, Method, Request, Response, StatusCode, Version};
use serde::ser::Serialize;
use serde_json::Value;
use vmm::devices::virtio::device::VirtioDeviceType;
use vmm::logger::{Level, error_unrestricted, info_unrestricted, log_enabled};
use vmm::rpc_interface::{VmmAction, VmmActionError, VmmData};

use super::ApiServer;
use super::request::actions::parse_put_actions;
use super::request::balloon::{parse_get_balloon, parse_patch_balloon, parse_put_balloon};
use super::request::boot_source::parse_put_boot_source;
use super::request::cpu_configuration::parse_put_cpu_config;
use super::request::drive::{parse_patch_drive, parse_put_drive};
use super::request::entropy::parse_put_entropy;
use super::request::instance_info::parse_get_instance_info;
use super::request::logger::parse_put_logger;
use super::request::machine_configuration::{
    parse_get_machine_config, parse_patch_machine_config, parse_put_machine_config,
};
use super::request::metrics::parse_put_metrics;
use super::request::mmds::{parse_get_mmds, parse_patch_mmds, parse_put_mmds};
use super::request::net::{parse_patch_net, parse_put_net};
use super::request::pmem::{parse_patch_pmem, parse_put_pmem};
use super::request::snapshot::{parse_patch_vm_state, parse_put_snapshot};
use super::request::version::parse_get_version;
use super::request::vsock::parse_put_vsock;
use crate::api_server::request::hotplug::memory::{
    parse_get_memory_hotplug, parse_patch_memory_hotplug, parse_put_memory_hotplug,
};
use crate::api_server::request::hotplug::parse_unplug_device;
use crate::api_server::request::serial::parse_put_serial;

#[derive(Debug)]
pub(crate) enum RequestAction {
    Sync(Box<VmmAction>),
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct ParsingInfo {
    deprecation_message: Option<String>,
}

impl ParsingInfo {
    pub fn append_deprecation_message(&mut self, message: &str) {
        match self.deprecation_message.as_mut() {
            None => self.deprecation_message = Some(message.to_owned()),
            Some(s) => (*s).push_str(message),
        }
    }

    pub fn take_deprecation_message(&mut self) -> Option<String> {
        self.deprecation_message.take()
    }
}

#[derive(Debug)]
pub(crate) struct ParsedRequest {
    action: RequestAction,
    parsing_info: ParsingInfo,
}

impl TryFrom<&Request> for ParsedRequest {
    type Error = RequestError;
    fn try_from(request: &Request) -> Result<Self, Self::Error> {
        let request_uri = request.uri().get_abs_path().to_string();
        let description = describe(
            request.method(),
            request_uri.as_str(),
            request.body.as_ref(),
        );
        info_unrestricted!("The API server received a {description}.");

        // Split request uri by '/' by doing:
        // 1. Trim starting '/' characters
        // 2. Splitting by '/'
        let mut path_tokens = request_uri.trim_start_matches('/').split_terminator('/');
        let path = path_tokens.next().unwrap_or("");

        match (request.method(), path, request.body.as_ref()) {
            (Method::Get, "", None) => parse_get_instance_info(),
            (Method::Get, "balloon", None) => parse_get_balloon(path_tokens),
            (Method::Get, "version", None) => parse_get_version(),
            (Method::Get, "vm", None) if path_tokens.next() == Some("config") => {
                Ok(ParsedRequest::new_sync(VmmAction::GetFullVmConfig))
            }
            (Method::Get, "machine-config", None) => parse_get_machine_config(),
            (Method::Get, "mmds", None) => parse_get_mmds(),
            (Method::Get, "hotplug", None) if path_tokens.next() == Some("memory") => {
                parse_get_memory_hotplug()
            }
            (Method::Get, _, Some(_)) => method_to_error(Method::Get),
            (Method::Put, "actions", Some(body)) => parse_put_actions(body),
            (Method::Put, "balloon", Some(body)) => parse_put_balloon(body),
            (Method::Put, "boot-source", Some(body)) => parse_put_boot_source(body),
            (Method::Put, "cpu-config", Some(body)) => parse_put_cpu_config(body),
            // PUT 方法 drives，配置磁盘接口
            (Method::Put, "drives", Some(body)) => parse_put_drive(body, path_tokens.next()),
            (Method::Put, "pmem", Some(body)) => parse_put_pmem(body, path_tokens.next()),
            (Method::Put, "logger", Some(body)) => parse_put_logger(body),
            (Method::Put, "serial", Some(body)) => parse_put_serial(body),
            // 配置 CPU、MEM 等信息
            (Method::Put, "machine-config", Some(body)) => parse_put_machine_config(body),
            (Method::Put, "metrics", Some(body)) => parse_put_metrics(body),
            (Method::Put, "mmds", Some(body)) => parse_put_mmds(body, path_tokens.next()),
            (Method::Put, "network-interfaces", Some(body)) => {
                parse_put_net(body, path_tokens.next())
            }
            (Method::Put, "snapshot", Some(body)) => parse_put_snapshot(body, path_tokens.next()),
            (Method::Put, "vsock", Some(body)) => parse_put_vsock(body),
            (Method::Put, "entropy", Some(body)) => parse_put_entropy(body),
            (Method::Put, "hotplug", Some(body)) if path_tokens.next() == Some("memory") => {
                parse_put_memory_hotplug(body)
            }
            (Method::Put, _, None) => method_to_error(Method::Put),
            (Method::Patch, "balloon", body) => parse_patch_balloon(body, path_tokens),
            (Method::Patch, "drives", Some(body)) => parse_patch_drive(body, path_tokens.next()),
            (Method::Patch, "machine-config", Some(body)) => parse_patch_machine_config(body),
            (Method::Patch, "mmds", Some(body)) => parse_patch_mmds(body),
            (Method::Patch, "network-interfaces", Some(body)) => {
                parse_patch_net(body, path_tokens.next())
            }
            (Method::Patch, "pmem", Some(body)) => parse_patch_pmem(body, path_tokens.next()),
            (Method::Patch, "vm", Some(body)) => parse_patch_vm_state(body),
            (Method::Patch, "hotplug", Some(body)) if path_tokens.next() == Some("memory") => {
                parse_patch_memory_hotplug(body)
            }
            (Method::Patch, _, None) => method_to_error(Method::Patch),
            (Method::Delete, "drives", None) => {
                parse_unplug_device(VirtioDeviceType::Block, path_tokens.next())
            }
            (Method::Delete, "pmem", None) => {
                parse_unplug_device(VirtioDeviceType::Pmem, path_tokens.next())
            }
            (Method::Delete, "network-interfaces", None) => {
                parse_unplug_device(VirtioDeviceType::Net, path_tokens.next())
            }
            (Method::Delete, _, Some(_)) => method_to_error(Method::Delete),
            (method, unknown_uri, _) => Err(RequestError::InvalidPathMethod(
                unknown_uri.to_string(),
                method,
            )),
        }
    }
}

impl ParsedRequest {
    pub(crate) fn new(action: RequestAction) -> Self {
        Self {
            action,
            parsing_info: Default::default(),
        }
    }

    pub(crate) fn into_parts(self) -> (RequestAction, ParsingInfo) {
        (self.action, self.parsing_info)
    }

    pub(crate) fn parsing_info(&mut self) -> &mut ParsingInfo {
        &mut self.parsing_info
    }

    pub(crate) fn success_response_with_data<T>(body_data: &T) -> Response
    where
        T: ?Sized + Serialize + Debug,
    {
        info_unrestricted!("The request was executed successfully. Status code: 200 OK.");
        let mut response = Response::new(Version::Http11, StatusCode::OK);
        response.set_body(Body::new(serde_json::to_string(body_data).unwrap()));
        response
    }

    pub(crate) fn success_response_with_mmds_value(body_data: &Value) -> Response {
        info_unrestricted!("The request was executed successfully. Status code: 200 OK.");
        let mut response = Response::new(Version::Http11, StatusCode::OK);
        let body_str = match body_data {
            Value::Null => "{}".to_string(),
            _ => serde_json::to_string(body_data).unwrap(),
        };
        response.set_body(Body::new(body_str));
        response
    }

    pub(crate) fn convert_to_response(
        request_outcome: &Result<VmmData, VmmActionError>,
    ) -> Response {
        match request_outcome {
            Ok(vmm_data) => match vmm_data {
                VmmData::Empty => {
                    info_unrestricted!(
                        "The request was executed successfully. Status code: 204 No Content."
                    );
                    Response::new(Version::Http11, StatusCode::NoContent)
                }
                VmmData::MachineConfiguration(machine_config) => {
                    Self::success_response_with_data(machine_config)
                }
                VmmData::MmdsValue(value) => Self::success_response_with_mmds_value(value),
                VmmData::BalloonConfig(balloon_config) => {
                    Self::success_response_with_data(balloon_config)
                }
                VmmData::BalloonStats(stats) => Self::success_response_with_data(stats),
                VmmData::VirtioMemStatus(data) => Self::success_response_with_data(data),
                VmmData::HintingStatus(hinting_status) => {
                    Self::success_response_with_data(hinting_status)
                }
                VmmData::InstanceInformation(info) => Self::success_response_with_data(info),
                VmmData::VmmVersion(version) => Self::success_response_with_data(
                    &serde_json::json!({ "firecracker_version": version.as_str() }),
                ),
                VmmData::FullVmConfig(config) => Self::success_response_with_data(config),
            },
            Err(vmm_action_error) => {
                let mut response = match vmm_action_error {
                    VmmActionError::MmdsLimitExceeded(_err) => {
                        error_unrestricted!(
                            "Received Error. Status code: 413 Payload too large. Message: {}",
                            vmm_action_error
                        );
                        Response::new(Version::Http11, StatusCode::PayloadTooLarge)
                    }
                    _ => {
                        error_unrestricted!(
                            "Received Error. Status code: 400 Bad Request. Message: {}",
                            vmm_action_error
                        );
                        Response::new(Version::Http11, StatusCode::BadRequest)
                    }
                };
                response.set_body(Body::new(ApiServer::json_fault_message(
                    vmm_action_error.to_string(),
                )));
                response
            }
        }
    }

    /// Helper function to avoid boiler-plate code.
    pub(crate) fn new_sync(vmm_action: VmmAction) -> ParsedRequest {
        ParsedRequest::new(RequestAction::Sync(Box::new(vmm_action)))
    }
}

/// Helper function for metric-logging purposes on API requests.
///
/// # Arguments
///
/// * `method` - one of `GET`, `PATCH`, `PUT`
/// * `path` - path of the API request
/// * `body` - body of the API request
fn describe(method: Method, path: &str, body: Option<&Body>) -> String {
    match (path, body) {
        ("/mmds", Some(_)) | (_, None) => format!("{:?} request on {:?}", method, path),
        ("/cpu-config", Some(payload_value)) => {
            // If the log level is at Debug or higher, include the CPU template in
            // the log line.
            if log_enabled!(Level::Debug) {
                describe_with_body(method, path, payload_value)
            } else {
                format!(
                    "{:?} request on {:?}. To view the CPU template received by the API, \
                     configure log-level to DEBUG",
                    method, path
                )
            }
        }
        (_, Some(payload_value)) => describe_with_body(method, path, payload_value),
    }
}

fn describe_with_body(method: Method, path: &str, payload_value: &Body) -> String {
    format!(
        "{:?} request on {:?} with body {:?}",
        method,
        path,
        std::str::from_utf8(payload_value.body.as_slice())
            .unwrap_or("inconvertible to UTF-8")
            .to_string()
    )
}

/// Generates a `GenericError` for each request method.
pub(crate) fn method_to_error(method: Method) -> Result<ParsedRequest, RequestError> {
    match method {
        Method::Get => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "GET request cannot have a body.".to_string(),
        )),
        Method::Put => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Empty PUT request.".to_string(),
        )),
        Method::Patch => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Empty PATCH request.".to_string(),
        )),
        Method::Delete => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Empty Delete request.".to_string(),
        )),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestError {
    // The resource ID is empty.
    #[error("The ID cannot be empty.")]
    EmptyID,
    // A generic error, with a given status code and message to be turned into a fault message.
    #[error("{1}")]
    Generic(StatusCode, String),
    // The resource ID must only contain alphanumeric characters and '_'.
    #[error("API Resource IDs can only contain alphanumeric characters and underscores.")]
    InvalidID,
    // The HTTP method & request path combination is not valid.
    #[error("Invalid request method and/or path: {} {}.", .1.to_str(), .0)]
    InvalidPathMethod(String, Method),
    // An error occurred when deserializing the json body of a request.
    #[error("An error occurred when deserializing the json body of a request: {0}.")]
    SerdeJson(#[from] serde_json::Error),
}

// It's convenient to turn errors into HTTP responses directly.
impl From<RequestError> for Response {
    fn from(err: RequestError) -> Self {
        let msg = ApiServer::json_fault_message(format!("{}", err));
        match err {
            RequestError::Generic(status, _) => ApiServer::json_response(status, msg),
            RequestError::EmptyID
            | RequestError::InvalidID
            | RequestError::InvalidPathMethod(_, _)
            | RequestError::SerdeJson(_) => ApiServer::json_response(StatusCode::BadRequest, msg),
        }
    }
}

// This function is supposed to do id validation for requests.
pub(crate) fn checked_id(id: &str) -> Result<&str, RequestError> {
    // todo: are there any checks we want to do on id's?
    // not allow them to be empty strings maybe?
    // check: ensure string is not empty
    if id.is_empty() {
        return Err(RequestError::EmptyID);
    }
    // check: ensure string is alphanumeric
    if !id.chars().all(|c| c == '_' || c.is_alphanumeric()) {
        return Err(RequestError::InvalidID);
    }
    Ok(id)
}
