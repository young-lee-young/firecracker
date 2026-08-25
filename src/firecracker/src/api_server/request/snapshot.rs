// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::de::Error as DeserializeError;
use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::snapshot::{
    CreateSnapshotParams, LoadSnapshotConfig, LoadSnapshotParams, MemBackendConfig, MemBackendType,
    Vm, VmState,
};

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::super::request::{Body, Method, StatusCode};

/// Deprecation message for the `mem_file_path` field.
const LOAD_DEPRECATION_MESSAGE: &str =
    "PUT /snapshot/load: mem_file_path and enable_diff_snapshots fields are deprecated.";
/// None of the `mem_backend` or `mem_file_path` fields has been specified.
pub const MISSING_FIELD: &str =
    "missing field: either `mem_backend` or `mem_file_path` is required";
/// Both the `mem_backend` and `mem_file_path` fields have been specified.
/// Only specifying one of them is allowed.
pub const TOO_MANY_FIELDS: &str =
    "too many fields: either `mem_backend` or `mem_file_path` exclusively is required";

pub(crate) fn parse_put_snapshot(
    body: &Body,
    request_type_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    match request_type_from_path {
        Some(request_type) => match request_type {
            "create" => parse_put_snapshot_create(body),
            "load" => parse_put_snapshot_load(body),
            _ => Err(RequestError::InvalidPathMethod(
                format!("/snapshot/{}", request_type),
                Method::Put,
            )),
        },
        None => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Missing snapshot operation type.".to_string(),
        )),
    }
}

pub(crate) fn parse_patch_vm_state(body: &Body) -> Result<ParsedRequest, RequestError> {
    let vm = serde_json::from_slice::<Vm>(body.raw())?;

    match vm.state {
        VmState::Paused => Ok(ParsedRequest::new_sync(VmmAction::Pause)),
        VmState::Resumed => Ok(ParsedRequest::new_sync(VmmAction::Resume)),
    }
}

fn parse_put_snapshot_create(body: &Body) -> Result<ParsedRequest, RequestError> {
    let snapshot_config = serde_json::from_slice::<CreateSnapshotParams>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::CreateSnapshot(
        snapshot_config,
    )))
}

fn parse_put_snapshot_load(body: &Body) -> Result<ParsedRequest, RequestError> {
    let snapshot_config = serde_json::from_slice::<LoadSnapshotConfig>(body.raw())?;

    match (&snapshot_config.mem_backend, &snapshot_config.mem_file_path) {
        // Ensure `mem_file_path` and `mem_backend` fields are not present at the same time.
        (Some(_), Some(_)) => {
            return Err(RequestError::SerdeJson(serde_json::Error::custom(
                TOO_MANY_FIELDS,
            )));
        }
        // Ensure that one of `mem_file_path` or `mem_backend` fields is always specified.
        (None, None) => {
            return Err(RequestError::SerdeJson(serde_json::Error::custom(
                MISSING_FIELD,
            )));
        }
        _ => {}
    }

    // Check for the presence of deprecated `mem_file_path` field and create
    // deprecation message if found.
    let mut deprecation_message = None;
    #[allow(deprecated)]
    if snapshot_config.mem_file_path.is_some() || snapshot_config.enable_diff_snapshots {
        // `mem_file_path` field in request is deprecated.
        METRICS.deprecated_api.deprecated_http_api_calls.inc();
        deprecation_message = Some(LOAD_DEPRECATION_MESSAGE);
    }

    // If `mem_file_path` is specified instead of `mem_backend`, we construct the
    // `MemBackendConfig` object from the path specified, with `File` as backend type.
    let mem_backend = match snapshot_config.mem_backend {
        Some(backend_cfg) => backend_cfg,
        None => {
            MemBackendConfig {
                // This is safe to unwrap() because we ensure above that one of the two:
                // either `mem_file_path` or `mem_backend` field is always specified.
                backend_path: snapshot_config.mem_file_path.unwrap(),
                backend_type: MemBackendType::File,
            }
        }
    };

    let snapshot_params = LoadSnapshotParams {
        snapshot_path: snapshot_config.snapshot_path,
        mem_backend,
        #[allow(deprecated)]
        track_dirty_pages: snapshot_config.enable_diff_snapshots
            || snapshot_config.track_dirty_pages,
        resume_vm: snapshot_config.resume_vm,
        network_overrides: snapshot_config.network_overrides,
        vsock_override: snapshot_config.vsock_override,
        clock_realtime: snapshot_config.clock_realtime,
    };

    // Construct the `ParsedRequest` object.
    let mut parsed_req = ParsedRequest::new_sync(VmmAction::LoadSnapshot(snapshot_params));

    // If `mem_file_path` was present, set the deprecation message in `parsing_info`.
    if let Some(msg) = deprecation_message {
        parsed_req.parsing_info().append_deprecation_message(msg);
    }

    Ok(parsed_req)
}
