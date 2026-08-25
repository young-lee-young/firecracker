// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::Body;
use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::memory_hotplug::{MemoryHotplugConfig, MemoryHotplugSizeUpdate};

use crate::api_server::parsed_request::{ParsedRequest, RequestError};

pub(crate) fn parse_put_memory_hotplug(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.hotplug_memory_count.inc();
    let config = serde_json::from_slice::<MemoryHotplugConfig>(body.raw()).inspect_err(|_| {
        METRICS.put_api_requests.hotplug_memory_fails.inc();
    })?;
    Ok(ParsedRequest::new_sync(VmmAction::SetMemoryHotplugDevice(
        config,
    )))
}

pub(crate) fn parse_get_memory_hotplug() -> Result<ParsedRequest, RequestError> {
    METRICS.get_api_requests.hotplug_memory_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetMemoryHotplugStatus))
}

pub(crate) fn parse_patch_memory_hotplug(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.patch_api_requests.hotplug_memory_count.inc();
    let config =
        serde_json::from_slice::<MemoryHotplugSizeUpdate>(body.raw()).inspect_err(|_| {
            METRICS.patch_api_requests.hotplug_memory_fails.inc();
        })?;
    Ok(ParsedRequest::new_sync(VmmAction::UpdateMemoryHotplugSize(
        config,
    )))
}
