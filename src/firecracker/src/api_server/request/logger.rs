// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_logger(body: &Body) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.logger_count.inc();
    let res = serde_json::from_slice::<vmm::logger::LoggerConfig>(body.raw());
    let config = res.inspect_err(|_| {
        METRICS.put_api_requests.logger_fails.inc();
    })?;
    Ok(ParsedRequest::new_sync(VmmAction::ConfigureLogger(config)))
}
