// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::{Method, StatusCode};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::balloon::{
    BalloonDeviceConfig, BalloonUpdateConfig, BalloonUpdateStatsConfig,
};

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;
use crate::api_server::parsed_request::method_to_error;

fn parse_get_hinting<'a, T>(mut path_tokens: T) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match path_tokens.next() {
        Some("status") => Ok(ParsedRequest::new_sync(VmmAction::GetFreePageHintingStatus)),
        Some(stats_path) => Err(RequestError::Generic(
            StatusCode::BadRequest,
            format!("Unrecognized GET request path `/hinting/{stats_path}`."),
        )),
        None => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Unrecognized GET request path `/hinting/`.".to_string(),
        )),
    }
}

pub(crate) fn parse_get_balloon<'a, T>(mut path_tokens: T) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match path_tokens.next() {
        Some("statistics") => Ok(ParsedRequest::new_sync(VmmAction::GetBalloonStats)),
        Some("hinting") => parse_get_hinting(path_tokens),
        Some(stats_path) => Err(RequestError::Generic(
            StatusCode::BadRequest,
            format!("Unrecognized GET request path `{}`.", stats_path),
        )),
        None => Ok(ParsedRequest::new_sync(VmmAction::GetBalloonConfig)),
    }
}

pub(crate) fn parse_put_balloon(body: &Body) -> Result<ParsedRequest, RequestError> {
    Ok(ParsedRequest::new_sync(VmmAction::SetBalloonDevice(
        serde_json::from_slice::<BalloonDeviceConfig>(body.raw())?,
    )))
}

fn parse_patch_hinting<'a, T>(
    body: Option<&Body>,
    mut path_tokens: T,
) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match path_tokens.next() {
        Some("start") => {
            let cmd = match body {
                None => Default::default(),
                Some(b) if b.is_empty() => Default::default(),
                Some(b) => serde_json::from_slice(b.raw())?,
            };

            Ok(ParsedRequest::new_sync(VmmAction::StartFreePageHinting(
                cmd,
            )))
        }
        Some("stop") => Ok(ParsedRequest::new_sync(VmmAction::StopFreePageHinting)),
        Some(stats_path) => Err(RequestError::Generic(
            StatusCode::BadRequest,
            format!("Unrecognized PATCH request path `/hinting/{stats_path}`."),
        )),
        None => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Unrecognized PATCH request path `/hinting/`.".to_string(),
        )),
    }
}

pub(crate) fn parse_patch_balloon<'a, T>(
    body: Option<&Body>,
    mut path_tokens: T,
) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match (path_tokens.next(), body) {
        (Some("statistics"), Some(body)) => {
            Ok(ParsedRequest::new_sync(VmmAction::UpdateBalloonStatistics(
                serde_json::from_slice::<BalloonUpdateStatsConfig>(body.raw())?,
            )))
        }
        (Some("hinting"), body) => parse_patch_hinting(body, path_tokens),
        (_, Some(body)) => Ok(ParsedRequest::new_sync(VmmAction::UpdateBalloon(
            serde_json::from_slice::<BalloonUpdateConfig>(body.raw())?,
        ))),
        (_, None) => method_to_error(Method::Patch),
    }
}
