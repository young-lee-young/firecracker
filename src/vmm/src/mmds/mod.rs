// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// MMDS data store
pub mod data_store;
/// MMDS network stack
pub mod ns;
/// Defines the structures needed for saving/restoring MmdsNetworkStack.
pub mod persist;
mod token;
/// MMDS token headers
pub mod token_headers;

use std::sync::{Arc, Mutex};

use micro_http::{
    Body, HttpHeaderError, MediaType, Method, Request, RequestError, Response, StatusCode, Version,
};
use serde_json::{Map, Value};

use crate::logger::{IncMetric, METRICS};
use crate::mmds::data_store::{Mmds, MmdsDatastoreError as MmdsError, MmdsVersion, OutputFormat};
use crate::mmds::token::PATH_TO_TOKEN;
use crate::mmds::token_headers::{
    X_AWS_EC2_METADATA_TOKEN_HEADER, X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER,
    X_FORWARDED_FOR_HEADER, X_METADATA_TOKEN_HEADER, X_METADATA_TOKEN_TTL_SECONDS_HEADER,
    get_header_value_pair,
};

#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// MMDS token errors
pub enum VmmMmdsError {
    /// MMDS token not valid.
    InvalidToken,
    /// Invalid URI.
    InvalidURI,
    /// Not allowed HTTP method.
    MethodNotAllowed,
    /// No MMDS token provided. Use `X-metadata-token` or `X-aws-ec2-metadata-token` header to specify the session token.
    NoTokenProvided,
    /// Token time to live value not found. Use `X-metadata-token-ttl-seconds` or `X-aws-ec2-metadata-token-ttl-seconds` header to specify the token's lifetime.
    NoTtlProvided,
    /// Resource not found: {0}.
    ResourceNotFound(String),
}

impl From<MediaType> for OutputFormat {
    fn from(media_type: MediaType) -> Self {
        match media_type {
            MediaType::ApplicationJson => OutputFormat::Json,
            MediaType::PlainText => OutputFormat::Imds,
        }
    }
}

// Builds the `micro_http::Response` with a given HTTP version, status code, and body.
fn build_response(
    http_version: Version,
    status_code: StatusCode,
    content_type: MediaType,
    body: Body,
) -> Response {
    let mut response = Response::new(http_version, status_code);
    response.set_content_type(content_type);
    response.set_body(body);
    response
}

/// Patch provided JSON document (given as `serde_json::Value`) in-place with JSON Merge Patch
/// [RFC 7396](https://tools.ietf.org/html/rfc7396).
pub fn json_patch(target: &mut Value, patch: &Value) {
    if patch.is_object() {
        if !target.is_object() {
            // Replace target with a serde_json object so we can recursively copy patch values.
            *target = Value::Object(Map::new());
        }

        // This is safe since we make sure patch and target are objects beforehand.
        let doc = target.as_object_mut().unwrap();
        for (key, value) in patch.as_object().unwrap() {
            if value.is_null() {
                // If the value in the patch is null we remove the entry.
                doc.remove(key.as_str());
            } else {
                // Recursive call to update target document.
                // If `key` is not in the target document (it's a new field defined in `patch`)
                // insert a null placeholder and pass it as the new target
                // so we can insert new values recursively.
                json_patch(doc.entry(key.as_str()).or_insert(Value::Null), value);
            }
        }
    } else {
        *target = patch.clone();
    }
}

// Make the URI a correct JSON pointer value.
fn sanitize_uri(mut uri: String) -> String {
    let mut len = u32::MAX as usize;
    // Loop while the deduping decreases the sanitized len.
    // Each iteration will attempt to dedup "//".
    while uri.len() < len {
        len = uri.len();
        uri = uri.replace("//", "/");
    }

    uri
}

/// Build a response for `request` and return response based on MMDS version
pub fn convert_to_response(mmds: Arc<Mutex<Mmds>>, request: Request) -> Response {
    // Check URI is not empty
    let uri = request.uri().get_abs_path();
    if uri.is_empty() {
        return build_response(
            request.http_version(),
            StatusCode::BadRequest,
            MediaType::PlainText,
            Body::new(VmmMmdsError::InvalidURI.to_string()),
        );
    }

    let mut mmds_guard = mmds.lock().expect("Poisoned lock");

    // Allow only GET and PUT requests
    match request.method() {
        Method::Get => match mmds_guard.version() {
            MmdsVersion::V1 => respond_to_get_request_v1(&mmds_guard, request),
            MmdsVersion::V2 => respond_to_get_request_v2(&mmds_guard, request),
        },
        Method::Put => respond_to_put_request(&mut mmds_guard, request),
        _ => {
            let mut response = build_response(
                request.http_version(),
                StatusCode::MethodNotAllowed,
                MediaType::PlainText,
                Body::new(VmmMmdsError::MethodNotAllowed.to_string()),
            );
            response.allow_method(Method::Get);
            response.allow_method(Method::Put);
            response
        }
    }
}

fn respond_to_get_request_v1(mmds: &Mmds, request: Request) -> Response {
    match get_header_value_pair(
        request.headers.custom_entries(),
        &[X_METADATA_TOKEN_HEADER, X_AWS_EC2_METADATA_TOKEN_HEADER],
    ) {
        Some((_, token)) => {
            if !mmds.is_valid_token(token) {
                METRICS.mmds.rx_invalid_token.inc();
            }
        }
        None => {
            METRICS.mmds.rx_no_token.inc();
        }
    }

    respond_to_get_request(mmds, request)
}

fn respond_to_get_request_v2(mmds: &Mmds, request: Request) -> Response {
    // Check whether a token exists.
    let token = match get_header_value_pair(
        request.headers.custom_entries(),
        &[X_METADATA_TOKEN_HEADER, X_AWS_EC2_METADATA_TOKEN_HEADER],
    ) {
        Some((_, token)) => token,
        None => {
            METRICS.mmds.rx_no_token.inc();
            let error_msg = VmmMmdsError::NoTokenProvided.to_string();
            return build_response(
                request.http_version(),
                StatusCode::Unauthorized,
                MediaType::PlainText,
                Body::new(error_msg),
            );
        }
    };

    // Validate the token.
    match mmds.is_valid_token(token) {
        true => respond_to_get_request(mmds, request),
        false => {
            METRICS.mmds.rx_invalid_token.inc();
            build_response(
                request.http_version(),
                StatusCode::Unauthorized,
                MediaType::PlainText,
                Body::new(VmmMmdsError::InvalidToken.to_string()),
            )
        }
    }
}

fn respond_to_get_request(mmds: &Mmds, request: Request) -> Response {
    let uri = request.uri().get_abs_path();

    // The data store expects a strict json path, so we need to
    // sanitize the URI.
    let json_path = sanitize_uri(uri.to_string());

    let content_type = request.headers.accept();

    match mmds.get_value(json_path, content_type.into()) {
        Ok(response_body) => build_response(
            request.http_version(),
            StatusCode::OK,
            content_type,
            Body::new(response_body),
        ),
        Err(err) => match err {
            MmdsError::NotFound => {
                let error_msg = VmmMmdsError::ResourceNotFound(String::from(uri)).to_string();
                build_response(
                    request.http_version(),
                    StatusCode::NotFound,
                    MediaType::PlainText,
                    Body::new(error_msg),
                )
            }
            MmdsError::UnsupportedValueType => build_response(
                request.http_version(),
                StatusCode::NotImplemented,
                MediaType::PlainText,
                Body::new(err.to_string()),
            ),
            MmdsError::DataStoreLimitExceeded => build_response(
                request.http_version(),
                StatusCode::PayloadTooLarge,
                MediaType::PlainText,
                Body::new(err.to_string()),
            ),
            _ => unreachable!(),
        },
    }
}

fn respond_to_put_request(mmds: &mut Mmds, request: Request) -> Response {
    let custom_headers = request.headers.custom_entries();

    // Reject `PUT` requests that contain `X-Forwarded-For` header.
    if let Some((header, _)) = get_header_value_pair(custom_headers, &[X_FORWARDED_FOR_HEADER]) {
        let error_msg =
            RequestError::HeaderError(HttpHeaderError::UnsupportedName(header.to_string()))
                .to_string();
        return build_response(
            request.http_version(),
            StatusCode::BadRequest,
            MediaType::PlainText,
            Body::new(error_msg),
        );
    }

    let uri = request.uri().get_abs_path();
    // Sanitize the URI into a strict json path.
    let json_path = sanitize_uri(uri.to_string());

    // Only accept PUT requests towards TOKEN_PATH.
    if json_path != PATH_TO_TOKEN {
        let error_msg = VmmMmdsError::ResourceNotFound(String::from(uri)).to_string();
        return build_response(
            request.http_version(),
            StatusCode::NotFound,
            MediaType::PlainText,
            Body::new(error_msg),
        );
    }

    // Get token lifetime value.
    let (header, ttl_seconds) = match get_header_value_pair(
        custom_headers,
        &[
            X_METADATA_TOKEN_TTL_SECONDS_HEADER,
            X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER,
        ],
    ) {
        // Header found
        Some((header, value)) => match value.parse::<u32>() {
            Ok(ttl_seconds) => (header, ttl_seconds),
            Err(_) => {
                return build_response(
                    request.http_version(),
                    StatusCode::BadRequest,
                    MediaType::PlainText,
                    Body::new(
                        RequestError::HeaderError(HttpHeaderError::InvalidValue(
                            header.into(),
                            value.into(),
                        ))
                        .to_string(),
                    ),
                );
            }
        },
        // Header not found
        None => {
            return build_response(
                request.http_version(),
                StatusCode::BadRequest,
                MediaType::PlainText,
                Body::new(VmmMmdsError::NoTtlProvided.to_string()),
            );
        }
    };

    // Generate token.
    let result = mmds.generate_token(ttl_seconds);
    match result {
        Ok(token) => {
            let mut response = build_response(
                request.http_version(),
                StatusCode::OK,
                MediaType::PlainText,
                Body::new(token),
            );
            let custom_headers = [(header.into(), ttl_seconds.to_string())].into();
            // Safe to unwrap because the header name and the value are valid as US-ASCII.
            // - `header` is either `X_METADATA_TOKEN_TTL_SECONDS_HEADER` or
            //   `X_AWS_EC2_METADATA_TOKEN_SSL_SECONDS_HEADER`.
            // - `ttl_seconds` is a decimal number between `MIN_TOKEN_TTL_SECONDS` and
            //   `MAX_TOKEN_TTL_SECONDS`.
            response.set_custom_headers(&custom_headers).unwrap();
            response
        }
        Err(err) => build_response(
            request.http_version(),
            StatusCode::BadRequest,
            MediaType::PlainText,
            Body::new(err.to_string()),
        ),
    }
}

