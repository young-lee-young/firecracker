// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module with types used for custom CPU templates
pub mod templates;
/// Module with ser/de utils for custom CPU templates
pub mod templates_serde;

/// Module containing type implementations needed for x86 CPU configuration
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
