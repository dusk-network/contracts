// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Events emitted by the `MultiSigV2`-contract.

use alloc::{string::String, vec::Vec};

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use dusk_core::signatures::bls::PublicKey;

use super::OpId;

/// Event emitted when an operation is proposed, confirmed, removed or
/// executing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize,
)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MultisigOperation {
    /// The operation ID.
    pub id: OpId,

    /// The public key of the admin that triggered the event.
    pub from: PublicKey,
}

impl MultisigOperation {
    /// Event topic used when an operation is proposed for confirmation.
    pub const PROPOSED: &'static str = "op_proposed";
    /// Event topic used when an operation is confirmed by an admin.
    pub const CONFIRMED: &'static str = "op_confirmed";
    /// Event topic used when an operation is being executed.
    pub const EXECUTING: &'static str = "op_executing";
    /// Event topic used when a pending operation is removed.
    pub const REMOVED: &'static str = "op_removed";
}

/// Event emitted when the operation has been executed.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecutionResult {
    /// The operation ID.
    pub id: OpId,

    /// Error message if the operation failed, or `None` on success.
    pub error: Option<String>,
}

impl ExecutionResult {
    /// Event topic used when an operation has been executed.
    pub const EXECUTED: &'static str = "op_executed";
}

/// Event emitted when the admins are updated.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdateAuthority {
    /// The previous public keys stored in the `MultiSigV2`.
    pub prev_admins: Vec<PublicKey>,
    /// The previous admin threshold.
    pub prev_admin_threshold: u8,
    /// The previous proposal threshold.
    pub prev_threshold: u8,

    /// The new public keys stored in the `MultiSigV2`.
    pub new_admins: Vec<PublicKey>,
    /// The new admin threshold.
    pub new_admin_threshold: u8,
    /// The new proposal threshold.
    pub new_threshold: u8,
}

impl UpdateAuthority {
    /// Event topic used when the admins have been updated.
    pub const TOPIC: &'static str = "update_authority";
}

/// Event emitted when the time parameters are updated.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdateTimeLimits {
    /// The previous proposal TTL in blocks.
    pub prev_proposal_ttl_blocks: u64,
    /// The previous replay window in blocks.
    pub prev_replay_window_blocks: u64,
    /// The new proposal TTL in blocks.
    pub proposal_ttl_blocks: u64,
    /// The new replay window in blocks.
    pub replay_window_blocks: u64,
}

impl UpdateTimeLimits {
    /// Event topic used when the time params are updated.
    pub const TOPIC: &'static str = "update_time_params";
}
