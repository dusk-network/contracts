// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! DRC721 rkyv-compatible call types.

use alloc::string::String;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::auth::SignedAuthorization;
use crate::core::Principal;

/// Initial token.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct InitToken {
    /// Owner.
    pub account: Principal,
    /// Token id.
    pub token_id: u64,
}

/// Initialization input.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Init {
    /// Name.
    pub name: String,
    /// Symbol.
    pub symbol: String,
    /// Base URI.
    pub base_uri: String,
    /// Initial tokens.
    pub initial_tokens: Vec<InitToken>,
}

/// Balance query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct BalanceOf {
    /// Account.
    pub account: Principal,
}

/// Owner query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct OwnerOf {
    /// Token id.
    pub token_id: u64,
}

/// URI query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TokenUri {
    /// Token id.
    pub token_id: u64,
}

/// Token by global index query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TokenByIndex {
    /// Zero-based index.
    pub index: u64,
}

/// Token by owner index query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TokenOfOwnerByIndex {
    /// Owner.
    pub owner: Principal,
    /// Zero-based owner-local index.
    pub index: u64,
}

/// Tokens owned by an account query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TokensOf {
    /// Owner.
    pub owner: Principal,
}

/// Approved query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct GetApproved {
    /// Token id.
    pub token_id: u64,
}

/// Operator approval query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct IsApprovedForAll {
    /// Owner.
    pub owner: Principal,
    /// Operator.
    pub operator: Principal,
}

/// Approve call.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ApproveCall {
    /// Approved account.
    pub approved: Principal,
    /// Token id.
    pub token_id: u64,
}

/// Operator approval call.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SetApprovalForAllCall {
    /// Operator.
    pub operator: Principal,
    /// Approval.
    pub approved: bool,
}

/// Signed token approval call for Moonlight/Phoenix owner authorization.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SignedApproveCall {
    /// Token owner. Must match the signed action principal and current owner.
    pub owner: Principal,
    /// Approved account.
    pub approved: Principal,
    /// Token id.
    pub token_id: u64,
    /// Replay-protected authorization for this approval payload.
    pub authorization: SignedAuthorization,
}

/// Signed operator approval call for Moonlight/Phoenix owner authorization.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SignedSetApprovalForAllCall {
    /// Token owner. Must match the signed action principal.
    pub owner: Principal,
    /// Operator.
    pub operator: Principal,
    /// Approval.
    pub approved: bool,
    /// Replay-protected authorization for this approval payload.
    pub authorization: SignedAuthorization,
}

/// Transfer call.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TransferFromCall {
    /// Current owner.
    pub from: Principal,
    /// Recipient.
    pub to: Principal,
    /// Token id.
    pub token_id: u64,
}
