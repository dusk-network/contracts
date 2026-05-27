// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! DRC721 event payloads.

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::Principal;

/// Transfer event topic.
pub const TRANSFER_TOPIC: &str = "drc721/transfer";
/// Approval event topic.
pub const APPROVAL_TOPIC: &str = "drc721/approval";
/// Approval-for-all event topic.
pub const APPROVAL_FOR_ALL_TOPIC: &str = "drc721/approval_for_all";
/// Default royalty set event topic.
pub const DEFAULT_ROYALTY_SET_TOPIC: &str = "drc721/default_royalty_set";
/// Default royalty cleared event topic.
pub const DEFAULT_ROYALTY_CLEARED_TOPIC: &str =
    "drc721/default_royalty_cleared";
/// Token royalty set event topic.
pub const TOKEN_ROYALTY_SET_TOPIC: &str = "drc721/token_royalty_set";
/// Token royalty cleared event topic.
pub const TOKEN_ROYALTY_CLEARED_TOPIC: &str = "drc721/token_royalty_cleared";

/// Transfer event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Transfer {
    /// Sender.
    pub from: Principal,
    /// Recipient.
    pub to: Principal,
    /// Token id.
    pub token_id: u64,
}

/// Approval event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Approval {
    /// Owner.
    pub owner: Principal,
    /// Approved account.
    pub approved: Principal,
    /// Token id.
    pub token_id: u64,
}

/// Approval-for-all event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ApprovalForAll {
    /// Owner.
    pub owner: Principal,
    /// Operator.
    pub operator: Principal,
    /// Approval.
    pub approved: bool,
}

/// Default royalty set event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct DefaultRoyaltySet {
    /// Principal that authorized the royalty change.
    pub operator: Principal,
    /// Royalty receiver.
    pub receiver: Principal,
    /// Royalty basis points.
    pub basis_points: u16,
}

/// Default royalty cleared event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct DefaultRoyaltyCleared {
    /// Principal that authorized the royalty change.
    pub operator: Principal,
}

/// Token royalty set event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TokenRoyaltySet {
    /// Principal that authorized the royalty change.
    pub operator: Principal,
    /// Token id.
    pub token_id: u64,
    /// Royalty receiver.
    pub receiver: Principal,
    /// Royalty basis points.
    pub basis_points: u16,
}

/// Token royalty cleared event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TokenRoyaltyCleared {
    /// Principal that authorized the royalty change.
    pub operator: Principal,
    /// Token id.
    pub token_id: u64,
}

impl dusk_forge::ContractEvent for Transfer {
    const TOPICS: &'static [&'static str] = &[TRANSFER_TOPIC];
}

impl dusk_forge::ContractEvent for Approval {
    const TOPICS: &'static [&'static str] = &[APPROVAL_TOPIC];
}

impl dusk_forge::ContractEvent for ApprovalForAll {
    const TOPICS: &'static [&'static str] = &[APPROVAL_FOR_ALL_TOPIC];
}

impl dusk_forge::ContractEvent for DefaultRoyaltySet {
    const TOPICS: &'static [&'static str] = &[DEFAULT_ROYALTY_SET_TOPIC];
}

impl dusk_forge::ContractEvent for DefaultRoyaltyCleared {
    const TOPICS: &'static [&'static str] = &[DEFAULT_ROYALTY_CLEARED_TOPIC];
}

impl dusk_forge::ContractEvent for TokenRoyaltySet {
    const TOPICS: &'static [&'static str] = &[TOKEN_ROYALTY_SET_TOPIC];
}

impl dusk_forge::ContractEvent for TokenRoyaltyCleared {
    const TOPICS: &'static [&'static str] = &[TOKEN_ROYALTY_CLEARED_TOPIC];
}
