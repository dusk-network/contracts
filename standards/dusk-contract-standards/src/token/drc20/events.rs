// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! DRC20 event payloads.

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::Principal;

/// Transfer event topic.
pub const TRANSFER_TOPIC: &str = "drc20/transfer";
/// Approval event topic.
pub const APPROVAL_TOPIC: &str = "drc20/approval";

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
    /// Amount.
    pub amount: u64,
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
    /// Spender.
    pub spender: Principal,
    /// Amount.
    pub amount: u64,
}

impl dusk_forge::ContractEvent for Transfer {
    const TOPICS: &'static [&'static str] = &[TRANSFER_TOPIC];
}

impl dusk_forge::ContractEvent for Approval {
    const TOPICS: &'static [&'static str] = &[APPROVAL_TOPIC];
}
