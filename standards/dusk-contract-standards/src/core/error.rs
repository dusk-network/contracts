// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Stable error strings used by the reusable primitives.

pub const ALREADY_INITIALIZED: &str = "DuskStandards: already initialized";
pub const NOT_INITIALIZED: &str = "DuskStandards: not initialized";
pub const UNAUTHORIZED: &str = "DuskStandards: unauthorized";
pub const INVALID_OWNER: &str = "DuskStandards: invalid owner";
pub const ZERO_PRINCIPAL: &str = "DuskStandards: zero principal";
pub const REPLAY: &str = "DuskStandards: replay";
pub const INVALID_NONCE: &str = "DuskStandards: invalid nonce";
pub const OPERATION_UNKNOWN: &str = "DuskStandards: operation unknown";
pub const INVALID_OPERATION: &str = "DuskStandards: invalid operation";
pub const EXPIRED: &str = "DuskStandards: expired";
pub const REENTRANCY: &str = "DuskStandards: reentrant call";
pub const OVERFLOW: &str = "DuskStandards: arithmetic overflow";
pub const UNDERFLOW: &str = "DuskStandards: arithmetic underflow";
pub const DRC20_ALLOWANCE_BELOW_ZERO: &str = "DRC20: allowance below zero";
pub const DRC20_ALLOWANCE_TOO_LOW: &str = "DRC20: allowance too low";
pub const DRC20_BALANCE_TOO_LOW: &str = "DRC20: balance too low";
pub const DRC20_CAP_BELOW_CURRENT_SUPPLY: &str =
    "DRC20: cap below current supply";
pub const DRC20_CAP_EXCEEDED: &str = "DRC20: cap exceeded";
pub const CHECKPOINTS_NON_MONOTONIC_KEY: &str =
    "Checkpoints: non-monotonic key";
pub const VOTING_UNITS_INSUFFICIENT_UNITS: &str =
    "VotingUnits: insufficient units";
pub const VOTING_UNITS_TOTAL_SUPPLY_UNDERFLOW: &str =
    "VotingUnits: total supply underflow";
