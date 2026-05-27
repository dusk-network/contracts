// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Optional DRC721 royalty policy helper.

use alloc::collections::BTreeMap;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::{error, Principal};
use crate::token::drc721::ZERO_PRINCIPAL;

/// Maximum royalty basis points.
pub const MAX_BASIS_POINTS: u16 = 10_000;

/// Royalty policy for a token or collection.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct RoyaltyInfo {
    /// Receiver principal.
    pub receiver: Principal,
    /// Royalty fraction in basis points.
    pub basis_points: u16,
}

/// Royalty quote for a sale price.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct RoyaltyQuote {
    /// Receiver principal, or zero principal when no royalty exists.
    pub receiver: Principal,
    /// Royalty amount.
    pub amount: u64,
}

/// Royalty quote query.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct RoyaltyQuery {
    /// Token id.
    pub token_id: u64,
    /// Sale price used for royalty calculation.
    pub sale_price: u64,
}

/// Default plus token-specific royalty registry.
#[derive(Clone, Debug, Default)]
pub struct RoyaltyRegistry {
    default: Option<RoyaltyInfo>,
    token_overrides: BTreeMap<u64, RoyaltyInfo>,
}

impl RoyaltyRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            default: None,
            token_overrides: BTreeMap::new(),
        }
    }

    /// Returns default royalty policy.
    pub const fn default_royalty(&self) -> Option<RoyaltyInfo> {
        self.default
    }

    /// Returns token royalty policy, falling back to default.
    pub fn royalty_for(&self, token_id: u64) -> Option<RoyaltyInfo> {
        self.token_overrides
            .get(&token_id)
            .copied()
            .or(self.default)
    }

    /// Sets default royalty.
    pub fn set_default_royalty(&mut self, info: RoyaltyInfo) {
        validate(info);
        self.default = Some(info);
    }

    /// Clears default royalty.
    pub fn clear_default_royalty(&mut self) {
        self.default = None;
    }

    /// Sets token-specific royalty.
    pub fn set_token_royalty(&mut self, token_id: u64, info: RoyaltyInfo) {
        validate(info);
        self.token_overrides.insert(token_id, info);
    }

    /// Clears token-specific royalty.
    pub fn clear_token_royalty(&mut self, token_id: u64) {
        self.token_overrides.remove(&token_id);
    }

    /// Returns a royalty quote for `sale_price`.
    pub fn royalty_info(&self, token_id: u64, sale_price: u64) -> RoyaltyQuote {
        let Some(info) = self.royalty_for(token_id) else {
            return RoyaltyQuote {
                receiver: ZERO_PRINCIPAL,
                amount: 0,
            };
        };
        let amount = sale_price
            .checked_mul(u64::from(info.basis_points))
            .expect(error::OVERFLOW)
            / u64::from(MAX_BASIS_POINTS);
        RoyaltyQuote {
            receiver: info.receiver,
            amount,
        }
    }
}

fn validate(info: RoyaltyInfo) {
    if info.receiver.is_zero() {
        panic!("{}", error::ZERO_PRINCIPAL);
    }
    if info.basis_points > MAX_BASIS_POINTS {
        panic!("DRC721: royalty exceeds sale price");
    }
}
