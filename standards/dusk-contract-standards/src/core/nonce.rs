// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Monotonic nonce management for replay-protected authorizations.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::{error, Principal};

/// Domain separator for a nonce stream.
///
/// A contract can keep independent streams for permits, role delegations,
/// Phoenix signature authorizations, upgrade approvals, or any other signed
/// flow.
pub type NonceDomain = [u8; 32];

/// Monotonic nonces keyed by `(principal, domain)`.
#[derive(Clone, Debug, Default)]
pub struct NonceManager {
    nonces: BTreeMap<(Principal, NonceDomain), u64>,
}

/// Portable nonce snapshot entry for migration or tests.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct NonceEntry {
    /// Principal owning this nonce stream.
    pub principal: Principal,
    /// Stream domain.
    pub domain: NonceDomain,
    /// Current nonce.
    pub nonce: u64,
}

/// Nonce query shared by reference contracts and clients.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct NonceQuery {
    /// Principal owning this nonce stream.
    pub principal: Principal,
    /// Stream domain.
    pub domain: NonceDomain,
}

impl NonceManager {
    /// Creates an empty nonce manager.
    pub const fn new() -> Self {
        Self {
            nonces: BTreeMap::new(),
        }
    }

    /// Returns the current nonce.
    pub fn current(&self, principal: Principal, domain: NonceDomain) -> u64 {
        self.nonces.get(&(principal, domain)).copied().unwrap_or(0)
    }

    /// Consumes exactly `expected` and increments the stream.
    pub fn consume(
        &mut self,
        principal: Principal,
        domain: NonceDomain,
        expected: u64,
    ) -> u64 {
        let current = self.current(principal, domain);
        if current != expected {
            panic!("{}", error::INVALID_NONCE);
        }
        let next = current.checked_add(1).expect(error::OVERFLOW);
        self.nonces.insert((principal, domain), next);
        next
    }

    /// Consumes the current nonce and returns the consumed value.
    pub fn use_next(
        &mut self,
        principal: Principal,
        domain: NonceDomain,
    ) -> u64 {
        let current = self.current(principal, domain);
        self.consume(principal, domain, current);
        current
    }

    /// Invalidates all nonces below `new_nonce`.
    pub fn invalidate_until(
        &mut self,
        principal: Principal,
        domain: NonceDomain,
        new_nonce: u64,
    ) {
        if new_nonce < self.current(principal, domain) {
            panic!("{}", error::INVALID_NONCE);
        }
        self.nonces.insert((principal, domain), new_nonce);
    }

    /// Exports all nonce streams.
    pub fn entries(&self) -> Vec<NonceEntry> {
        self.nonces
            .iter()
            .map(|((principal, domain), nonce)| NonceEntry {
                principal: *principal,
                domain: *domain,
                nonce: *nonce,
            })
            .collect()
    }

    /// Imports nonce streams, keeping the greatest value for duplicates.
    pub fn import_entries(
        &mut self,
        entries: impl IntoIterator<Item = NonceEntry>,
    ) {
        for entry in entries {
            let current = self.current(entry.principal, entry.domain);
            if entry.nonce > current {
                self.nonces
                    .insert((entry.principal, entry.domain), entry.nonce);
            }
        }
    }
}
