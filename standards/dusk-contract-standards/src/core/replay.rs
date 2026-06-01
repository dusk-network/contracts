// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Replay protection for signed authorizations.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::error;
use crate::core::principal::Principal;

/// Replay key supplied by an authorization flow.
pub type ReplayKey = [u8; 32];

/// Tracks consumed replay keys per principal.
#[derive(Clone, Debug, Default)]
pub struct ReplayGuard {
    used: BTreeSet<(Principal, ReplayKey)>,
}

/// Portable snapshot entry for migration or tests.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ReplayEntry {
    /// Principal that consumed the key.
    pub principal: Principal,
    /// Consumed key.
    pub key: ReplayKey,
}

impl ReplayGuard {
    /// Creates an empty replay guard.
    pub const fn new() -> Self {
        Self {
            used: BTreeSet::new(),
        }
    }

    /// Returns whether a key has been consumed.
    pub fn is_used(&self, principal: Principal, key: ReplayKey) -> bool {
        self.used.contains(&(principal, key))
    }

    /// Consumes a replay key or panics when it was already used.
    pub fn consume(&mut self, principal: Principal, key: ReplayKey) {
        if !self.used.insert((principal, key)) {
            panic!("{}", error::REPLAY);
        }
    }

    /// Exports all entries for migration or inspection.
    pub fn entries(&self) -> Vec<ReplayEntry> {
        self.used
            .iter()
            .map(|(principal, key)| ReplayEntry {
                principal: *principal,
                key: *key,
            })
            .collect()
    }

    /// Imports entries; duplicates are deduplicated by the set, not rejected.
    pub fn import_entries(
        &mut self,
        entries: impl IntoIterator<Item = ReplayEntry>,
    ) {
        for entry in entries {
            self.used.insert((entry.principal, entry.key));
        }
    }
}
