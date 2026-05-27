// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Threshold multisig authorization for Dusk principals.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::auth::{ActionEnvelope, AuthorizationManager, SignedAuthorization};
use crate::core::{error, CallContext, Principal, PrincipalKind};

/// Owner threshold type used by multisig policies.
pub type Threshold = u16;

/// Initialization config for a threshold multisig policy.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigConfig {
    /// Unique non-zero owners.
    pub owners: Vec<Principal>,
    /// Required number of distinct owners.
    pub threshold: Threshold,
}

/// Signed approvals submitted with a multisig-gated call.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigApprovals {
    /// Signed Moonlight/Phoenix approvals for the exact call envelope.
    pub approvals: Vec<SignedAuthorization>,
}

/// Dusk-native threshold multisig authorization policy.
///
/// The primitive is intentionally an action authorizer, not an EVM-style
/// arbitrary calldata executor. Composing contracts bind approvals to their own
/// `ActionEnvelope`, then execute the local state transition after this module
/// returns a threshold of distinct owner signers.
#[derive(Clone, Debug, Default)]
pub struct ThresholdMultisig {
    owners: BTreeSet<Principal>,
    threshold: Threshold,
}

impl ThresholdMultisig {
    /// Creates an uninitialized multisig policy.
    pub const fn new() -> Self {
        Self {
            owners: BTreeSet::new(),
            threshold: 0,
        }
    }

    /// Initializes the policy with unique owners and a non-zero threshold.
    pub fn init(&mut self, config: MultisigConfig) {
        if self.threshold != 0 || !self.owners.is_empty() {
            panic!("{}", error::ALREADY_INITIALIZED);
        }
        let owners = collect_owners(config.owners);
        validate_threshold(config.threshold, owners.len());
        self.owners = owners;
        self.threshold = config.threshold;
    }

    /// Returns all owners in stable order.
    pub fn owners(&self) -> Vec<Principal> {
        self.owners.iter().copied().collect()
    }

    /// Returns the number of owners.
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// Returns true when there are no owners configured.
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// Returns the current threshold.
    pub const fn threshold(&self) -> Threshold {
        self.threshold
    }

    /// Returns true when `principal` is an owner.
    pub fn is_owner(&self, principal: Principal) -> bool {
        self.owners.contains(&principal)
    }

    /// Verifies that the observed caller plus supplied signed approvals satisfy
    /// the threshold for a concrete call envelope.
    ///
    /// The method verifies every signed approval and all policy constraints
    /// before consuming any nonce/replay state. Rejected threshold, duplicate,
    /// unauthorized, expired, wrong-envelope, or bad-signature cases are
    /// therefore atomic with respect to signer nonces.
    pub fn authorize_action(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        approvals: &[SignedAuthorization],
        envelope: ActionEnvelope,
        now: u64,
    ) -> Vec<Principal> {
        let signers = self.verify_action(
            authorizations,
            context,
            approvals,
            envelope,
            now,
        );
        for approval in approvals {
            authorizations.consume_verified(approval);
        }
        signers
    }

    /// Verifies that the observed caller plus supplied signed approvals satisfy
    /// the threshold for a concrete call envelope without consuming nonce or
    /// replay state.
    pub fn verify_action(
        &self,
        authorizations: &AuthorizationManager,
        context: CallContext,
        approvals: &[SignedAuthorization],
        envelope: ActionEnvelope,
        now: u64,
    ) -> Vec<Principal> {
        self.assert_initialized();

        let mut signers = BTreeSet::new();
        if let Some(principal) = context.principal {
            match principal.kind() {
                PrincipalKind::Moonlight | PrincipalKind::Contract => {
                    if self.is_owner(principal) {
                        signers.insert(principal);
                    }
                }
                PrincipalKind::Phoenix => {}
            }
        }

        for approval in approvals {
            let principal =
                authorizations.verify_signed_action(approval, envelope, now);
            if !self.is_owner(principal) || !signers.insert(principal) {
                panic!("{}", error::UNAUTHORIZED);
            }
        }

        self.assert_threshold_count(signers.len());
        signers.iter().copied().collect()
    }

    /// Panics unless `signers` are a distinct threshold of current owners.
    pub fn assert_quorum(&self, signers: &[Principal]) {
        self.assert_initialized();
        let mut unique = BTreeSet::new();
        for signer in signers {
            if !self.is_owner(*signer) || !unique.insert(*signer) {
                panic!("{}", error::UNAUTHORIZED);
            }
        }
        self.assert_threshold_count(unique.len());
    }

    /// Adds an owner after a threshold of current owners has authorized it.
    pub fn add_owner(&mut self, signers: &[Principal], owner: Principal) {
        self.assert_quorum(signers);
        if owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        if !self.owners.insert(owner) {
            panic!("{}", error::INVALID_OWNER);
        }
    }

    /// Removes an owner and sets the threshold that should apply after removal.
    pub fn remove_owner(
        &mut self,
        signers: &[Principal],
        owner: Principal,
        new_threshold: Threshold,
    ) {
        self.assert_quorum(signers);
        let mut owners = self.owners.clone();
        if !owners.remove(&owner) {
            panic!("{}", error::INVALID_OWNER);
        }
        validate_threshold(new_threshold, owners.len());
        self.owners = owners;
        self.threshold = new_threshold;
    }

    /// Replaces one owner with another after threshold authorization.
    pub fn replace_owner(
        &mut self,
        signers: &[Principal],
        old_owner: Principal,
        new_owner: Principal,
    ) {
        self.assert_quorum(signers);
        if new_owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        let mut owners = self.owners.clone();
        if !owners.remove(&old_owner) || !owners.insert(new_owner) {
            panic!("{}", error::INVALID_OWNER);
        }
        self.owners = owners;
    }

    /// Changes the threshold after a threshold of current owners has authorized
    /// it.
    pub fn set_threshold(
        &mut self,
        signers: &[Principal],
        threshold: Threshold,
    ) {
        self.assert_quorum(signers);
        validate_threshold(threshold, self.owners.len());
        self.threshold = threshold;
    }

    fn assert_initialized(&self) {
        if self.threshold == 0 || self.owners.is_empty() {
            panic!("{}", error::NOT_INITIALIZED);
        }
    }

    fn assert_threshold_count(&self, count: usize) {
        if count < usize::from(self.threshold) {
            panic!("{}", error::UNAUTHORIZED);
        }
    }
}

fn collect_owners(owners: Vec<Principal>) -> BTreeSet<Principal> {
    let mut next = BTreeSet::new();
    for owner in owners {
        if owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        if !next.insert(owner) {
            panic!("{}", error::INVALID_OWNER);
        }
    }
    if next.is_empty() {
        panic!("{}", error::INVALID_OWNER);
    }
    next
}

fn validate_threshold(threshold: Threshold, owner_count: usize) {
    if threshold == 0 || usize::from(threshold) > owner_count {
        panic!("{}", error::INVALID_OWNER);
    }
}
