// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Multi-principal ownership.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::access::OwnerAuthorization;
use crate::auth::{
    ActionEnvelope, AuthorizationManager, Authorizer, SignedAuthorization,
};
use crate::core::{error, CallContext, Principal, PrincipalKind};

/// Owner registry for contracts that need Moonlight, Phoenix, and contract
/// identities to coexist in one authorization policy.
#[derive(Clone, Debug, Default)]
pub struct OwnerSet {
    owners: BTreeSet<Principal>,
}

impl OwnerSet {
    /// Creates an empty owner set.
    pub const fn new() -> Self {
        Self {
            owners: BTreeSet::new(),
        }
    }

    /// Initializes with at least one owner.
    pub fn init(&mut self, owners: impl IntoIterator<Item = Principal>) {
        if !self.owners.is_empty() {
            panic!("{}", error::ALREADY_INITIALIZED);
        }
        let mut next = BTreeSet::new();
        for owner in owners {
            if owner.is_zero() {
                panic!("{}", error::ZERO_PRINCIPAL);
            }
            next.insert(owner);
        }
        if next.is_empty() {
            panic!("{}", error::INVALID_OWNER);
        }
        self.owners = next;
    }

    /// Returns true when `principal` is an owner.
    pub fn is_owner(&self, principal: Principal) -> bool {
        self.owners.contains(&principal)
    }

    /// Panics unless `principal` is an owner.
    pub fn assert_owner(&self, principal: Principal) {
        if !self.is_owner(principal) {
            panic!("{}", error::UNAUTHORIZED);
        }
    }

    /// Authorizes any owner through runtime context or signed authorization.
    ///
    /// Signed fallbacks are not checked against a call envelope. Prefer
    /// [`Self::authorize_owner_action`] in public contract methods.
    pub fn authorize_owner(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        now: u64,
    ) -> OwnerAuthorization {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_owner_with(&mut authorizer, authorization)
    }

    /// Authorizes any owner with a reusable call authorizer.
    ///
    /// Signed fallbacks are not checked against a call envelope. Prefer
    /// [`Self::authorize_owner_action_with`] in public contract methods.
    pub fn authorize_owner_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
    ) -> OwnerAuthorization {
        if let Some(principal) = authorizer.observed_principal() {
            match principal.kind() {
                PrincipalKind::Moonlight | PrincipalKind::Contract => {
                    if self.is_owner(principal) {
                        return OwnerAuthorization::new(principal);
                    }
                }
                PrincipalKind::Phoenix => {}
            }
        }
        let Some(authorization) = authorization else {
            panic!("{}", error::UNAUTHORIZED);
        };
        OwnerAuthorization::new(
            authorizer.require_unbound_signed_if(authorization, |principal| {
                self.is_owner(principal)
            }),
        )
    }

    /// Authorizes any owner through runtime context or an action-bound signed
    /// authorization.
    pub fn authorize_owner_action(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
        now: u64,
    ) -> OwnerAuthorization {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_owner_action_with(
            &mut authorizer,
            authorization,
            envelope,
        )
    }

    /// Authorizes any owner with a reusable call authorizer and exact call
    /// envelope for signed fallbacks.
    pub fn authorize_owner_action_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
    ) -> OwnerAuthorization {
        if let Some(principal) = authorizer.observed_principal() {
            match principal.kind() {
                PrincipalKind::Moonlight | PrincipalKind::Contract => {
                    if self.is_owner(principal) {
                        return OwnerAuthorization::new(principal);
                    }
                }
                PrincipalKind::Phoenix => {}
            }
        }
        let Some(authorization) = authorization else {
            panic!("{}", error::UNAUTHORIZED);
        };
        OwnerAuthorization::new(authorizer.require_signed_action_if(
            authorization,
            envelope,
            |principal| self.is_owner(principal),
        ))
    }

    /// Returns all owners in stable order.
    pub fn owners(&self) -> Vec<Principal> {
        self.owners.iter().copied().collect()
    }

    /// Returns the number of owners.
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// Returns true when no owners are configured.
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// Counts owners of a given principal kind.
    pub fn count_kind(&self, kind: PrincipalKind) -> usize {
        self.owners
            .iter()
            .filter(|principal| principal.kind() == kind)
            .count()
    }

    /// Adds an owner after an existing owner freshly authorizes this exact
    /// addition.
    pub fn add_owner(
        &mut self,
        authorization: OwnerAuthorization,
        new_owner: Principal,
    ) {
        self.assert_owner(authorization.principal());
        self.add_initial_owner(new_owner);
    }

    /// Removes an owner after an existing owner freshly authorizes this exact
    /// removal.
    ///
    /// The last owner cannot be removed.
    pub fn remove_owner(
        &mut self,
        authorization: OwnerAuthorization,
        owner: Principal,
    ) {
        self.assert_owner(authorization.principal());
        if !self.owners.contains(&owner) {
            panic!("{}", error::INVALID_OWNER);
        }
        if self.owners.len() == 1 {
            panic!("{}", error::INVALID_OWNER);
        }
        self.owners.remove(&owner);
    }

    /// Replaces one owner with another after an existing owner freshly
    /// authorizes this exact replacement.
    pub fn replace_owner(
        &mut self,
        authorization: OwnerAuthorization,
        old_owner: Principal,
        new_owner: Principal,
    ) {
        self.assert_owner(authorization.principal());
        if new_owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        if !self.owners.contains(&old_owner) {
            panic!("{}", error::INVALID_OWNER);
        }
        if old_owner != new_owner && self.owners.contains(&new_owner) {
            panic!("{}", error::INVALID_OWNER);
        }
        self.owners.remove(&old_owner);
        self.owners.insert(new_owner);
    }

    fn add_initial_owner(&mut self, owner: Principal) {
        if owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        self.owners.insert(owner);
    }
}
