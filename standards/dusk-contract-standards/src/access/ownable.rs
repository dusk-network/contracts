// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Ownership primitives.

use crate::auth::{
    ActionEnvelope, AuthorizationManager, Authorizer, SignedAuthorization,
};
use crate::core::{error, CallContext, Principal};

/// Fresh owner authorization witness.
///
/// This type is minted by owner authorization helpers after runtime-context or
/// signature verification. Mutating owner APIs accept this witness instead of a
/// raw public principal so downstream wrappers cannot accidentally trust
/// caller-supplied identity data.
///
/// The witness carries only the verified principal. Public contract methods
/// should mint it freshly for the exact operation being executed, and should
/// prefer the action-bound authorization helpers when accepting signed
/// fallbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerAuthorization {
    principal: Principal,
}

impl OwnerAuthorization {
    pub(crate) const fn new(principal: Principal) -> Self {
        Self { principal }
    }

    /// Returns the authorized owner principal.
    pub const fn principal(&self) -> Principal {
        self.principal
    }
}

/// Single-owner access control.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ownable {
    owner: Option<Principal>,
}

impl Ownable {
    /// Creates an uninitialized owner module.
    pub const fn new() -> Self {
        Self { owner: None }
    }

    /// Initializes ownership.
    pub fn init(&mut self, owner: Principal) {
        if self.owner.is_some() {
            panic!("{}", error::ALREADY_INITIALIZED);
        }
        if owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        self.owner = Some(owner);
    }

    /// Returns the current owner.
    pub const fn owner(&self) -> Option<Principal> {
        self.owner
    }

    /// Returns true when `caller` is the owner.
    pub fn is_owner(&self, caller: Principal) -> bool {
        self.owner == Some(caller)
    }

    /// Panics unless `caller` is the owner.
    pub fn assert_owner(&self, caller: Principal) {
        if !self.is_owner(caller) {
            panic!("{}", error::UNAUTHORIZED);
        }
    }

    /// Authorizes the owner through runtime context or signed authorization.
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

    /// Authorizes the owner with a reusable call authorizer.
    ///
    /// Signed fallbacks are not checked against a call envelope. Prefer
    /// [`Self::authorize_owner_action_with`] in public contract methods.
    pub fn authorize_owner_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
    ) -> OwnerAuthorization {
        let owner = self
            .owner
            .unwrap_or_else(|| panic!("{}", error::NOT_INITIALIZED));
        OwnerAuthorization {
            principal: authorizer
                .require_principal_unbound(owner, authorization),
        }
    }

    /// Authorizes the owner through runtime context or an action-bound signed
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

    /// Authorizes the owner with a reusable call authorizer and exact call
    /// envelope for signed fallbacks.
    pub fn authorize_owner_action_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
    ) -> OwnerAuthorization {
        let owner = self
            .owner
            .unwrap_or_else(|| panic!("{}", error::NOT_INITIALIZED));
        OwnerAuthorization {
            principal: authorizer.require_principal_action(
                owner,
                authorization,
                envelope,
            ),
        }
    }

    /// Transfers ownership after a freshly verified owner authorizes this exact
    /// transfer.
    pub fn transfer_ownership(
        &mut self,
        authorization: OwnerAuthorization,
        new_owner: Principal,
    ) {
        self.assert_owner(authorization.principal());
        if new_owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        self.owner = Some(new_owner);
    }

    /// Renounces ownership after the current owner freshly authorizes this
    /// exact renouncement.
    pub fn renounce_ownership(&mut self, authorization: OwnerAuthorization) {
        self.assert_owner(authorization.principal());
        self.owner = None;
    }
}

/// Two-step ownership transfer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ownable2Step {
    ownable: Ownable,
    pending_owner: Option<Principal>,
}

impl Ownable2Step {
    /// Creates an uninitialized module.
    pub const fn new() -> Self {
        Self {
            ownable: Ownable::new(),
            pending_owner: None,
        }
    }

    /// Initializes ownership.
    pub fn init(&mut self, owner: Principal) {
        self.ownable.init(owner);
    }

    /// Returns the current owner.
    pub const fn owner(&self) -> Option<Principal> {
        self.ownable.owner()
    }

    /// Returns the pending owner.
    pub const fn pending_owner(&self) -> Option<Principal> {
        self.pending_owner
    }

    /// Panics unless `caller` is the owner.
    pub fn assert_owner(&self, caller: Principal) {
        self.ownable.assert_owner(caller);
    }

    /// Authorizes the owner through runtime context or signed authorization.
    pub fn authorize_owner(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        now: u64,
    ) -> OwnerAuthorization {
        self.ownable.authorize_owner(
            authorizations,
            context,
            authorization,
            now,
        )
    }

    /// Authorizes the owner with a reusable call authorizer.
    pub fn authorize_owner_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
    ) -> OwnerAuthorization {
        self.ownable.authorize_owner_with(authorizer, authorization)
    }

    /// Authorizes the owner through runtime context or an action-bound signed
    /// authorization.
    pub fn authorize_owner_action(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
        now: u64,
    ) -> OwnerAuthorization {
        self.ownable.authorize_owner_action(
            authorizations,
            context,
            authorization,
            envelope,
            now,
        )
    }

    /// Authorizes the owner with a reusable call authorizer and exact call
    /// envelope for signed fallbacks.
    pub fn authorize_owner_action_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
    ) -> OwnerAuthorization {
        self.ownable.authorize_owner_action_with(
            authorizer,
            authorization,
            envelope,
        )
    }

    /// Authorizes the pending owner through runtime context or signed
    /// authorization.
    ///
    /// Signed fallbacks are not checked against a call envelope. Prefer
    /// [`Self::authorize_pending_owner_action`] in public contract methods.
    pub fn authorize_pending_owner(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        now: u64,
    ) -> OwnerAuthorization {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_pending_owner_with(&mut authorizer, authorization)
    }

    /// Authorizes the pending owner with a reusable call authorizer.
    ///
    /// Signed fallbacks are not checked against a call envelope. Prefer
    /// [`Self::authorize_pending_owner_action_with`] in public contract
    /// methods.
    pub fn authorize_pending_owner_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
    ) -> OwnerAuthorization {
        let pending_owner = self
            .pending_owner
            .unwrap_or_else(|| panic!("{}", error::NOT_INITIALIZED));
        OwnerAuthorization::new(
            authorizer.require_principal_unbound(pending_owner, authorization),
        )
    }

    /// Authorizes the pending owner through runtime context or an action-bound
    /// signed authorization.
    pub fn authorize_pending_owner_action(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
        now: u64,
    ) -> OwnerAuthorization {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_pending_owner_action_with(
            &mut authorizer,
            authorization,
            envelope,
        )
    }

    /// Authorizes the pending owner with a reusable call authorizer and exact
    /// call envelope for signed fallbacks.
    pub fn authorize_pending_owner_action_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
    ) -> OwnerAuthorization {
        let pending_owner = self
            .pending_owner
            .unwrap_or_else(|| panic!("{}", error::NOT_INITIALIZED));
        OwnerAuthorization::new(authorizer.require_principal_action(
            pending_owner,
            authorization,
            envelope,
        ))
    }

    /// Starts ownership transfer after the current owner freshly authorizes
    /// this exact pending-owner change.
    pub fn transfer_ownership(
        &mut self,
        authorization: OwnerAuthorization,
        new_owner: Principal,
    ) {
        self.ownable.assert_owner(authorization.principal());
        if new_owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        self.pending_owner = Some(new_owner);
    }

    /// Accepts ownership transfer after the pending owner freshly authorizes
    /// this exact acceptance.
    pub fn accept_ownership(&mut self, authorization: OwnerAuthorization) {
        let caller = authorization.principal();
        if self.pending_owner != Some(caller) {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.ownable.owner = Some(caller);
        self.pending_owner = None;
    }

    /// Renounces ownership after the current owner freshly authorizes this
    /// exact renouncement.
    pub fn renounce_ownership(&mut self, authorization: OwnerAuthorization) {
        self.ownable.renounce_ownership(authorization);
        self.pending_owner = None;
    }
}
