//! Ownership primitives.

use crate::auth::{
    ActionEnvelope, AuthorizationManager, Authorizer, SignedAuthorization,
};
use crate::core::{error, CallContext, Principal};

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
    pub fn authorize_owner(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        now: u64,
    ) -> Principal {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_owner_with(&mut authorizer, authorization)
    }

    /// Authorizes the owner with a reusable call authorizer.
    pub fn authorize_owner_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
    ) -> Principal {
        let owner = self
            .owner
            .unwrap_or_else(|| panic!("{}", error::NOT_INITIALIZED));
        authorizer.require_principal(owner, authorization)
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
    ) -> Principal {
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
    ) -> Principal {
        let owner = self
            .owner
            .unwrap_or_else(|| panic!("{}", error::NOT_INITIALIZED));
        authorizer.require_principal_action(owner, authorization, envelope)
    }

    /// Transfers ownership.
    pub fn transfer_ownership(
        &mut self,
        caller: Principal,
        new_owner: Principal,
    ) {
        self.assert_owner(caller);
        if new_owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        self.owner = Some(new_owner);
    }

    /// Renounces ownership.
    pub fn renounce_ownership(&mut self, caller: Principal) {
        self.assert_owner(caller);
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
    ) -> Principal {
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
    ) -> Principal {
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
    ) -> Principal {
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
    ) -> Principal {
        self.ownable.authorize_owner_action_with(
            authorizer,
            authorization,
            envelope,
        )
    }

    /// Starts ownership transfer.
    pub fn transfer_ownership(
        &mut self,
        caller: Principal,
        new_owner: Principal,
    ) {
        self.ownable.assert_owner(caller);
        if new_owner.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        self.pending_owner = Some(new_owner);
    }

    /// Accepts ownership transfer.
    pub fn accept_ownership(&mut self, caller: Principal) {
        if self.pending_owner != Some(caller) {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.ownable.owner = Some(caller);
        self.pending_owner = None;
    }

    /// Renounces ownership.
    pub fn renounce_ownership(&mut self, caller: Principal) {
        self.ownable.renounce_ownership(caller);
        self.pending_owner = None;
    }
}
