// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Role-based access control.

use alloc::collections::{BTreeMap, BTreeSet};

use crate::auth::{
    ActionEnvelope, AuthorizationManager, Authorizer, SignedAuthorization,
};
use crate::core::{error, CallContext, Principal};

/// 32-byte role id.
pub type Role = [u8; 32];

/// Default admin role.
pub const DEFAULT_ADMIN_ROLE: Role = [0u8; 32];

#[derive(Clone, Debug)]
struct RoleData {
    members: BTreeSet<Principal>,
    admin_role: Role,
}

impl RoleData {
    fn new(admin_role: Role) -> Self {
        Self {
            members: BTreeSet::new(),
            admin_role,
        }
    }
}

/// Role-based access-control module.
#[derive(Clone, Debug, Default)]
pub struct AccessControl {
    roles: BTreeMap<Role, RoleData>,
}

impl AccessControl {
    /// Creates an empty access-control module.
    pub const fn new() -> Self {
        Self {
            roles: BTreeMap::new(),
        }
    }

    /// Bootstraps the default admin role.
    pub fn init_admin(&mut self, admin: Principal) {
        if admin.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        if self.roles.contains_key(&DEFAULT_ADMIN_ROLE) {
            panic!("{}", error::ALREADY_INITIALIZED);
        }
        self.roles
            .entry(DEFAULT_ADMIN_ROLE)
            .or_insert_with(|| RoleData::new(DEFAULT_ADMIN_ROLE))
            .members
            .insert(admin);
    }

    /// Returns true when `account` has `role`.
    pub fn has_role(&self, role: Role, account: Principal) -> bool {
        self.roles
            .get(&role)
            .map(|data| data.members.contains(&account))
            .unwrap_or(false)
    }

    /// Panics unless `account` has `role`.
    pub fn assert_role(&self, role: Role, account: Principal) {
        if !self.has_role(role, account) {
            panic!("{}", error::UNAUTHORIZED);
        }
    }

    /// Authorizes any principal with `role` through runtime context or signed
    /// authorization.
    pub fn authorize_role(
        &self,
        role: Role,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        now: u64,
    ) -> Principal {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_role_with(role, &mut authorizer, authorization)
    }

    /// Authorizes any principal with `role` using a reusable call authorizer.
    pub fn authorize_role_with(
        &self,
        role: Role,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
    ) -> Principal {
        if let Some(principal) = authorizer.observed_principal() {
            if self.has_role(role, principal) {
                return principal;
            }
        }
        let Some(authorization) = authorization else {
            panic!("{}", error::UNAUTHORIZED);
        };
        authorizer.require_signed_if(authorization, |principal| {
            self.has_role(role, principal)
        })
    }

    /// Authorizes any principal with `role` through runtime context or an
    /// action-bound signed authorization.
    pub fn authorize_role_action(
        &self,
        role: Role,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
        now: u64,
    ) -> Principal {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_role_action_with(
            role,
            &mut authorizer,
            authorization,
            envelope,
        )
    }

    /// Authorizes any principal with `role` using a reusable call authorizer
    /// and exact call envelope for signed fallbacks.
    pub fn authorize_role_action_with(
        &self,
        role: Role,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
    ) -> Principal {
        if let Some(principal) = authorizer.observed_principal() {
            if self.has_role(role, principal) {
                return principal;
            }
        }
        let Some(authorization) = authorization else {
            panic!("{}", error::UNAUTHORIZED);
        };
        authorizer.require_signed_action_if(
            authorization,
            envelope,
            |principal| self.has_role(role, principal),
        )
    }

    /// Returns a role's admin role.
    pub fn get_role_admin(&self, role: Role) -> Role {
        self.roles
            .get(&role)
            .map(|data| data.admin_role)
            .unwrap_or(DEFAULT_ADMIN_ROLE)
    }

    /// Sets a role's admin role. Caller must have the current admin role.
    pub fn set_role_admin(
        &mut self,
        caller: Principal,
        role: Role,
        admin_role: Role,
    ) {
        let current_admin = self.get_role_admin(role);
        self.assert_role(current_admin, caller);
        self.roles
            .entry(role)
            .or_insert_with(|| RoleData::new(DEFAULT_ADMIN_ROLE))
            .admin_role = admin_role;
    }

    /// Grants `role` to `account`. Caller must have the role admin.
    pub fn grant_role(
        &mut self,
        caller: Principal,
        role: Role,
        account: Principal,
    ) {
        if account.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        let admin = self.get_role_admin(role);
        self.assert_role(admin, caller);
        self.roles
            .entry(role)
            .or_insert_with(|| RoleData::new(DEFAULT_ADMIN_ROLE))
            .members
            .insert(account);
    }

    /// Revokes `role` from `account`. Caller must have the role admin.
    pub fn revoke_role(
        &mut self,
        caller: Principal,
        role: Role,
        account: Principal,
    ) {
        let admin = self.get_role_admin(role);
        self.assert_role(admin, caller);
        if let Some(data) = self.roles.get_mut(&role) {
            data.members.remove(&account);
        }
    }

    /// Renounces `role` from `caller`.
    pub fn renounce_role(&mut self, role: Role, caller: Principal) {
        if let Some(data) = self.roles.get_mut(&role) {
            data.members.remove(&caller);
        }
    }
}
