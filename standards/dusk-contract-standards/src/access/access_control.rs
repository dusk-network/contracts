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
use crate::core::{error, CallContext, Principal, PrincipalKind};

/// 32-byte role id.
pub type Role = [u8; 32];

/// Default admin role.
pub const DEFAULT_ADMIN_ROLE: Role = [0u8; 32];

/// Fresh role authorization witness.
///
/// This type is minted by role authorization helpers after runtime-context or
/// signature verification. Role mutators accept this witness instead of a raw
/// public principal so wrappers cannot accidentally trust caller-supplied
/// identity data.
///
/// The witness carries only the verified role and principal. Public contract
/// methods should mint it freshly for the exact operation being executed, and
/// should prefer the action-bound authorization helpers when accepting signed
/// fallbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleAuthorization {
    role: Role,
    principal: Principal,
}

impl RoleAuthorization {
    pub(crate) const fn new(role: Role, principal: Principal) -> Self {
        Self { role, principal }
    }

    /// Returns the authorized role.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns the authorized principal.
    pub const fn principal(&self) -> Principal {
        self.principal
    }
}

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
        self.init_admin_with_roles(admin, core::iter::empty::<Role>());
    }

    /// Bootstraps the default admin role and seeds additional initial roles.
    ///
    /// This is intended for contract initialization only. It keeps initial role
    /// seeding inside the same one-time initialization gate as the default
    /// admin, while regular role changes still require a fresh authorization
    /// witness.
    pub fn init_admin_with_roles(
        &mut self,
        admin: Principal,
        roles: impl IntoIterator<Item = Role>,
    ) {
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
        for role in roles {
            self.roles
                .entry(role)
                .or_insert_with(|| RoleData::new(DEFAULT_ADMIN_ROLE))
                .members
                .insert(admin);
        }
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
    ///
    /// Signed fallbacks are not checked against a call envelope. Prefer
    /// [`Self::authorize_role_action`] in public contract methods.
    pub fn authorize_role(
        &self,
        role: Role,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        now: u64,
    ) -> RoleAuthorization {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_role_with(role, &mut authorizer, authorization)
    }

    /// Authorizes any principal with `role` using a reusable call authorizer.
    ///
    /// Signed fallbacks are not checked against a call envelope. Prefer
    /// [`Self::authorize_role_action_with`] in public contract methods.
    pub fn authorize_role_with(
        &self,
        role: Role,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
    ) -> RoleAuthorization {
        if let Some(principal) = authorizer.observed_principal() {
            match principal.kind() {
                PrincipalKind::Moonlight | PrincipalKind::Contract => {
                    if self.has_role(role, principal) {
                        return RoleAuthorization::new(role, principal);
                    }
                }
                PrincipalKind::Phoenix => {}
            }
        }
        let Some(authorization) = authorization else {
            panic!("{}", error::UNAUTHORIZED);
        };
        RoleAuthorization::new(
            role,
            authorizer.require_unbound_signed_if(authorization, |principal| {
                self.has_role(role, principal)
            }),
        )
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
    ) -> RoleAuthorization {
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
    ) -> RoleAuthorization {
        if let Some(principal) = authorizer.observed_principal() {
            match principal.kind() {
                PrincipalKind::Moonlight | PrincipalKind::Contract => {
                    if self.has_role(role, principal) {
                        return RoleAuthorization::new(role, principal);
                    }
                }
                PrincipalKind::Phoenix => {}
            }
        }
        let Some(authorization) = authorization else {
            panic!("{}", error::UNAUTHORIZED);
        };
        RoleAuthorization::new(
            role,
            authorizer.require_signed_action_if(
                authorization,
                envelope,
                |principal| self.has_role(role, principal),
            ),
        )
    }

    /// Returns a role's admin role.
    pub fn get_role_admin(&self, role: Role) -> Role {
        self.roles
            .get(&role)
            .map(|data| data.admin_role)
            .unwrap_or(DEFAULT_ADMIN_ROLE)
    }

    /// Sets a role's admin role after the current admin role freshly
    /// authorizes this exact change.
    pub fn set_role_admin(
        &mut self,
        authorization: RoleAuthorization,
        role: Role,
        admin_role: Role,
    ) {
        let current_admin = self.get_role_admin(role);
        self.assert_authorized_role(&authorization, current_admin);
        self.roles
            .entry(role)
            .or_insert_with(|| RoleData::new(DEFAULT_ADMIN_ROLE))
            .admin_role = admin_role;
    }

    /// Grants `role` to `account` after the role admin freshly authorizes this
    /// exact grant.
    pub fn grant_role(
        &mut self,
        authorization: RoleAuthorization,
        role: Role,
        account: Principal,
    ) {
        if account.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        let admin = self.get_role_admin(role);
        self.assert_authorized_role(&authorization, admin);
        self.roles
            .entry(role)
            .or_insert_with(|| RoleData::new(DEFAULT_ADMIN_ROLE))
            .members
            .insert(account);
    }

    /// Revokes `role` from `account` after the role admin freshly authorizes
    /// this exact revoke.
    pub fn revoke_role(
        &mut self,
        authorization: RoleAuthorization,
        role: Role,
        account: Principal,
    ) {
        let admin = self.get_role_admin(role);
        self.assert_authorized_role(&authorization, admin);
        if let Some(data) = self.roles.get_mut(&role) {
            data.members.remove(&account);
        }
    }

    /// Renounces `role` after that role holder freshly authorizes this exact
    /// renouncement.
    pub fn renounce_role(
        &mut self,
        role: Role,
        authorization: RoleAuthorization,
    ) {
        self.assert_authorized_role(&authorization, role);
        if let Some(data) = self.roles.get_mut(&role) {
            data.members.remove(&authorization.principal());
        }
    }

    fn assert_authorized_role(
        &self,
        authorization: &RoleAuthorization,
        role: Role,
    ) {
        if authorization.role() != role
            || !self.has_role(role, authorization.principal())
        {
            panic!("{}", error::UNAUTHORIZED);
        }
    }
}
