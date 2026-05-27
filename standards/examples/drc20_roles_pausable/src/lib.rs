// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Example DRC20 composed from reusable Dusk contract standards modules.

#![no_std]
#![cfg(target_family = "wasm")]

extern crate alloc;
extern crate self as drc20_roles_pausable_types;

use bytecheck::CheckBytes;
use dusk_contract_standards::access::Role;
use dusk_contract_standards::auth::SignedAuthorization;
use dusk_contract_standards::core::{NonceDomain, Principal};
use dusk_contract_standards::token::drc20::Init as TokenInit;
use rkyv::{Archive, Deserialize, Serialize};

pub const TOKEN_ADMIN_DOMAIN: NonceDomain = [11u8; 32];
pub const SIGNED_APPROVE_DOMAIN: NonceDomain = [12u8; 32];
pub const MINT_ACTION: [u8; 32] = [13u8; 32];
pub const PAUSE_ACTION: [u8; 32] = [14u8; 32];
pub const UNPAUSE_ACTION: [u8; 32] = [15u8; 32];
pub const GRANT_ROLE_ACTION: [u8; 32] = [16u8; 32];
pub const REVOKE_ROLE_ACTION: [u8; 32] = [17u8; 32];
pub const SIGNED_APPROVE_ACTION: [u8; 32] = [18u8; 32];

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Init {
    pub admin: Principal,
    pub token: TokenInit,
    /// Optional max supply. A value of zero means uncapped.
    pub cap: u64,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MintCall {
    pub to: Principal,
    pub amount: u64,
    pub authorization: Option<SignedAuthorization>,
}

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct RoleQuery {
    pub role: Role,
    pub account: Principal,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct RoleCall {
    pub role: Role,
    pub account: Principal,
    pub authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct AdminCall {
    pub authorization: Option<SignedAuthorization>,
}

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct VotesQuery {
    pub account: Principal,
    pub timepoint: u64,
}

#[dusk_forge::contract(events = [
    Drc20Transfer,
    Drc20Approval,
    Paused,
    Unpaused,
    RoleGranted,
    RoleRevoked,
])]
mod drc20_roles_pausable {
    use alloc::string::String;
    use alloc::vec::Vec;

    use drc20_roles_pausable_types::{
        AdminCall, Init, MintCall, RoleCall, RoleQuery, VotesQuery,
        GRANT_ROLE_ACTION, MINT_ACTION, PAUSE_ACTION, REVOKE_ROLE_ACTION,
        SIGNED_APPROVE_ACTION, SIGNED_APPROVE_DOMAIN, TOKEN_ADMIN_DOMAIN,
        UNPAUSE_ACTION,
    };
    use dusk_contract_standards::access::events::{
        Paused, RoleGranted, RoleRevoked, Unpaused, PAUSED_TOPIC,
        ROLE_GRANTED_TOPIC, ROLE_REVOKED_TOPIC, UNPAUSED_TOPIC,
    };
    use dusk_contract_standards::access::{AccessControl, Pausable, Role};
    use dusk_contract_standards::auth::{
        ActionEnvelope, AuthorizationManager, SignedAuthorization,
    };
    use dusk_contract_standards::core::{
        error, CallContext, NonceQuery, Principal,
    };
    use dusk_contract_standards::security::ReentrancyGuard;
    use dusk_contract_standards::token::drc20::events::{
        Approval as Drc20Approval, Transfer as Drc20Transfer, APPROVAL_TOPIC,
        TRANSFER_TOPIC,
    };
    use dusk_contract_standards::token::drc20::{
        Allowance, ApproveCall, BalanceOf, DecreaseAllowanceCall, Drc20,
        IncreaseAllowanceCall, SignedApproveCall, SupplyCap, TransferCall,
        TransferFromCall, VotingUnits,
    };
    use dusk_core::abi;

    const MINTER_ROLE: Role = [1u8; 32];
    const PAUSER_ROLE: Role = [2u8; 32];

    pub struct Drc20RolesPausable {
        token: Drc20,
        access: AccessControl,
        authorizations: AuthorizationManager,
        pausable: Pausable,
        guard: ReentrancyGuard,
        cap: Option<SupplyCap>,
        votes: VotingUnits,
    }

    impl Drc20RolesPausable {
        pub const fn new() -> Self {
            Self {
                token: Drc20::new(),
                access: AccessControl::new(),
                authorizations: AuthorizationManager::new(),
                pausable: Pausable::new(),
                guard: ReentrancyGuard::new(),
                cap: None,
                votes: VotingUnits::new(),
            }
        }
        pub fn init(&mut self, args: Init) {
            if args.admin.is_zero() {
                panic!("{}", error::ZERO_PRINCIPAL);
            }
            let mut initial_supply = 0u64;
            for balance in &args.token.initial_balances {
                if balance.account.is_zero() {
                    panic!("{}", error::ZERO_PRINCIPAL);
                }
                initial_supply = initial_supply
                    .checked_add(balance.amount)
                    .expect(error::OVERFLOW);
            }
            if args.cap != 0 {
                SupplyCap::new(args.cap).assert_mint(0, initial_supply);
            }

            let initial_balances = args.token.initial_balances.clone();
            let events = self.token.init(args.token);
            self.access.init_admin(args.admin);
            self.access.grant_role(args.admin, MINTER_ROLE, args.admin);
            self.access.grant_role(args.admin, PAUSER_ROLE, args.admin);
            for event in events {
                Self::emit_transfer(event);
            }
            if args.cap != 0 {
                let cap = SupplyCap::new(args.cap);
                self.cap = Some(cap);
            }
            for balance in initial_balances {
                self.votes.move_units(
                    None,
                    Some(balance.account),
                    balance.amount,
                    now(),
                );
            }
        }

        pub fn name(&self) -> String {
            self.token.name()
        }

        pub fn symbol(&self) -> String {
            self.token.symbol()
        }

        pub fn decimals(&self) -> u8 {
            self.token.decimals()
        }

        pub fn total_supply(&self) -> u64 {
            self.token.total_supply()
        }

        pub fn balance_of(&self, args: BalanceOf) -> u64 {
            self.token.balance_of(args)
        }

        pub fn allowance(&self, args: Allowance) -> u64 {
            self.token.allowance(args)
        }

        pub fn nonce(&self, args: NonceQuery) -> u64 {
            self.authorizations.nonce(args.principal, args.domain)
        }

        pub fn cap(&self) -> u64 {
            self.cap.map(|cap| cap.cap()).unwrap_or(0)
        }

        pub fn remaining_mintable(&self) -> u64 {
            self.cap
                .map(|cap| cap.remaining(self.token.total_supply()))
                .unwrap_or(u64::MAX)
        }

        pub fn latest_votes(&self, account: Principal) -> u64 {
            self.votes.latest_votes(account)
        }

        pub fn past_votes(&self, args: VotesQuery) -> u64 {
            self.votes.past_votes(args.account, args.timepoint)
        }

        pub fn latest_total_votes(&self) -> u64 {
            self.votes.latest_total_supply()
        }

        pub fn past_total_supply(&self, timepoint: u64) -> u64 {
            self.votes.past_total_supply(timepoint)
        }

        pub fn has_role(&self, args: RoleQuery) -> bool {
            self.access.has_role(args.role, args.account)
        }
        pub fn transfer(&mut self, args: TransferCall) {
            self.pausable.assert_not_paused();
            let caller = caller();
            let event = {
                let guard = &mut self.guard;
                let token = &mut self.token;
                let votes = &mut self.votes;
                guard.run(|| {
                    let event = token.transfer(caller, args);
                    votes.move_units(
                        Some(event.from),
                        Some(event.to),
                        event.amount,
                        now(),
                    );
                    event
                })
            };
            Self::emit_transfer(event);
        }
        pub fn approve(&mut self, args: ApproveCall) {
            let caller = caller();
            let event = self.token.approve(caller, args);
            Self::emit_approval(event);
        }
        pub fn approve_by_authorization(&mut self, args: SignedApproveCall) {
            let principal = self.authorizations.authorize_signed_action(
                &args.authorization,
                ActionEnvelope::for_current_chain(
                    abi::self_id(),
                    SIGNED_APPROVE_DOMAIN,
                    SIGNED_APPROVE_ACTION,
                    approve_payload_hash(args.owner, args.spender, args.amount),
                ),
                now(),
            );
            if principal != args.owner {
                panic!("{}", error::UNAUTHORIZED);
            }
            let event = self.token.approve_for(
                args.owner,
                ApproveCall {
                    spender: args.spender,
                    amount: args.amount,
                },
            );
            Self::emit_approval(event);
        }
        pub fn increase_allowance(&mut self, args: IncreaseAllowanceCall) {
            let caller = caller();
            let event = self.token.increase_allowance(caller, args);
            Self::emit_approval(event);
        }
        pub fn decrease_allowance(&mut self, args: DecreaseAllowanceCall) {
            let caller = caller();
            let event = self.token.decrease_allowance(caller, args);
            Self::emit_approval(event);
        }
        pub fn transfer_from(&mut self, args: TransferFromCall) {
            self.pausable.assert_not_paused();
            let caller = caller();
            let event = {
                let guard = &mut self.guard;
                let token = &mut self.token;
                let votes = &mut self.votes;
                guard.run(|| {
                    let event = token.transfer_from(caller, args);
                    votes.move_units(
                        Some(event.from),
                        Some(event.to),
                        event.amount,
                        now(),
                    );
                    event
                })
            };
            Self::emit_transfer(event);
        }
        pub fn mint(&mut self, args: MintCall) {
            self.pausable.assert_not_paused();
            if args.to.is_zero() {
                panic!("{}", error::ZERO_PRINCIPAL);
            }
            if let Some(cap) = self.cap {
                cap.assert_mint(self.token.total_supply(), args.amount);
            }
            self.authorize_role_action(
                MINTER_ROLE,
                args.authorization.as_ref(),
                ActionEnvelope::for_current_chain(
                    abi::self_id(),
                    TOKEN_ADMIN_DOMAIN,
                    MINT_ACTION,
                    mint_payload_hash(args.to, args.amount),
                ),
            );
            let event = self.token.mint(args.to, args.amount);
            self.votes
                .move_units(None, Some(event.to), event.amount, now());
            Self::emit_transfer(event);
        }
        pub fn burn(&mut self, amount: u64) {
            self.pausable.assert_not_paused();
            let caller = caller();
            let event = self.token.burn(caller, amount);
            self.votes
                .move_units(Some(event.from), None, event.amount, now());
            Self::emit_transfer(event);
        }
        pub fn pause(&mut self, args: AdminCall) {
            self.pausable.assert_not_paused();
            let caller = self.authorize_role_action(
                PAUSER_ROLE,
                args.authorization.as_ref(),
                ActionEnvelope::for_current_chain(
                    abi::self_id(),
                    TOKEN_ADMIN_DOMAIN,
                    PAUSE_ACTION,
                    empty_payload_hash(b"drc20.pause"),
                ),
            );
            self.pausable.pause();
            Self::emit_paused(caller);
        }
        pub fn unpause(&mut self, args: AdminCall) {
            self.pausable.assert_paused();
            let caller = self.authorize_role_action(
                PAUSER_ROLE,
                args.authorization.as_ref(),
                ActionEnvelope::for_current_chain(
                    abi::self_id(),
                    TOKEN_ADMIN_DOMAIN,
                    UNPAUSE_ACTION,
                    empty_payload_hash(b"drc20.unpause"),
                ),
            );
            self.pausable.unpause();
            Self::emit_unpaused(caller);
        }

        pub fn paused(&self) -> bool {
            self.pausable.paused()
        }
        pub fn grant_role(&mut self, args: RoleCall) {
            if args.account.is_zero() {
                panic!("{}", error::ZERO_PRINCIPAL);
            }
            let admin = self.access.get_role_admin(args.role);
            let caller = self.authorize_role_action(
                admin,
                args.authorization.as_ref(),
                ActionEnvelope::for_current_chain(
                    abi::self_id(),
                    TOKEN_ADMIN_DOMAIN,
                    GRANT_ROLE_ACTION,
                    role_payload_hash(args.role, args.account),
                ),
            );
            let had_role = self.access.has_role(args.role, args.account);
            self.access.grant_role(caller, args.role, args.account);
            if !had_role {
                Self::emit_role_granted(args.role, args.account, caller);
            }
        }
        pub fn revoke_role(&mut self, args: RoleCall) {
            let admin = self.access.get_role_admin(args.role);
            let caller = self.authorize_role_action(
                admin,
                args.authorization.as_ref(),
                ActionEnvelope::for_current_chain(
                    abi::self_id(),
                    TOKEN_ADMIN_DOMAIN,
                    REVOKE_ROLE_ACTION,
                    role_payload_hash(args.role, args.account),
                ),
            );
            let had_role = self.access.has_role(args.role, args.account);
            self.access.revoke_role(caller, args.role, args.account);
            if had_role {
                Self::emit_role_revoked(args.role, args.account, caller);
            }
        }

        fn authorize_role_action(
            &mut self,
            role: Role,
            authorization: Option<&SignedAuthorization>,
            envelope: ActionEnvelope,
        ) -> Principal {
            self.access.authorize_role_action(
                role,
                &mut self.authorizations,
                CallContext::current(),
                authorization,
                envelope,
                now(),
            )
        }

        fn emit_transfer(event: Drc20Transfer) {
            abi::emit(
                TRANSFER_TOPIC,
                Drc20Transfer {
                    from: event.from,
                    to: event.to,
                    amount: event.amount,
                },
            );
        }

        fn emit_approval(event: Drc20Approval) {
            abi::emit(
                APPROVAL_TOPIC,
                Drc20Approval {
                    owner: event.owner,
                    spender: event.spender,
                    amount: event.amount,
                },
            );
        }

        fn emit_paused(account: Principal) {
            abi::emit(PAUSED_TOPIC, Paused { account });
        }

        fn emit_unpaused(account: Principal) {
            abi::emit(UNPAUSED_TOPIC, Unpaused { account });
        }

        fn emit_role_granted(
            role: Role,
            account: Principal,
            sender: Principal,
        ) {
            abi::emit(
                ROLE_GRANTED_TOPIC,
                RoleGranted {
                    role,
                    account,
                    sender,
                },
            );
        }

        fn emit_role_revoked(
            role: Role,
            account: Principal,
            sender: Principal,
        ) {
            abi::emit(
                ROLE_REVOKED_TOPIC,
                RoleRevoked {
                    role,
                    account,
                    sender,
                },
            );
        }
    }

    impl Default for Drc20RolesPausable {
        fn default() -> Self {
            Self::new()
        }
    }

    fn caller() -> Principal {
        CallContext::current().require_principal(error::UNAUTHORIZED)
    }

    fn empty_payload_hash(tag: &[u8]) -> [u8; 32] {
        abi::keccak256(Vec::from(tag))
    }

    fn mint_payload_hash(to: Principal, amount: u64) -> [u8; 32] {
        let mut bytes = Vec::from(&b"drc20.mint"[..]);
        push_principal(&mut bytes, to);
        bytes.extend_from_slice(&amount.to_be_bytes());
        abi::keccak256(bytes)
    }

    fn approve_payload_hash(
        owner: Principal,
        spender: Principal,
        amount: u64,
    ) -> [u8; 32] {
        let mut bytes = Vec::from(&b"drc20.approve"[..]);
        push_principal(&mut bytes, owner);
        push_principal(&mut bytes, spender);
        bytes.extend_from_slice(&amount.to_be_bytes());
        abi::keccak256(bytes)
    }

    fn role_payload_hash(role: Role, account: Principal) -> [u8; 32] {
        let mut bytes = Vec::from(&b"drc20.role"[..]);
        bytes.extend_from_slice(&role);
        push_principal(&mut bytes, account);
        abi::keccak256(bytes)
    }

    fn push_principal(bytes: &mut Vec<u8>, principal: Principal) {
        let principal = principal.to_bytes();
        bytes.extend_from_slice(&(principal.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&principal);
    }

    fn now() -> u64 {
        abi::block_height()
    }
}
