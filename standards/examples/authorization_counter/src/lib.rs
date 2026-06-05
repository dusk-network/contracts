// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Example counter controlled by replay-protected Dusk authorizations.

#![no_std]
#![cfg(target_family = "wasm")]

extern crate alloc;
extern crate self as authorization_counter_types;

use bytecheck::CheckBytes;
use dusk_contract_standards::auth::{
    MoonlightAuthorization, PhoenixSignatureAuthorization,
};
use dusk_contract_standards::core::{NonceDomain, Principal};
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SetValueByMoonlight {
    pub authorization: MoonlightAuthorization,
    pub amount: u64,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SetValueByPhoenix {
    pub authorization: PhoenixSignatureAuthorization,
    pub amount: u64,
}

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct NonceQuery {
    pub principal: Principal,
    pub domain: NonceDomain,
}

#[dusk_forge::contract]
mod authorization_counter {
    use alloc::vec::Vec;

    use authorization_counter_types::{
        NonceQuery, SetValueByMoonlight, SetValueByPhoenix,
    };
    use dusk_contract_standards::auth::{ActionEnvelope, AuthorizationManager};
    use dusk_contract_standards::core::{NonceDomain, Principal};
    use dusk_core::abi;

    const SET_VALUE_DOMAIN: NonceDomain = [3u8; 32];
    const SET_VALUE_ACTION: [u8; 32] = [4u8; 32];

    pub struct AuthorizationCounter {
        authorizations: AuthorizationManager,
        value: u64,
        last_authorizer: Option<Principal>,
        initialized: bool,
    }

    impl AuthorizationCounter {
        pub const fn new() -> Self {
            Self {
                authorizations: AuthorizationManager::new(),
                value: 0,
                last_authorizer: None,
                initialized: false,
            }
        }
        pub fn init(&mut self) {
            if self.initialized {
                panic!("AuthorizationCounter: already initialized");
            }
            self.initialized = true;
        }

        pub fn value(&self) -> u64 {
            self.value
        }

        pub const fn last_authorizer(&self) -> Option<Principal> {
            self.last_authorizer
        }

        pub fn nonce(&self, query: NonceQuery) -> u64 {
            self.authorizations.nonce(query.principal, query.domain)
        }
        pub fn set_value_by_moonlight(&mut self, args: SetValueByMoonlight) {
            let envelope = self.action_envelope(args.amount);
            let principal = self.authorizations.authorize_moonlight_action(
                &args.authorization,
                envelope,
                now(),
            );
            self.set_value(principal, args.amount);
        }
        pub fn set_value_by_phoenix(&mut self, args: SetValueByPhoenix) {
            let envelope = self.action_envelope(args.amount);
            let principal = self.authorizations.authorize_phoenix_action(
                &args.authorization,
                envelope,
                now(),
            );
            self.set_value(principal, args.amount);
        }

        fn action_envelope(&self, amount: u64) -> ActionEnvelope {
            if !self.initialized {
                panic!("AuthorizationCounter: not initialized");
            }
            ActionEnvelope::new(
                abi::chain_id(),
                abi::self_id(),
                SET_VALUE_DOMAIN,
                SET_VALUE_ACTION,
                amount_hash(amount),
            )
        }

        fn set_value(&mut self, principal: Principal, amount: u64) {
            self.value = amount;
            self.last_authorizer = Some(principal);
        }
    }

    impl Default for AuthorizationCounter {
        fn default() -> Self {
            Self::new()
        }
    }

    fn amount_hash(amount: u64) -> [u8; 32] {
        abi::keccak256(Vec::from(amount.to_be_bytes()))
    }

    fn now() -> u64 {
        abi::block_height()
    }
}
