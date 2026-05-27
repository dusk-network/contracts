// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Test-only router that models the transfer-contract Moonlight call path.

#![no_std]
#![cfg(target_family = "wasm")]

extern crate alloc;
extern crate self as moonlight_call_router_types;

use alloc::string::String;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use dusk_core::abi::ContractId;
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[archive_attr(derive(CheckBytes))]
pub struct ForwardCall {
    pub contract: ContractId,
    pub function: String,
    pub args: Vec<u8>,
}

#[dusk_forge::contract]
mod moonlight_call_router {
    use alloc::vec::Vec;

    use dusk_core::abi;
    use moonlight_call_router_types::ForwardCall;

    pub struct MoonlightCallRouter;

    impl MoonlightCallRouter {
        pub const fn new() -> Self {
            Self
        }

        pub fn init(&mut self) {}

        pub fn forward(&mut self, call: ForwardCall) -> Vec<u8> {
            abi::call_raw(call.contract, &call.function, &call.args)
                .unwrap_or_else(|err| panic!("MoonlightCallRouter: {err:?}"))
        }
    }

    impl Default for MoonlightCallRouter {
        fn default() -> Self {
            Self::new()
        }
    }
}
