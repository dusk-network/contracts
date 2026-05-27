// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Dusk-native reusable contract standards and examples.
//!
//! This crate intentionally does not provide EVM API compatibility. It ports
//! the security concepts into Dusk's account, contract, and call model.

#![no_std]
#![cfg_attr(
    not(all(target_family = "wasm", feature = "contract")),
    deny(unused_crate_dependencies)
)]
#![deny(unused_extern_crates)]

extern crate alloc;

use dusk_forge as _;

#[cfg(test)]
use dusk_vm as _;
#[cfg(test)]
use rand as _;
#[cfg(test)]
use serde_json as _;

pub mod access;
pub mod auth;
pub mod core;
pub mod governance;
pub mod security;
pub mod token;
