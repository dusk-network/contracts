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

#[cfg(test)]
use dusk_data_driver as _;
#[cfg(test)]
use dusk_vm as _;
#[cfg(test)]
use proptest as _;
#[cfg(test)]
use rand as _;
#[cfg(test)]
use serde_json as _;
#[cfg(feature = "serde")]
use serde_with as _;
#[cfg(feature = "serde")]
use time as _;

pub mod access;
pub mod auth;
pub mod core;
pub mod governance;
pub mod proxy;
pub mod security;
pub mod token;
