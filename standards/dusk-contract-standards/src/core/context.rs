// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Runtime call context helpers.

use crate::core::principal::Principal;

#[cfg(any(all(target_family = "wasm", feature = "contract"), test))]
use dusk_core::abi::ContractId;
#[cfg(any(all(target_family = "wasm", feature = "contract"), test))]
use dusk_core::signatures::bls::PublicKey as BlsPublicKey;
#[cfg(any(all(target_family = "wasm", feature = "contract"), test))]
use dusk_core::transfer::TRANSFER_CONTRACT;

/// Current call context.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallContext {
    /// Current actor, if the runtime exposes one.
    pub principal: Option<Principal>,
}

impl CallContext {
    /// Creates a context from an explicit principal.
    pub const fn from_principal(principal: Principal) -> Self {
        Self {
            principal: Some(principal),
        }
    }

    /// Creates an empty context.
    pub const fn none() -> Self {
        Self { principal: None }
    }

    /// Returns the principal or panics with `msg`.
    pub fn require_principal(&self, msg: &str) -> Principal {
        self.principal.unwrap_or_else(|| panic!("{}", msg))
    }

    /// Reads the current Dusk runtime context.
    ///
    /// A root Moonlight transaction routed through the transfer contract is
    /// represented by `public_sender`. An inter-contract call is represented
    /// by the immediate caller contract id. Phoenix transactions do not expose
    /// a stable owner identity here; Phoenix authorization should be modeled
    /// with an explicit Schnorr signature plus nonce/replay protection.
    #[cfg(all(target_family = "wasm", feature = "contract"))]
    pub fn current() -> Self {
        use dusk_core::abi;

        let caller = abi::caller();
        let callstack_len = abi::callstack().len();
        let public_sender = match caller {
            Some(TRANSFER_CONTRACT) if callstack_len <= 1 => {
                abi::public_sender()
            }
            _ => None,
        };

        Self::from_runtime_parts(caller, public_sender, callstack_len)
    }

    /// Native tests must inject context explicitly.
    #[cfg(not(all(target_family = "wasm", feature = "contract")))]
    pub const fn current() -> Self {
        Self::none()
    }

    #[cfg(any(all(target_family = "wasm", feature = "contract"), test))]
    fn from_runtime_parts(
        caller: Option<ContractId>,
        public_sender: Option<BlsPublicKey>,
        callstack_len: usize,
    ) -> Self {
        match caller {
            Some(TRANSFER_CONTRACT) if callstack_len <= 1 => {
                public_sender.as_ref().map_or_else(Self::none, |pk| {
                    Self::from_principal(Principal::moonlight(pk))
                })
            }
            Some(caller) => Self::from_principal(Principal::Contract(caller)),
            None => Self::none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use dusk_core::signatures::bls::{
        PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
    };

    use super::*;

    fn moonlight_key(seed: u64) -> BlsPublicKey {
        let mut rng = StdRng::seed_from_u64(seed);
        BlsPublicKey::from(&BlsSecretKey::random(&mut rng))
    }

    fn contract(byte: u8) -> ContractId {
        ContractId::from_bytes([byte; 32])
    }

    #[test]
    fn transfer_entrypoint_moonlight_uses_public_sender() {
        let pk = moonlight_key(1);
        let context = CallContext::from_runtime_parts(
            Some(TRANSFER_CONTRACT),
            Some(pk),
            1,
        );
        assert_eq!(context.principal, Some(Principal::moonlight(&pk)));
    }

    #[test]
    fn transfer_entrypoint_without_public_sender_has_no_actor() {
        let context =
            CallContext::from_runtime_parts(Some(TRANSFER_CONTRACT), None, 1);
        assert_eq!(context.principal, None);
    }

    #[test]
    fn nested_contract_call_keeps_immediate_contract_caller() {
        let pk = moonlight_key(2);
        let caller = contract(7);
        let context =
            CallContext::from_runtime_parts(Some(caller), Some(pk), 2);
        assert_eq!(context.principal, Some(Principal::Contract(caller)));
    }

    #[test]
    fn nested_transfer_call_is_not_rewritten_to_public_sender() {
        let pk = moonlight_key(3);
        let context = CallContext::from_runtime_parts(
            Some(TRANSFER_CONTRACT),
            Some(pk),
            2,
        );
        assert_eq!(
            context.principal,
            Some(Principal::Contract(TRANSFER_CONTRACT))
        );
    }

    #[test]
    fn no_caller_has_no_observed_actor() {
        let pk = moonlight_key(4);
        let context = CallContext::from_runtime_parts(None, Some(pk), 0);
        assert_eq!(context.principal, None);
    }
}
