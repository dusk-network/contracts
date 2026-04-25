//! Runtime call context helpers.

use crate::core::principal::Principal;

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
    /// A root Moonlight call is represented by `public_sender`. An
    /// inter-contract call is represented by the immediate caller contract id.
    /// Phoenix transactions do not expose a stable owner identity here; Phoenix
    /// authorization should be modeled with an explicit Schnorr signature plus
    /// nonce/replay protection.
    #[cfg(all(target_family = "wasm", feature = "contract"))]
    pub fn current() -> Self {
        use dusk_core::abi;

        match abi::callstack().len() {
            0 => Self::none(),
            1 => {
                let Some(pk) = abi::public_sender() else {
                    return Self::none();
                };
                Self::from_principal(Principal::moonlight(&pk))
            }
            _ => {
                let Some(caller) = abi::caller() else {
                    return Self::none();
                };
                Self::from_principal(Principal::Contract(caller))
            }
        }
    }

    /// Native tests must inject context explicitly.
    #[cfg(not(all(target_family = "wasm", feature = "contract")))]
    pub const fn current() -> Self {
        Self::none()
    }
}
