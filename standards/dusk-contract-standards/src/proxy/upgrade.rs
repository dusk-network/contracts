// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Upgrade admin state machine.

use alloc::vec::Vec;

use bytecheck::CheckBytes;
use dusk_core::abi::ContractId;
use rkyv::{Archive, Deserialize, Serialize};

use crate::auth::{
    ActionEnvelope, AuthorizationManager, Authorizer, SignedAuthorization,
};
use crate::core::{error, CallContext, Principal};

/// Upgrade prepared event topic.
pub const UPGRADE_PREPARED_TOPIC: &str = "proxy/upgrade_prepared";
/// Upgrade activated event topic.
pub const UPGRADE_ACTIVATED_TOPIC: &str = "proxy/upgrade_activated";
/// Pending upgrade cancelled event topic.
pub const UPGRADE_CANCELLED_TOPIC: &str = "proxy/upgrade_cancelled";
/// Upgrade rolled back event topic.
pub const UPGRADE_ROLLED_BACK_TOPIC: &str = "proxy/upgrade_rolled_back";
/// Rollback window finalized event topic.
pub const ROLLBACK_FINALIZED_TOPIC: &str = "proxy/rollback_finalized";

/// Pending upgrade data.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PendingUpgrade {
    /// New implementation id.
    pub implementation: ContractId,
    /// Earliest activation timestamp/height unit selected by the contract.
    pub eta: u64,
    /// Migration payload.
    pub migrate_data: Vec<u8>,
}

/// Upgrade prepared event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct UpgradePrepared {
    /// New implementation id.
    pub implementation: ContractId,
    /// Earliest activation timestamp/height unit selected by the contract.
    pub eta: u64,
}

/// Upgrade activated event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct UpgradeActivated {
    /// Previous implementation id.
    pub previous_implementation: ContractId,
    /// Active implementation id.
    pub implementation: ContractId,
    /// Rollback deadline.
    pub rollback_deadline: u64,
}

/// Pending upgrade cancelled event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct UpgradeCancelled {
    /// Cancelled implementation id.
    pub implementation: ContractId,
}

/// Upgrade rolled back event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct UpgradeRolledBack {
    /// Implementation that was rolled back from.
    pub from_implementation: ContractId,
    /// Restored implementation id.
    pub restored_implementation: ContractId,
}

/// Rollback window finalized event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct RollbackFinalized {
    /// Active implementation id.
    pub implementation: ContractId,
}

#[cfg(feature = "forge")]
impl dusk_forge::ContractEvent for UpgradePrepared {
    const TOPICS: &'static [&'static str] = &[UPGRADE_PREPARED_TOPIC];
}

#[cfg(feature = "forge")]
impl dusk_forge::ContractEvent for UpgradeActivated {
    const TOPICS: &'static [&'static str] = &[UPGRADE_ACTIVATED_TOPIC];
}

#[cfg(feature = "forge")]
impl dusk_forge::ContractEvent for UpgradeCancelled {
    const TOPICS: &'static [&'static str] = &[UPGRADE_CANCELLED_TOPIC];
}

#[cfg(feature = "forge")]
impl dusk_forge::ContractEvent for UpgradeRolledBack {
    const TOPICS: &'static [&'static str] = &[UPGRADE_ROLLED_BACK_TOPIC];
}

#[cfg(feature = "forge")]
impl dusk_forge::ContractEvent for RollbackFinalized {
    const TOPICS: &'static [&'static str] = &[ROLLBACK_FINALIZED_TOPIC];
}

/// Dusk-native upgrade controller.
#[derive(Clone, Debug)]
pub struct UpgradeAdmin {
    admin: Principal,
    implementation: ContractId,
    previous_implementation: Option<ContractId>,
    pending: Option<PendingUpgrade>,
    delay: u64,
    rollback_window: u64,
    rollback_deadline: u64,
}

impl UpgradeAdmin {
    /// Creates an upgrade admin.
    pub fn new(
        admin: Principal,
        implementation: ContractId,
        delay: u64,
        rollback_window: u64,
    ) -> Self {
        if admin.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        if is_zero_contract_id(implementation) {
            panic!("Proxy: invalid implementation");
        }
        Self {
            admin,
            implementation,
            previous_implementation: None,
            pending: None,
            delay,
            rollback_window,
            rollback_deadline: 0,
        }
    }

    /// Returns the admin.
    pub const fn admin(&self) -> Principal {
        self.admin
    }

    /// Authorizes the upgrade admin through runtime context or signed
    /// authorization.
    pub fn authorize_admin(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        now: u64,
    ) -> Principal {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_admin_with(&mut authorizer, authorization)
    }

    /// Authorizes the upgrade admin with a reusable call authorizer.
    pub fn authorize_admin_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
    ) -> Principal {
        authorizer.require_principal_unbound(self.admin, authorization)
    }

    /// Authorizes the upgrade admin through runtime context or an action-bound
    /// signed authorization.
    pub fn authorize_admin_action(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
        now: u64,
    ) -> Principal {
        let mut authorizer = Authorizer::new(authorizations, context, now);
        self.authorize_admin_action_with(
            &mut authorizer,
            authorization,
            envelope,
        )
    }

    /// Authorizes the upgrade admin with a reusable call authorizer and exact
    /// call envelope for signed fallbacks.
    pub fn authorize_admin_action_with(
        &self,
        authorizer: &mut Authorizer<'_>,
        authorization: Option<&SignedAuthorization>,
        envelope: ActionEnvelope,
    ) -> Principal {
        authorizer.require_principal_action(self.admin, authorization, envelope)
    }

    /// Returns the active implementation.
    pub const fn implementation(&self) -> ContractId {
        self.implementation
    }

    /// Returns pending upgrade.
    pub const fn pending(&self) -> Option<&PendingUpgrade> {
        self.pending.as_ref()
    }

    /// Returns rollback deadline.
    pub const fn rollback_deadline(&self) -> u64 {
        self.rollback_deadline
    }

    /// Prepares an upgrade.
    pub fn prepare(
        &mut self,
        caller: Principal,
        implementation: ContractId,
        now: u64,
        migrate_data: Vec<u8>,
    ) -> UpgradePrepared {
        self.assert_admin(caller);
        if is_zero_contract_id(implementation) {
            panic!("Proxy: invalid implementation");
        }
        let eta = now.checked_add(self.delay).expect(error::OVERFLOW);
        self.pending = Some(PendingUpgrade {
            implementation,
            eta,
            migrate_data,
        });
        UpgradePrepared {
            implementation,
            eta,
        }
    }

    /// Activates a prepared upgrade and returns migration data.
    pub fn activate(&mut self, caller: Principal, now: u64) -> Vec<u8> {
        self.activate_with_event(caller, now).0
    }

    /// Activates a prepared upgrade and returns migration data plus event data.
    pub fn activate_with_event(
        &mut self,
        caller: Principal,
        now: u64,
    ) -> (Vec<u8>, UpgradeActivated) {
        self.assert_admin(caller);
        let eta = self
            .pending
            .as_ref()
            .unwrap_or_else(|| panic!("Proxy: no pending upgrade"))
            .eta;
        if now < eta {
            panic!("Proxy: upgrade delay not elapsed");
        }
        let rollback_deadline = now
            .checked_add(self.rollback_window)
            .expect(error::OVERFLOW);
        let Some(pending) = self.pending.take() else {
            panic!("Proxy: no pending upgrade");
        };
        let previous = self.implementation;
        self.previous_implementation = Some(previous);
        self.implementation = pending.implementation;
        self.rollback_deadline = rollback_deadline;
        let event = UpgradeActivated {
            previous_implementation: previous,
            implementation: pending.implementation,
            rollback_deadline: self.rollback_deadline,
        };
        (pending.migrate_data, event)
    }

    /// Cancels a pending upgrade.
    pub fn cancel_pending(&mut self, caller: Principal) -> UpgradeCancelled {
        self.assert_admin(caller);
        let pending = self
            .pending
            .take()
            .unwrap_or_else(|| panic!("Proxy: no pending upgrade"));
        UpgradeCancelled {
            implementation: pending.implementation,
        }
    }

    /// Rolls back to the previous implementation.
    pub fn rollback(&mut self, caller: Principal, now: u64) {
        let _ = self.rollback_with_event(caller, now);
    }

    /// Rolls back to the previous implementation and returns event data.
    pub fn rollback_with_event(
        &mut self,
        caller: Principal,
        now: u64,
    ) -> UpgradeRolledBack {
        self.assert_admin(caller);
        if self.rollback_deadline == 0 || now > self.rollback_deadline {
            panic!("Proxy: rollback window closed");
        }
        let from_implementation = self.implementation;
        let previous = self
            .previous_implementation
            .take()
            .unwrap_or_else(|| panic!("Proxy: no previous implementation"));
        self.implementation = previous;
        self.pending = None;
        self.rollback_deadline = 0;
        UpgradeRolledBack {
            from_implementation,
            restored_implementation: previous,
        }
    }

    /// Finalizes rollback window after it has elapsed.
    pub fn finalize_rollback_window(&mut self, caller: Principal, now: u64) {
        let _ = self.finalize_rollback_window_with_event(caller, now);
    }

    /// Finalizes rollback window after it has elapsed and returns event data.
    pub fn finalize_rollback_window_with_event(
        &mut self,
        caller: Principal,
        now: u64,
    ) -> RollbackFinalized {
        self.assert_admin(caller);
        if self.rollback_deadline != 0 && now < self.rollback_deadline {
            panic!("Proxy: rollback window open");
        }
        self.previous_implementation = None;
        self.rollback_deadline = 0;
        RollbackFinalized {
            implementation: self.implementation,
        }
    }

    fn assert_admin(&self, caller: Principal) {
        if caller != self.admin {
            panic!("{}", error::UNAUTHORIZED);
        }
    }
}

fn is_zero_contract_id(id: ContractId) -> bool {
    id.to_bytes().iter().all(|byte| *byte == 0)
}
