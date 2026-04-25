//! Role-gated timelock controller.

use alloc::vec::Vec;

use crate::access::{AccessControl, Role};
use crate::core::{error, Principal};
use crate::governance::{OperationId, ScheduledOperation, Timelock};

/// Role allowed to update timelock policy.
pub const TIMELOCK_ADMIN_ROLE: Role = {
    let mut role = [0u8; 32];
    role[0] = 1;
    role
};

/// Role allowed to schedule operations.
pub const PROPOSER_ROLE: Role = {
    let mut role = [0u8; 32];
    role[0] = 2;
    role
};

/// Role allowed to execute ready operations.
pub const EXECUTOR_ROLE: Role = {
    let mut role = [0u8; 32];
    role[0] = 3;
    role
};

/// Role allowed to cancel pending operations.
pub const CANCELLER_ROLE: Role = {
    let mut role = [0u8; 32];
    role[0] = 4;
    role
};

/// Timelock plus role-based caller policy.
#[derive(Clone, Debug)]
pub struct TimelockController {
    access: AccessControl,
    timelock: Timelock,
    self_principal: Principal,
}

impl TimelockController {
    /// Creates a controller and grants all controller roles to `admin`.
    pub fn new(
        self_principal: Principal,
        admin: Principal,
        min_delay: u64,
    ) -> Self {
        if self_principal.is_zero() || admin.is_zero() {
            panic!("{}", error::ZERO_PRINCIPAL);
        }
        let mut access = AccessControl::new();
        access.init_admin(admin);
        access.grant_role(admin, TIMELOCK_ADMIN_ROLE, admin);
        access.grant_role(admin, PROPOSER_ROLE, admin);
        access.grant_role(admin, EXECUTOR_ROLE, admin);
        access.grant_role(admin, CANCELLER_ROLE, admin);
        Self {
            access,
            timelock: Timelock::new(min_delay),
            self_principal,
        }
    }

    /// Returns the controller principal used for self-governed operations.
    pub const fn self_principal(&self) -> Principal {
        self.self_principal
    }

    /// Returns access-control state.
    pub const fn access(&self) -> &AccessControl {
        &self.access
    }

    /// Returns timelock state.
    pub const fn timelock(&self) -> &Timelock {
        &self.timelock
    }

    /// Returns a scheduled operation.
    pub fn get(&self, id: OperationId) -> Option<&ScheduledOperation> {
        self.timelock.get(id)
    }

    /// Returns whether an account has a role.
    pub fn has_role(&self, role: Role, account: Principal) -> bool {
        self.access.has_role(role, account)
    }

    /// Grants a role through the underlying access-control policy.
    pub fn grant_role(
        &mut self,
        caller: Principal,
        role: Role,
        account: Principal,
    ) {
        self.access.grant_role(caller, role, account);
    }

    /// Revokes a role through the underlying access-control policy.
    pub fn revoke_role(
        &mut self,
        caller: Principal,
        role: Role,
        account: Principal,
    ) {
        self.access.revoke_role(caller, role, account);
    }

    /// Updates the minimum delay. Caller must be the controller itself.
    ///
    /// Composing contracts should reach this path through a scheduled
    /// operation, not through an arbitrary administrator call.
    pub fn set_min_delay(&mut self, caller: Principal, min_delay: u64) {
        if caller != self.self_principal {
            panic!("{}", error::UNAUTHORIZED);
        }
        self.timelock.set_min_delay(min_delay);
    }

    /// Schedules a self-governed minimum-delay update.
    pub fn schedule_min_delay_change(
        &mut self,
        caller: Principal,
        id: OperationId,
        now: u64,
        min_delay: u64,
    ) -> u64 {
        self.access.assert_role(PROPOSER_ROLE, caller);
        self.timelock
            .schedule(id, now, min_delay.to_be_bytes().to_vec())
    }

    /// Executes a ready minimum-delay update as the controller itself.
    pub fn execute_min_delay_change(
        &mut self,
        caller: Principal,
        id: OperationId,
        now: u64,
    ) -> u64 {
        self.access.assert_role(EXECUTOR_ROLE, caller);
        let payload = self.timelock.execute(id, now);
        let bytes: [u8; 8] = payload
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("{}", error::INVALID_OPERATION));
        let min_delay = u64::from_be_bytes(bytes);
        self.set_min_delay(self.self_principal, min_delay);
        min_delay
    }

    /// Schedules an operation. Caller must have proposer role.
    pub fn schedule(
        &mut self,
        caller: Principal,
        id: OperationId,
        now: u64,
        payload: Vec<u8>,
    ) -> u64 {
        self.access.assert_role(PROPOSER_ROLE, caller);
        self.timelock.schedule(id, now, payload)
    }

    /// Cancels a pending operation. Caller must have canceller role.
    pub fn cancel(&mut self, caller: Principal, id: OperationId) {
        self.access.assert_role(CANCELLER_ROLE, caller);
        self.timelock.cancel(id);
    }

    /// Executes a ready operation. Caller must have executor role.
    pub fn execute(
        &mut self,
        caller: Principal,
        id: OperationId,
        now: u64,
    ) -> Vec<u8> {
        self.access.assert_role(EXECUTOR_ROLE, caller);
        self.timelock.execute(id, now)
    }
}
