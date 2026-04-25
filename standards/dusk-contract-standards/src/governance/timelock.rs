//! Timelock operation scheduler.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use crate::core::error;

/// Operation id.
pub type OperationId = [u8; 32];

/// Scheduled operation metadata.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ScheduledOperation {
    /// Earliest executable height or timestamp unit selected by the contract.
    pub ready_at: u64,
    /// Whether the operation has already been executed.
    pub done: bool,
    /// Optional operation payload for migration or client inspection.
    pub payload: Vec<u8>,
}

/// Minimal timelock state machine.
#[derive(Clone, Debug)]
pub struct Timelock {
    min_delay: u64,
    operations: BTreeMap<OperationId, ScheduledOperation>,
}

impl Timelock {
    /// Creates a timelock with `min_delay`.
    pub const fn new(min_delay: u64) -> Self {
        Self {
            min_delay,
            operations: BTreeMap::new(),
        }
    }

    /// Returns the configured minimum delay.
    pub const fn min_delay(&self) -> u64 {
        self.min_delay
    }

    /// Updates the delay. Caller authorization belongs in the composing
    /// contract.
    pub fn set_min_delay(&mut self, min_delay: u64) {
        self.min_delay = min_delay;
    }

    /// Schedules an operation.
    pub fn schedule(
        &mut self,
        id: OperationId,
        now: u64,
        payload: Vec<u8>,
    ) -> u64 {
        if self.operations.contains_key(&id) {
            panic!("{}", error::ALREADY_INITIALIZED);
        }
        let ready_at = now.checked_add(self.min_delay).expect(error::OVERFLOW);
        self.operations.insert(
            id,
            ScheduledOperation {
                ready_at,
                done: false,
                payload,
            },
        );
        ready_at
    }

    /// Cancels a pending operation.
    pub fn cancel(&mut self, id: OperationId) {
        let Some(op) = self.operations.get(&id) else {
            panic!("{}", error::OPERATION_UNKNOWN);
        };
        if op.done {
            panic!("{}", error::OPERATION_DONE);
        }
        self.operations.remove(&id);
    }

    /// Marks an operation as executed and returns its payload.
    pub fn execute(&mut self, id: OperationId, now: u64) -> Vec<u8> {
        let op = self
            .operations
            .get_mut(&id)
            .unwrap_or_else(|| panic!("{}", error::OPERATION_UNKNOWN));
        if op.done {
            panic!("{}", error::OPERATION_DONE);
        }
        if now < op.ready_at {
            panic!("{}", error::DELAY_NOT_ELAPSED);
        }
        op.done = true;
        op.payload.clone()
    }

    /// Returns an operation.
    pub fn get(&self, id: OperationId) -> Option<&ScheduledOperation> {
        self.operations.get(&id)
    }

    /// Returns true when operation is ready and not done.
    pub fn is_ready(&self, id: OperationId, now: u64) -> bool {
        self.operations
            .get(&id)
            .map(|op| !op.done && now >= op.ready_at)
            .unwrap_or(false)
    }
}

impl Default for Timelock {
    fn default() -> Self {
        Self::new(0)
    }
}
