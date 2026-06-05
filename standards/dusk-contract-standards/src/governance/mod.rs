// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Governance and scheduling primitives.

pub mod controller;
pub mod multisig;
pub mod multisig_controller;
pub mod timelock;

pub use controller::{
    TimelockController, CANCELLER_ROLE, EXECUTOR_ROLE, PROPOSER_ROLE,
    TIMELOCK_ADMIN_ROLE,
};
pub use multisig::{
    MultisigApprovals, MultisigConfig, MultisigQuorum, Threshold,
    ThresholdMultisig,
};
pub use multisig_controller::{
    MultisigAuthorityUpdated, MultisigController, MultisigControllerConfig,
    MultisigControllerOutcome, MultisigControllerStatus,
    MultisigOperationCancelled, MultisigOperationConfirmed,
    MultisigOperationExecuted, MultisigOperationId, MultisigOperationProposed,
    MultisigPendingOperation, MultisigTarget, MultisigTimeLimitsUpdated,
    MULTISIG_AUTHORITY_UPDATED_TOPIC, MULTISIG_OPERATION_CANCELLED_TOPIC,
    MULTISIG_OPERATION_CONFIRMED_TOPIC, MULTISIG_OPERATION_EXECUTED_TOPIC,
    MULTISIG_OPERATION_PROPOSED_TOPIC, MULTISIG_TIME_LIMITS_UPDATED_TOPIC,
};
pub use timelock::{OperationId, ScheduledOperation, Timelock};
