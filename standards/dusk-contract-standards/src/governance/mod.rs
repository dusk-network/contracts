// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Governance primitives.

pub mod multisig;
pub mod multisig_controller;

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
