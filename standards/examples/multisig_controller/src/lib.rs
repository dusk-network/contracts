// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Forge reference multisig controller for Dusk standards contracts.

#![no_std]
#![cfg(target_family = "wasm")]

extern crate alloc;
extern crate self as multisig_controller_types;

use alloc::vec::Vec;
use bytecheck::CheckBytes;
use dusk_contract_standards::auth::SignedAuthorization;
use dusk_contract_standards::core::{NonceDomain, Principal};
use dusk_contract_standards::governance::{
    MultisigApprovals, MultisigControllerConfig, MultisigOperationId,
    MultisigTarget, Threshold,
};
use rkyv::{Archive, Deserialize, Serialize};

pub const MULTISIG_CONTROLLER_DOMAIN: NonceDomain = [41u8; 32];
pub const PROPOSE_ACTION: [u8; 32] = [42u8; 32];
pub const CONFIRM_ACTION: [u8; 32] = [43u8; 32];
pub const CANCEL_ACTION: [u8; 32] = [44u8; 32];
pub const UPDATE_AUTHORITY_ACTION: [u8; 32] = [45u8; 32];
pub const SET_TIME_LIMITS_ACTION: [u8; 32] = [46u8; 32];

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Init {
    pub config: MultisigControllerConfig,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Propose {
    pub target: MultisigTarget,
    pub authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Confirm {
    pub id: MultisigOperationId,
    pub authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Cancel {
    pub id: MultisigOperationId,
    pub approvals: MultisigApprovals,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct UpdateAuthority {
    pub owners: Vec<Principal>,
    pub threshold: Threshold,
    pub approvals: MultisigApprovals,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SetTimeLimits {
    pub proposal_ttl: u64,
    pub tombstone_ttl: u64,
    pub approvals: MultisigApprovals,
}

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct NonceQuery {
    pub principal: Principal,
    pub domain: NonceDomain,
}

#[dusk_forge::contract(events = [
    MultisigOperationProposed,
    MultisigOperationConfirmed,
    MultisigOperationExecuted,
    MultisigOperationCancelled,
    MultisigAuthorityUpdated,
    MultisigTimeLimitsUpdated,
])]
mod multisig_controller {
    use alloc::format;
    use alloc::vec::Vec;

    use dusk_contract_standards::auth::{
        ActionEnvelope, AuthorizationManager, SignedAuthorization,
    };
    use dusk_contract_standards::core::{
        error, CallContext, Principal, PrincipalKind,
    };
    use dusk_contract_standards::governance::{
        MultisigAuthorityUpdated, MultisigController,
        MultisigControllerOutcome, MultisigControllerStatus,
        MultisigOperationCancelled, MultisigOperationConfirmed,
        MultisigOperationExecuted, MultisigOperationId,
        MultisigOperationProposed, MultisigPendingOperation, MultisigTarget,
        MultisigTimeLimitsUpdated, Threshold, MULTISIG_AUTHORITY_UPDATED_TOPIC,
        MULTISIG_OPERATION_CANCELLED_TOPIC, MULTISIG_OPERATION_CONFIRMED_TOPIC,
        MULTISIG_OPERATION_EXECUTED_TOPIC, MULTISIG_OPERATION_PROPOSED_TOPIC,
        MULTISIG_TIME_LIMITS_UPDATED_TOPIC,
    };
    use dusk_core::abi;

    use multisig_controller_types::{
        Cancel, Confirm, Init, NonceQuery, Propose, SetTimeLimits,
        UpdateAuthority, CANCEL_ACTION, CONFIRM_ACTION,
        MULTISIG_CONTROLLER_DOMAIN, PROPOSE_ACTION, SET_TIME_LIMITS_ACTION,
        UPDATE_AUTHORITY_ACTION,
    };

    pub struct MultisigControllerContract {
        controller: MultisigController,
        authorizations: AuthorizationManager,
        initialized: bool,
    }

    impl MultisigControllerContract {
        pub const fn new() -> Self {
            Self {
                controller: MultisigController::new(),
                authorizations: AuthorizationManager::new(),
                initialized: false,
            }
        }
        pub fn init(&mut self, args: Init) {
            if self.initialized {
                panic!("{}", error::ALREADY_INITIALIZED);
            }
            self.controller.init(args.config);
            self.initialized = true;
        }

        pub fn owners(&self) -> Vec<Principal> {
            self.controller.owners()
        }

        pub fn threshold(&self) -> Threshold {
            self.controller.threshold()
        }

        pub fn proposal_ttl(&self) -> u64 {
            self.controller.proposal_ttl()
        }

        pub fn tombstone_ttl(&self) -> u64 {
            self.controller.tombstone_ttl()
        }

        pub fn nonce(&self, args: NonceQuery) -> u64 {
            self.authorizations.nonce(args.principal, args.domain)
        }

        pub fn operation_id(
            &self,
            target: MultisigTarget,
        ) -> MultisigOperationId {
            operation_id(&target)
        }

        pub fn proposal(
            &self,
            id: MultisigOperationId,
        ) -> Option<MultisigPendingOperation> {
            self.controller.proposal(id)
        }

        pub fn tombstone_expiry(&self, id: MultisigOperationId) -> Option<u64> {
            self.controller.tombstone_expiry(id)
        }

        pub fn propose(&mut self, args: Propose) -> Vec<u8> {
            self.assert_initialized();
            let Propose {
                target,
                authorization,
            } = args;
            let id = operation_id(&target);
            let authorizer =
                self.verify_owner(PROPOSE_ACTION, id, authorization.as_ref());
            let outcome =
                self.controller.propose(id, target, authorizer, now());
            self.consume_authorization(authorization.as_ref());
            match outcome.status {
                MultisigControllerStatus::Proposed => abi::emit(
                    MULTISIG_OPERATION_PROPOSED_TOPIC,
                    MultisigOperationProposed {
                        id: outcome.id,
                        authorizer: outcome.authorizer,
                        confirmations: outcome.confirmations,
                        threshold: outcome.threshold,
                        deadline: outcome.deadline,
                    },
                ),
                MultisigControllerStatus::Confirmed
                | MultisigControllerStatus::Ready => abi::emit(
                    MULTISIG_OPERATION_CONFIRMED_TOPIC,
                    MultisigOperationConfirmed {
                        id: outcome.id,
                        authorizer: outcome.authorizer,
                        confirmations: outcome.confirmations,
                        threshold: outcome.threshold,
                        deadline: outcome.deadline,
                    },
                ),
            }
            let execution_id = outcome.id;
            let (return_data, execution) = self.execute_if_ready(outcome);
            if let Some((success, error)) = execution {
                abi::emit(
                    MULTISIG_OPERATION_EXECUTED_TOPIC,
                    MultisigOperationExecuted {
                        id: execution_id,
                        success,
                        return_data: return_data.clone(),
                        error,
                    },
                );
            }
            return_data
        }

        pub fn confirm(&mut self, args: Confirm) -> Vec<u8> {
            self.assert_initialized();
            let authorizer = self.verify_owner(
                CONFIRM_ACTION,
                args.id,
                args.authorization.as_ref(),
            );
            let outcome = self.controller.confirm(args.id, authorizer, now());
            self.consume_authorization(args.authorization.as_ref());
            match outcome.status {
                MultisigControllerStatus::Proposed => abi::emit(
                    MULTISIG_OPERATION_PROPOSED_TOPIC,
                    MultisigOperationProposed {
                        id: outcome.id,
                        authorizer: outcome.authorizer,
                        confirmations: outcome.confirmations,
                        threshold: outcome.threshold,
                        deadline: outcome.deadline,
                    },
                ),
                MultisigControllerStatus::Confirmed
                | MultisigControllerStatus::Ready => abi::emit(
                    MULTISIG_OPERATION_CONFIRMED_TOPIC,
                    MultisigOperationConfirmed {
                        id: outcome.id,
                        authorizer: outcome.authorizer,
                        confirmations: outcome.confirmations,
                        threshold: outcome.threshold,
                        deadline: outcome.deadline,
                    },
                ),
            }
            let execution_id = outcome.id;
            let (return_data, execution) = self.execute_if_ready(outcome);
            if let Some((success, error)) = execution {
                abi::emit(
                    MULTISIG_OPERATION_EXECUTED_TOPIC,
                    MultisigOperationExecuted {
                        id: execution_id,
                        success,
                        return_data: return_data.clone(),
                        error,
                    },
                );
            }
            return_data
        }

        pub fn cancel(&mut self, args: Cancel) {
            self.assert_initialized();
            let signers = self.verify_quorum(
                CANCEL_ACTION,
                args.id,
                &args.approvals.approvals,
            );
            let event: MultisigOperationCancelled =
                self.controller.cancel(args.id, &signers, now());
            self.consume_approvals(&args.approvals.approvals);
            abi::emit(
                MULTISIG_OPERATION_CANCELLED_TOPIC,
                MultisigOperationCancelled {
                    id: event.id,
                    signers: event.signers,
                },
            );
        }

        pub fn update_authority(&mut self, args: UpdateAuthority) {
            self.assert_initialized();
            let payload_hash =
                authority_payload_hash(&args.owners, args.threshold);
            let signers = self.verify_quorum(
                UPDATE_AUTHORITY_ACTION,
                payload_hash,
                &args.approvals.approvals,
            );
            let event: MultisigAuthorityUpdated = self
                .controller
                .update_authority(&signers, args.owners, args.threshold);
            self.consume_approvals(&args.approvals.approvals);
            abi::emit(
                MULTISIG_AUTHORITY_UPDATED_TOPIC,
                MultisigAuthorityUpdated {
                    previous_owners: event.previous_owners,
                    previous_threshold: event.previous_threshold,
                    owners: event.owners,
                    threshold: event.threshold,
                    removed_operations: event.removed_operations,
                },
            );
        }

        pub fn set_time_limits(&mut self, args: SetTimeLimits) {
            self.assert_initialized();
            let payload_hash =
                time_limits_payload_hash(args.proposal_ttl, args.tombstone_ttl);
            let signers = self.verify_quorum(
                SET_TIME_LIMITS_ACTION,
                payload_hash,
                &args.approvals.approvals,
            );
            let event: MultisigTimeLimitsUpdated =
                self.controller.set_time_limits(
                    &signers,
                    args.proposal_ttl,
                    args.tombstone_ttl,
                );
            self.consume_approvals(&args.approvals.approvals);
            abi::emit(
                MULTISIG_TIME_LIMITS_UPDATED_TOPIC,
                MultisigTimeLimitsUpdated {
                    previous_proposal_ttl: event.previous_proposal_ttl,
                    previous_tombstone_ttl: event.previous_tombstone_ttl,
                    proposal_ttl: event.proposal_ttl,
                    tombstone_ttl: event.tombstone_ttl,
                },
            );
        }

        fn verify_owner(
            &self,
            action_id: [u8; 32],
            payload_hash: [u8; 32],
            authorization: Option<&SignedAuthorization>,
        ) -> Principal {
            if let Some(principal) = CallContext::current().principal {
                match principal.kind() {
                    PrincipalKind::Moonlight | PrincipalKind::Contract => {
                        if self.controller.is_owner(principal) {
                            return principal;
                        }
                    }
                    PrincipalKind::Phoenix => {}
                }
            }

            let Some(authorization) = authorization else {
                panic!("{}", error::UNAUTHORIZED);
            };
            let envelope = ActionEnvelope::for_current_chain(
                abi::self_id(),
                MULTISIG_CONTROLLER_DOMAIN,
                action_id,
                payload_hash,
            );
            let principal = self.authorizations.verify_signed_action(
                authorization,
                envelope,
                now(),
            );
            if !self.controller.is_owner(principal) {
                panic!("{}", error::UNAUTHORIZED);
            }
            principal
        }

        fn verify_quorum(
            &self,
            action_id: [u8; 32],
            payload_hash: [u8; 32],
            approvals: &[SignedAuthorization],
        ) -> Vec<Principal> {
            self.controller.verify_action(
                &self.authorizations,
                CallContext::current(),
                approvals,
                ActionEnvelope::for_current_chain(
                    abi::self_id(),
                    MULTISIG_CONTROLLER_DOMAIN,
                    action_id,
                    payload_hash,
                ),
                now(),
            )
        }

        fn consume_authorization(
            &mut self,
            authorization: Option<&SignedAuthorization>,
        ) {
            if let Some(authorization) = authorization {
                self.authorizations.consume_verified(authorization);
            }
        }

        fn consume_approvals(&mut self, approvals: &[SignedAuthorization]) {
            for approval in approvals {
                self.authorizations.consume_verified(approval);
            }
        }

        fn execute_if_ready(
            &mut self,
            outcome: MultisigControllerOutcome,
        ) -> (Vec<u8>, Option<(bool, Option<alloc::string::String>)>) {
            let Some(operation) = outcome.ready_operation else {
                return (Vec::new(), None);
            };

            let call = &operation.target.call;
            let (success, return_data, error) = match abi::call_raw(
                call.contract,
                &call.fn_name,
                &call.fn_args,
            ) {
                Ok(data) => (true, data, None),
                Err(error) => (false, Vec::new(), Some(format!("{error}"))),
            };
            (return_data, Some((success, error)))
        }

        fn assert_initialized(&self) {
            if !self.initialized {
                panic!("{}", error::NOT_INITIALIZED);
            }
        }
    }

    impl Default for MultisigControllerContract {
        fn default() -> Self {
            Self::new()
        }
    }

    fn operation_id(target: &MultisigTarget) -> MultisigOperationId {
        let mut bytes =
            Vec::from(&b"dusk-contract-standards/multisig/op/v1"[..]);
        bytes.push(abi::chain_id());
        bytes.extend_from_slice(&abi::self_id().to_bytes());
        bytes.extend_from_slice(&target.call.to_var_bytes());
        bytes.extend_from_slice(&target.salt);
        abi::keccak256(bytes)
    }

    fn authority_payload_hash(
        owners: &[Principal],
        threshold: Threshold,
    ) -> [u8; 32] {
        let mut bytes = Vec::from(&b"multisig.authority"[..]);
        bytes.extend_from_slice(&(owners.len() as u32).to_be_bytes());
        for owner in owners {
            push_principal(&mut bytes, *owner);
        }
        bytes.extend_from_slice(&threshold.to_be_bytes());
        abi::keccak256(bytes)
    }

    fn time_limits_payload_hash(
        proposal_ttl: u64,
        tombstone_ttl: u64,
    ) -> [u8; 32] {
        let mut bytes = Vec::from(&b"multisig.time_limits"[..]);
        bytes.extend_from_slice(&proposal_ttl.to_be_bytes());
        bytes.extend_from_slice(&tombstone_ttl.to_be_bytes());
        abi::keccak256(bytes)
    }

    fn push_principal(bytes: &mut Vec<u8>, principal: Principal) {
        let principal = principal.to_bytes();
        bytes.extend_from_slice(&(principal.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&principal);
    }

    fn now() -> u64 {
        abi::block_height()
    }
}
