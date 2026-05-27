//! Standalone multisig controller state machine.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use bytecheck::CheckBytes;
use dusk_core::transfer::data::ContractCall;
use rkyv::{Archive, Deserialize, Serialize};

use crate::auth::{ActionEnvelope, AuthorizationManager, SignedAuthorization};
use crate::core::{error, CallContext, Principal};
use crate::governance::{MultisigConfig, Threshold, ThresholdMultisig};

/// Multisig operation id.
pub type MultisigOperationId = [u8; 32];

/// Event topic emitted when an operation is proposed.
pub const MULTISIG_OPERATION_PROPOSED_TOPIC: &str =
    "multisig/operation_proposed";
/// Event topic emitted when an operation is confirmed.
pub const MULTISIG_OPERATION_CONFIRMED_TOPIC: &str =
    "multisig/operation_confirmed";
/// Event topic emitted when an operation execution is attempted.
pub const MULTISIG_OPERATION_EXECUTED_TOPIC: &str =
    "multisig/operation_executed";
/// Event topic emitted when a pending operation is cancelled.
pub const MULTISIG_OPERATION_CANCELLED_TOPIC: &str =
    "multisig/operation_cancelled";
/// Event topic emitted when owner authority changes.
pub const MULTISIG_AUTHORITY_UPDATED_TOPIC: &str = "multisig/authority_updated";
/// Event topic emitted when proposal/replay timing changes.
pub const MULTISIG_TIME_LIMITS_UPDATED_TOPIC: &str =
    "multisig/time_limits_updated";

/// Target call controlled by the multisig.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigTarget {
    /// Call executed by the controller after quorum.
    pub call: ContractCall,
    /// Salt used to intentionally repeat the same logical call.
    pub salt: [u8; 32],
}

/// Initialization config for a standalone multisig controller.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigControllerConfig {
    /// Unique non-zero owner principals.
    pub owners: Vec<Principal>,
    /// Required distinct confirmations.
    pub threshold: Threshold,
    /// Number of blocks/heights a proposal remains confirmable.
    pub proposal_ttl: u64,
    /// Number of blocks/heights an executed operation id remains tombstoned.
    pub tombstone_ttl: u64,
}

/// Pending operation metadata.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigPendingOperation {
    /// Target call.
    pub target: MultisigTarget,
    /// Distinct owner confirmations in stable insertion order.
    pub confirmations: Vec<Principal>,
    /// Last block/height at which confirmations are accepted.
    pub deadline: u64,
}

impl MultisigPendingOperation {
    /// Returns true when `principal` has already confirmed.
    pub fn confirmed_by(&self, principal: Principal) -> bool {
        self.confirmations.contains(&principal)
    }
}

/// Lifecycle status for a proposal/confirmation call.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub enum MultisigControllerStatus {
    /// A new operation was created.
    Proposed,
    /// An existing operation received one confirmation.
    Confirmed,
    /// The operation reached threshold and should be executed by the wrapper.
    Ready,
}

/// Result of proposing or confirming an operation.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigControllerOutcome {
    /// Operation id.
    pub id: MultisigOperationId,
    /// Owner principal that authorized this confirmation.
    pub authorizer: Principal,
    /// Lifecycle status.
    pub status: MultisigControllerStatus,
    /// Confirmation count after this call.
    pub confirmations: u16,
    /// Current threshold.
    pub threshold: Threshold,
    /// Operation deadline.
    pub deadline: u64,
    /// Operation to execute when status is
    /// [`MultisigControllerStatus::Ready`].
    pub ready_operation: Option<MultisigPendingOperation>,
}

/// Event payload for proposal creation.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigOperationProposed {
    /// Operation id.
    pub id: MultisigOperationId,
    /// Owner that proposed the operation.
    pub authorizer: Principal,
    /// Confirmation count after proposal.
    pub confirmations: u16,
    /// Required confirmation threshold.
    pub threshold: Threshold,
    /// Operation deadline.
    pub deadline: u64,
}

/// Event payload for operation confirmation.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigOperationConfirmed {
    /// Operation id.
    pub id: MultisigOperationId,
    /// Owner that confirmed the operation.
    pub authorizer: Principal,
    /// Confirmation count after confirmation.
    pub confirmations: u16,
    /// Required confirmation threshold.
    pub threshold: Threshold,
    /// Operation deadline.
    pub deadline: u64,
}

/// Event payload for operation execution attempts.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigOperationExecuted {
    /// Operation id.
    pub id: MultisigOperationId,
    /// Whether the target call returned successfully.
    pub success: bool,
    /// Raw return data when the target call succeeds.
    pub return_data: Vec<u8>,
    /// Error string when the target call fails.
    pub error: Option<String>,
}

/// Event payload for threshold-cancelled operations.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigOperationCancelled {
    /// Operation id.
    pub id: MultisigOperationId,
    /// Owners that authorized cancellation.
    pub signers: Vec<Principal>,
}

/// Event payload for authority changes.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigAuthorityUpdated {
    /// Previous owners.
    pub previous_owners: Vec<Principal>,
    /// Previous threshold.
    pub previous_threshold: Threshold,
    /// New owners.
    pub owners: Vec<Principal>,
    /// New threshold.
    pub threshold: Threshold,
    /// Pending operations removed because the authority changed.
    pub removed_operations: Vec<MultisigOperationId>,
}

/// Event payload for proposal/replay timing changes.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MultisigTimeLimitsUpdated {
    /// Previous proposal TTL.
    pub previous_proposal_ttl: u64,
    /// Previous tombstone TTL.
    pub previous_tombstone_ttl: u64,
    /// New proposal TTL.
    pub proposal_ttl: u64,
    /// New tombstone TTL.
    pub tombstone_ttl: u64,
}

impl dusk_forge::ContractEvent for MultisigOperationProposed {
    const TOPICS: &'static [&'static str] =
        &[MULTISIG_OPERATION_PROPOSED_TOPIC];
}

impl dusk_forge::ContractEvent for MultisigOperationConfirmed {
    const TOPICS: &'static [&'static str] =
        &[MULTISIG_OPERATION_CONFIRMED_TOPIC];
}

impl dusk_forge::ContractEvent for MultisigOperationExecuted {
    const TOPICS: &'static [&'static str] =
        &[MULTISIG_OPERATION_EXECUTED_TOPIC];
}

impl dusk_forge::ContractEvent for MultisigOperationCancelled {
    const TOPICS: &'static [&'static str] =
        &[MULTISIG_OPERATION_CANCELLED_TOPIC];
}

impl dusk_forge::ContractEvent for MultisigAuthorityUpdated {
    const TOPICS: &'static [&'static str] = &[MULTISIG_AUTHORITY_UPDATED_TOPIC];
}

impl dusk_forge::ContractEvent for MultisigTimeLimitsUpdated {
    const TOPICS: &'static [&'static str] =
        &[MULTISIG_TIME_LIMITS_UPDATED_TOPIC];
}

/// Standalone multisig controller primitive.
///
/// This state machine tracks operation proposals and confirmations. It does
/// not call target contracts itself; Forge wrappers perform the runtime call
/// after this primitive returns a ready operation.
#[derive(Clone, Debug)]
pub struct MultisigController {
    policy: ThresholdMultisig,
    proposal_ttl: u64,
    tombstone_ttl: u64,
    proposals: BTreeMap<MultisigOperationId, MultisigPendingOperation>,
    tombstones: BTreeMap<MultisigOperationId, u64>,
}

impl MultisigController {
    /// Creates an uninitialized controller.
    pub const fn new() -> Self {
        Self {
            policy: ThresholdMultisig::new(),
            proposal_ttl: 0,
            tombstone_ttl: 0,
            proposals: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        }
    }

    /// Initializes the controller.
    pub fn init(&mut self, config: MultisigControllerConfig) {
        if self.is_initialized() {
            panic!("{}", error::ALREADY_INITIALIZED);
        }
        validate_time_limits(config.proposal_ttl, config.tombstone_ttl);
        self.policy.init(MultisigConfig {
            owners: config.owners,
            threshold: config.threshold,
        });
        self.proposal_ttl = config.proposal_ttl;
        self.tombstone_ttl = config.tombstone_ttl;
    }

    /// Returns true when the controller is initialized.
    pub fn is_initialized(&self) -> bool {
        !self.policy.is_empty() && self.policy.threshold() != 0
    }

    /// Returns owners in stable order.
    pub fn owners(&self) -> Vec<Principal> {
        self.policy.owners()
    }

    /// Returns the current threshold.
    pub const fn threshold(&self) -> Threshold {
        self.policy.threshold()
    }

    /// Returns the proposal TTL.
    pub const fn proposal_ttl(&self) -> u64 {
        self.proposal_ttl
    }

    /// Returns the tombstone TTL.
    pub const fn tombstone_ttl(&self) -> u64 {
        self.tombstone_ttl
    }

    /// Returns true when `principal` is an owner.
    pub fn is_owner(&self, principal: Principal) -> bool {
        self.policy.is_owner(principal)
    }

    /// Returns a pending proposal.
    pub fn proposal(
        &self,
        id: MultisigOperationId,
    ) -> Option<MultisigPendingOperation> {
        self.proposals.get(&id).cloned()
    }

    /// Returns a tombstone expiry.
    pub fn tombstone_expiry(&self, id: MultisigOperationId) -> Option<u64> {
        self.tombstones.get(&id).copied()
    }

    /// Verifies an action-bound threshold of owner approvals.
    pub fn authorize_action(
        &self,
        authorizations: &mut AuthorizationManager,
        context: CallContext,
        approvals: &[SignedAuthorization],
        envelope: ActionEnvelope,
        now: u64,
    ) -> Vec<Principal> {
        self.policy.authorize_action(
            authorizations,
            context,
            approvals,
            envelope,
            now,
        )
    }

    /// Verifies an action-bound threshold of owner approvals without consuming
    /// nonce or replay state.
    pub fn verify_action(
        &self,
        authorizations: &AuthorizationManager,
        context: CallContext,
        approvals: &[SignedAuthorization],
        envelope: ActionEnvelope,
        now: u64,
    ) -> Vec<Principal> {
        self.policy.verify_action(
            authorizations,
            context,
            approvals,
            envelope,
            now,
        )
    }

    /// Proposes an operation and records the first confirmation.
    pub fn propose(
        &mut self,
        id: MultisigOperationId,
        target: MultisigTarget,
        authorizer: Principal,
        now: u64,
    ) -> MultisigControllerOutcome {
        self.assert_initialized();
        self.assert_owner(authorizer);
        validate_target(&target);
        self.prune(now);
        self.assert_not_tombstoned(id);

        if self.proposals.contains_key(&id) {
            return self.confirm_pending(id, authorizer, now);
        }

        let deadline =
            now.checked_add(self.proposal_ttl).expect(error::OVERFLOW);
        self.proposals.insert(
            id,
            MultisigPendingOperation {
                target,
                confirmations: vec![authorizer],
                deadline,
            },
        );

        self.finish_if_ready(
            id,
            authorizer,
            MultisigControllerStatus::Proposed,
            deadline,
            now,
        )
    }

    /// Confirms a pending operation.
    pub fn confirm(
        &mut self,
        id: MultisigOperationId,
        authorizer: Principal,
        now: u64,
    ) -> MultisigControllerOutcome {
        self.assert_initialized();
        self.assert_owner(authorizer);
        self.prune(now);
        self.assert_not_tombstoned(id);
        self.confirm_pending(id, authorizer, now)
    }

    /// Cancels a pending operation after a current owner quorum authorizes it.
    pub fn cancel(
        &mut self,
        id: MultisigOperationId,
        signers: &[Principal],
        now: u64,
    ) -> MultisigOperationCancelled {
        self.assert_initialized();
        self.policy.assert_quorum(signers);
        self.prune(now);
        if self.proposals.remove(&id).is_none() {
            panic!("{}", error::OPERATION_UNKNOWN);
        }
        MultisigOperationCancelled {
            id,
            signers: signers.to_vec(),
        }
    }

    /// Updates owners and threshold after a current owner quorum authorizes it.
    ///
    /// Pending operations are removed when an owner is removed or the threshold
    /// changes, because old confirmations may no longer represent the new
    /// authority.
    pub fn update_authority(
        &mut self,
        signers: &[Principal],
        owners: Vec<Principal>,
        threshold: Threshold,
    ) -> MultisigAuthorityUpdated {
        self.assert_initialized();
        self.policy.assert_quorum(signers);

        let previous_owners = self.owners();
        let previous_threshold = self.threshold();
        let mut next = ThresholdMultisig::new();
        next.init(MultisigConfig { owners, threshold });
        let next_owners = next.owners();

        let removed_owner =
            previous_owners.iter().any(|owner| !next.is_owner(*owner));
        let threshold_changed = previous_threshold != next.threshold();
        let removed_operations = if removed_owner || threshold_changed {
            self.clear_pending()
        } else {
            Vec::new()
        };

        self.policy = next;

        MultisigAuthorityUpdated {
            previous_owners,
            previous_threshold,
            owners: next_owners,
            threshold,
            removed_operations,
        }
    }

    /// Updates time limits after a current owner quorum authorizes it.
    pub fn set_time_limits(
        &mut self,
        signers: &[Principal],
        proposal_ttl: u64,
        tombstone_ttl: u64,
    ) -> MultisigTimeLimitsUpdated {
        self.assert_initialized();
        self.policy.assert_quorum(signers);
        validate_time_limits(proposal_ttl, tombstone_ttl);

        let event = MultisigTimeLimitsUpdated {
            previous_proposal_ttl: self.proposal_ttl,
            previous_tombstone_ttl: self.tombstone_ttl,
            proposal_ttl,
            tombstone_ttl,
        };
        self.proposal_ttl = proposal_ttl;
        self.tombstone_ttl = tombstone_ttl;
        event
    }

    fn confirm_pending(
        &mut self,
        id: MultisigOperationId,
        authorizer: Principal,
        now: u64,
    ) -> MultisigControllerOutcome {
        let deadline = {
            let operation = self
                .proposals
                .get_mut(&id)
                .unwrap_or_else(|| panic!("{}", error::OPERATION_UNKNOWN));
            if now > operation.deadline {
                panic!("{}", error::DELAY_NOT_ELAPSED);
            }
            if operation.confirmed_by(authorizer) {
                panic!("{}", error::UNAUTHORIZED);
            }
            operation.confirmations.push(authorizer);
            operation.deadline
        };

        self.finish_if_ready(
            id,
            authorizer,
            MultisigControllerStatus::Confirmed,
            deadline,
            now,
        )
    }

    fn finish_if_ready(
        &mut self,
        id: MultisigOperationId,
        authorizer: Principal,
        status: MultisigControllerStatus,
        deadline: u64,
        now: u64,
    ) -> MultisigControllerOutcome {
        let confirmations = self
            .proposals
            .get(&id)
            .unwrap_or_else(|| panic!("{}", error::OPERATION_UNKNOWN))
            .confirmations
            .len();
        let mut status = status;
        let ready_operation =
            if confirmations >= usize::from(self.policy.threshold()) {
                status = MultisigControllerStatus::Ready;
                let operation = self
                    .proposals
                    .remove(&id)
                    .expect("ready operation must be pending");
                self.tombstones.insert(
                    id,
                    now.checked_add(self.tombstone_ttl).expect(error::OVERFLOW),
                );
                Some(operation)
            } else {
                None
            };

        MultisigControllerOutcome {
            id,
            authorizer,
            status,
            confirmations: confirmations as u16,
            threshold: self.policy.threshold(),
            deadline,
            ready_operation,
        }
    }

    fn assert_initialized(&self) {
        if !self.is_initialized() {
            panic!("{}", error::NOT_INITIALIZED);
        }
    }

    fn assert_owner(&self, authorizer: Principal) {
        if !self.policy.is_owner(authorizer) {
            panic!("{}", error::UNAUTHORIZED);
        }
    }

    fn assert_not_tombstoned(&self, id: MultisigOperationId) {
        if self.tombstones.contains_key(&id) {
            panic!("{}", error::REPLAY);
        }
    }

    fn prune(&mut self, now: u64) {
        self.proposals
            .retain(|_, operation| now <= operation.deadline);
        self.tombstones.retain(|_, expiry| now <= *expiry);
    }

    fn clear_pending(&mut self) -> Vec<MultisigOperationId> {
        let proposals = mem::take(&mut self.proposals);
        proposals.into_keys().collect()
    }
}

impl Default for MultisigController {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_time_limits(proposal_ttl: u64, tombstone_ttl: u64) {
    if proposal_ttl == 0 || tombstone_ttl == 0 {
        panic!("{}", error::INVALID_OPERATION);
    }
}

fn validate_target(target: &MultisigTarget) {
    if target
        .call
        .contract
        .to_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || target.call.fn_name.is_empty()
    {
        panic!("{}", error::INVALID_OPERATION);
    }
}
