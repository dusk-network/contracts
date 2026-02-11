// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use dusk_core::abi::{self, ContractId, CONTRACT_ID_BYTES};
use dusk_core::signatures::bls::{MultisigSignature, PublicKey};
use multisig_core::{
    error, events, InitArgs, OpId, Operation, SetAuthority, SetTimeLimits,
    Target, MAX_ADMINS,
};

use crate::has_duplicates;

/// Bounded pruning to avoid unbounded work inside `propose()`.
const MAX_TOMBSTONES_TO_PRUNE: u32 = 32;
const MAX_PROPOSALS_TO_PRUNE: u32 = 32;

/// Uninitialized contract ID constant.
const UNINITIALIZED_CONTRACT_ID: ContractId =
    ContractId::from_bytes([0u8; CONTRACT_ID_BYTES]);

/// The state of the `MultiSigV2` contract.
///
/// # Overview
///
/// `MultiSigV2` implements a multi-signature authorization layer for the Dusk
/// network. It does not hold or move funds, but coordinates admin confirmations
/// for arbitrary operations and, once the required threshold is reached,
/// executes the operation on the target contract.
///
/// ## Core Logic
/// - Manages a set of admin public keys and enforces a signature threshold
///   (e.g., 2-of-3, 3-of-5).
/// - Admins can propose new operations or confirm pending ones. A new proposal
///   also counts as first confirmation.
/// - Tracks pending proposals, each identified by a stable operation `id``
///   which is a hash of:
///   - multisig contract id
///   - target contract id
///   - function name
///   - function arguments
///   - salt (for intentional duplication)
/// - Duplicate proposals (for the same `id`) are counted as confirmations for
///   such operation.
/// - Confirmations are accumulated until reaching the target threshold.
/// - As soon as the number of unique admin confirmations for a proposal reaches
///   the threshold, the target call is executed automatically.
/// - After execution, a tombstone is recorded for `replay_window_blocks` to
///   prevent accidental duplicate proposals.
/// - Proposals have a TTL (time-to-live) in blocks; expired proposals can be
///   deleted.
/// - Multiple pending proposals can exist at the same time.
/// - To allow multiple proposals of the same operation, a `salt` can be used to
///   differentiate their `op_id`.
///
/// ## Security and Trust Model
/// - The contract does not store funds or tokens; it only authorizes actions on
///   a target contract that must explicitly trust this multisig.
/// - All interactions require a public (Moonlight) transaction and a direct
///   call from a registered admin.
/// - Expiration prevents stale confirmations from being kept in the state.
/// - Tombstoning executed operations prevents accidental duplicate proposals.
/// - Protection from replay attacks is ensured by enforcing the use of public
///   transactions (which include a signed nonce).
///
/// ## Non-Goals
/// - Does not aggregate off-chain signatures, store assets, or implement a
///   wallet.
/// - Does not support meta-transactions, relayers, or account abstraction.
///
/// See the README for a full description of the proposal lifecycle, replay
/// protection, and usage patterns.
pub struct MultiSigV2 {
    /// List of authorized admins' public keys.
    admins: Vec<PublicKey>,

    /// Nonce for admin operations that require aggregated signatures.
    admin_nonce: u64,

    /// Threshold to use for new proposals.
    confirmation_threshold: u8,

    /// Threshold for admin operations.
    admin_threshold: u8,

    /// Number of blocks to keep a proposal without being executed.
    proposal_ttl: u64,

    /// Number of blocks to keep an operation tombstone after its execution.
    tombstone_ttl: u64,

    /// Pending operations keyed by `id`.
    proposals: BTreeMap<OpId, Operation>,

    /// Index to prune expired pending ops deterministically:
    /// `deadline_height` -> list of `ids` that (may) expire at that height.
    proposal_deadlines: BTreeMap<u64, Vec<OpId>>,

    /// Tombstones to prevent immediate accidental duplication after execution:
    /// `id` -> `expiry_height`.
    tombstones: BTreeMap<OpId, u64>,

    /// Index to prune expired tombstones deterministically:
    /// `expiry_height` -> list of `id`s that (may) expire at that height.
    tombstone_deadlines: BTreeMap<u64, Vec<OpId>>,

    /// This contract's own address.
    ///
    /// Stored in the state for efficiency purposes.
    this_address: ContractId,
}

/// The state of the `MultiSigV2` contract at deployment.
pub static mut STATE: MultiSigV2 = MultiSigV2::new();

enum OperationStatus<'a> {
    Pending(&'a mut Operation),
    Executed,
    Expired,
    Unknown,
}

/// Basic contract implementation.
impl MultiSigV2 {
    /// Creates a new `MultiSigV2` contract state.
    #[must_use]
    const fn new() -> Self {
        Self {
            admins: Vec::new(),
            admin_nonce: 0,
            admin_threshold: 0,
            confirmation_threshold: 0,
            proposal_ttl: 0,
            tombstone_ttl: 0,
            proposals: BTreeMap::new(),
            proposal_deadlines: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            tombstone_deadlines: BTreeMap::new(),
            this_address: UNINITIALIZED_CONTRACT_ID,
        }
    }

    /// Initializes the `MultiSigV2` contract state.
    ///
    /// # Details
    /// Sets the initial admin public keys and signature threshold.
    ///
    /// # Parameters
    /// - `admins`: List of admin public keys.
    /// - `admin_threshold`: Threshold for admin operations.
    /// - `confirmation_threshold`: Required number of confirmations to execute
    ///   a pending operation.
    /// - `proposal_ttl`: Number of blocks a proposal remains valid.
    /// - `tombstone_ttl`: Number of blocks to prevent accidental duplication
    ///   after execution.
    ///
    /// # Panics
    /// - If already initialized
    /// - If admin set is empty or invalid (duplicates or too large)
    /// - If thresholds are 0 or exceed number of admins.
    /// - If time parameters are 0.
    pub fn init(&mut self, init: InitArgs) {
        let InitArgs {
            admins,
            admin_threshold,
            confirmation_threshold,
            proposal_ttl,
            tombstone_ttl,
        } = init;

        // panic if the contract has already been initialized
        assert!(self.admins.is_empty(), "{}", error::ALREADY_INITIALIZED);

        Self::check_admins(&admins);

        assert_ne!(
            confirmation_threshold, 0,
            "Cannot set confirmation_threshold to zero"
        );
        assert_ne!(admin_threshold, 0, "Cannot set admin_threshold to zero");
        assert_ne!(proposal_ttl, 0, "Cannot set proposal_ttl to zero");
        assert_ne!(tombstone_ttl, 0, "Cannot set tombstone_ttl to zero");

        assert!(
            (confirmation_threshold as usize) <= admins.len(),
            "Confirmation threshold cannot be larger than admin count"
        );

        self.this_address = abi::self_id();
        assert_ne!(
            self.this_address, UNINITIALIZED_CONTRACT_ID,
            "Cannot get contract ID"
        );

        self.admins = admins;
        self.confirmation_threshold = confirmation_threshold;
        self.proposal_ttl = proposal_ttl;
        self.tombstone_ttl = tombstone_ttl;
    }

    /// Retrieves the current set of admin keys.
    ///
    /// # Returns
    /// A vector of admin public keys.
    #[must_use]
    pub fn admins(&self) -> Vec<PublicKey> {
        self.admins.clone()
    }

    /// Returns the threshold for operation proposals.
    #[must_use]
    pub fn confirmation_threshold(&self) -> u8 {
        self.confirmation_threshold
    }

    /// Returns the threshold for admin operations.
    #[must_use]
    pub fn admin_threshold(&self) -> u8 {
        self.admin_threshold
    }

    /// Retrieves the admin nonce used for admin-signed operations like
    /// `set_admins` and `set_thresholds`.
    #[must_use]
    pub fn admin_nonce(&self) -> u64 {
        self.admin_nonce
    }

    /// Retrieves the proposal TTL in blocks.
    #[must_use]
    pub fn proposal_ttl(&self) -> u64 {
        self.proposal_ttl
    }

    /// Retrieves the tombstone TTL in blocks.
    #[must_use]
    pub fn tombstone_ttl(&self) -> u64 {
        self.tombstone_ttl
    }

    /// Retrieve the pending operation for a given `id`.
    #[must_use]
    pub fn proposal(&self, id: OpId) -> Option<Operation> {
        self.proposals.get(&id).cloned()
    }

    /// Retrieves all the pending proposals in form of `(OpId, Operation)`.
    ///
    /// This method requires the `ABI::feed` function to return the list.
    pub fn feed_proposals(&self) {
        for (id, op) in &self.proposals {
            abi::feed((*id, op.clone()));
        }
    }

    /// Retrieves all the tombstoned operation IDs together with their expiry
    /// heights.
    ///
    /// This method requires the `ABI::feed` function to return the list.
    pub fn feed_tombstones(&self) {
        for (id, expiry) in &self.tombstones {
            abi::feed((*id, *expiry));
        }
    }

    /// Returns the public address who initiated the transaction.
    ///
    /// Asserts that:
    /// - The call comes directly from a transaction (not via another contract)
    /// - The transaction is not shielded.
    /// - The sender is a registered admin.
    fn get_direct_admin(&self) -> PublicKey {
        assert!(abi::callstack().len() == 1, "Indirect call not allowed");

        let sender =
            abi::public_sender().expect("Shielded transactions not allowed");
        assert!(self.admins.contains(&sender), "Not an admin");
        sender
    }

    /// Compute a unique operation identifier.
    ///
    /// The identifier is obtained by hashing the target call data with the
    /// `salt` value.
    fn compute_id(target: &Target) -> OpId {
        let mut bytes = target.call.to_var_bytes();
        bytes.extend_from_slice(&target.salt);
        let hash = abi::keccak256(bytes);
        OpId(hash)
    }

    /// Insert a tombstone for `id` to prevent immediate replay after
    /// execution.
    fn insert_tombstone(&mut self, id: OpId) {
        let now = abi::block_height();
        let expiry = now
            .checked_add(self.tombstone_ttl)
            .expect("Tombstone expiry overflow");

        self.tombstones.insert(id, expiry);
        self.tombstone_deadlines.entry(expiry).or_default().push(id);
    }

    /// Prune expired tombstones in a bounded way to mitigate Out-of-Gas while
    /// cleaning.
    fn prune_tombstones(&mut self) {
        let now = abi::block_height();
        let mut pruned = 0;

        while pruned < MAX_TOMBSTONES_TO_PRUNE {
            let Some((&expiry, _)) = self.tombstone_deadlines.iter().next()
            else {
                break; // no more tombstones
            };

            if expiry > now {
                break; // next tombstone not expired
            }

            let mut ids = self
                .tombstone_deadlines
                .remove(&expiry)
                .expect("tombstone bucket must exist");

            while pruned < MAX_TOMBSTONES_TO_PRUNE && !ids.is_empty() {
                let id = ids.pop().expect("id to be present");
                self.tombstones.remove(&id);
                pruned += 1;
            }

            // If we didn't fully empty the `expiry` bucket, let's put it back
            if !ids.is_empty() {
                self.tombstone_deadlines.insert(expiry, ids);
                break;
            }
        }
    }

    /// Prune expired pending operations in a bounded way to mitigate Out-of-Gas
    /// while cleaning.
    fn prune_proposals(&mut self) {
        let now = abi::block_height();
        let mut pruned = 0;

        while pruned < MAX_PROPOSALS_TO_PRUNE {
            let Some((&deadline, _)) = self.proposal_deadlines.iter().next()
            else {
                break; // no more pendings
            };

            if deadline > now {
                break; // next pending not expired
            }

            let mut ids = self
                .proposal_deadlines
                .remove(&deadline)
                .expect("pending bucket must exist");

            while pruned < MAX_PROPOSALS_TO_PRUNE && !ids.is_empty() {
                let id = ids.pop().expect("not empty");
                self.proposals.remove(&id);
                pruned += 1;
            }

            // If we didn't fully empty the `expiry` bucket, let's put it back
            if !ids.is_empty() {
                self.proposal_deadlines.insert(deadline, ids);
                break;
            }
        }
    }

    /// Retrieve the status of an operation to confirm.
    ///
    /// # Returns
    /// - `OperationStatus::Pending(&mut Operation)` if the operation is
    ///   pending.
    /// - `OperationStatus::Executed` if the operation has been executed.
    /// - `OperationStatus::Expired` if the operation has expired.
    /// - `OperationStatus::Unknown` if the operation is not found.
    fn get_operation_to_confirm(&mut self, id: &OpId) -> OperationStatus {
        match self.proposals.get_mut(id) {
            None => {
                if self.tombstones.contains_key(id) {
                    OperationStatus::Executed
                } else {
                    OperationStatus::Unknown
                }
            }
            Some(p) => {
                if abi::block_height() > p.deadline {
                    OperationStatus::Expired
                } else {
                    OperationStatus::Pending(p)
                }
            }
        }
    }

    /// Create or merge a proposal, keyed by `id`.
    ///
    /// Semantics:
    /// - direct public admin call required
    /// - if `id` is tombstoned (recently executed) => panic
    /// - if `id` is pending => merge confirmation (idempotent)
    /// - else create pending with deadline = now + `proposal_ttl_blocks`
    /// - auto-exec when threshold is reached
    pub fn propose(&mut self, target: Target) {
        let from = self.get_direct_admin();

        assert!(self.confirmation_threshold > 0, "Threshold not configured");
        assert!(self.proposal_ttl > 0, "TTL not configured");
        assert!(self.tombstone_ttl > 0, "Replay window not configured");

        self.prune_tombstones();
        self.prune_proposals();

        let id = Self::compute_id(&target);

        let topic = match self.get_operation_to_confirm(&id) {
            OperationStatus::Executed | OperationStatus::Expired => return, /* noop */
            OperationStatus::Unknown => {
                let deadline = abi::block_height()
                    .checked_add(self.proposal_ttl)
                    .expect("Adding ttl should not overflow");
                let confirmations = vec![from];

                let op = Operation {
                    target,
                    confirmations,
                    deadline,
                };

                self.proposals.insert(id, op);
                self.proposal_deadlines
                    .entry(deadline)
                    .or_default()
                    .push(id);
                events::MultisigOperation::PROPOSED
            }
            OperationStatus::Pending(pending) => {
                assert!(!pending.confirmed_by(&from), "Already confirmed");
                pending.confirmations.push(from);
                events::MultisigOperation::CONFIRMED
            }
        };
        abi::emit(topic, events::MultisigOperation { id, from });

        self.try_execute(&id);
    }

    /// Confirm an existing proposal.
    ///
    /// Semantics:
    /// - panic if `id` does not exist
    /// - idempotent noop if already confirmed or expired
    /// - auto-exec when threshold is reached
    pub fn confirm(&mut self, id: OpId) {
        let from = self.get_direct_admin();

        self.prune_tombstones();
        self.prune_proposals();

        let pending = match self.get_operation_to_confirm(&id) {
            OperationStatus::Executed | OperationStatus::Expired => return, /* noop */
            OperationStatus::Unknown => panic!("Operation not found"),
            OperationStatus::Pending(pending) => pending,
        };

        if !pending.confirmed_by(&from) {
            pending.confirmations.push(from);

            abi::emit(
                events::MultisigOperation::CONFIRMED,
                events::MultisigOperation { id, from },
            );
        }

        self.try_execute(&id);
    }

    /// Attempts to execute a proposal if threshold is reached.
    fn try_execute(&mut self, id: &OpId) {
        let now = abi::block_height();

        let pending = self
            .proposals
            .get(id)
            .expect("trying executing a no-pending operation - maybe a bug?");

        // Never execute expired proposals.
        assert!(
            now <= pending.deadline,
            "Pending operation expired - maybe a bug?"
        );

        if pending.confirmations.len() < self.confirmation_threshold as usize {
            return;
        }

        let id = *id;

        abi::emit(events::MultisigOperation::EXECUTING, id);

        let call = &pending.target.call;

        // Execute (panic on failure should NOT revert this state).
        let error = abi::call_raw(call.contract, &call.fn_name, &call.fn_args)
            .err()
            .map(|e| format!("{e}"));
        let result = events::ExecutionResult { id, error };
        abi::emit(events::ExecutionResult::EXECUTED, result);

        // Cleanup pending state.
        self.proposal_deadlines
            .entry(pending.deadline)
            .and_modify(|ids| ids.retain(|pending_id| *pending_id != id));
        self.proposals
            .remove(&id)
            .expect("pending to exists at this point");

        // Insert tombstone to block immediate replay.
        self.insert_tombstone(id);
    }
}

// Methods that need the admins' operations.
impl MultiSigV2 {
    /// Validates a new set of admin public keys.
    ///
    /// # Panics
    /// - If admin set is empty or invalid (duplicates or too large)
    /// - If any admin public key is invalid.
    fn check_admins(admins: &[PublicKey]) {
        // panic if no admins are given
        assert!(!admins.is_empty(), "{}", error::EMPTY_ADMINS);
        // panic if more than `MAX_ADMINS` admins are given
        assert!(admins.len() <= MAX_ADMINS, "{}", error::TOO_MANY_ADMINS);
        // panic if there are duplicate admins
        assert!(!has_duplicates(admins), "{}", error::DUPLICATE_ADMIN);

        for pk in admins {
            assert!(pk.is_valid(), "Invalid admin");
        }
    }

    /// Updates the admin public keys.
    ///
    /// # Details
    /// Requires majority admin signatures.
    ///
    /// # Parameters
    /// - [`SetAuthority`]: Struct containing the new admin public keys,
    ///   aggregated admin signature, and indices of signing admins.
    ///
    /// # Panics
    /// Panics if signature is invalid, signature threshold is not met or the
    /// new admin keys list is invalid
    pub fn set_authority(&mut self, args: SetAuthority) {
        let SetAuthority {
            chain_id,
            new_admins,
            new_admin_threshold,
            new_threshold,
            sig,
            signers,
        } = args;
        assert!(chain_id == abi::chain_id(), "Invalid chain id");
        Self::check_admins(&new_admins);
        // panic if the thresholds exceed the number of admins
        assert!(
            new_threshold as usize <= new_admins.len(),
            "{}",
            error::THRESHOLD_EXCEEDS_ADMINS
        );
        assert!(
            new_admin_threshold as usize <= new_admins.len(),
            "{}",
            error::THRESHOLD_EXCEEDS_ADMINS
        );

        assert_ne!(
            new_threshold, 0,
            "Cannot set confirmation threshold to zero"
        );
        assert_ne!(
            new_admin_threshold, 0,
            "Cannot set admin threshold to zero"
        );

        // check the signature
        let sig_msg = SetAuthority::signature_message(
            chain_id,
            self.admin_nonce,
            &self.this_address,
            new_admin_threshold,
            new_threshold,
            &new_admins,
        );
        self.verify_sig(self.admin_threshold, sig_msg, sig, signers);

        let prev_admin_threshold =
            core::mem::replace(&mut self.admin_threshold, new_admin_threshold);
        let prev_threshold =
            core::mem::replace(&mut self.confirmation_threshold, new_threshold);

        // update the admins to the new set
        let prev_admins =
            core::mem::replace(&mut self.admins, new_admins.clone());

        // alert network of the changes to the state
        abi::emit(
            events::UpdateAuthority::TOPIC,
            events::UpdateAuthority {
                prev_admins,
                prev_admin_threshold,
                prev_threshold,
                new_admins,
                new_admin_threshold,
                new_threshold,
            },
        );

        // increment the admins nonce
        self.admin_nonce += 1;

        // Remove all the pending proposals that are no more valid due to the
        // change in the admin set. For each removed proposal, emit an
        // event with the removed proposal id.
        let removed = core::mem::take(&mut self.proposals);
        let _ = core::mem::take(&mut self.proposal_deadlines);
        for id in removed.into_keys() {
            abi::emit(events::MultisigOperation::REMOVED, id);
        }
    }

    /// Updates the proposal TTL and replay window parameters.
    ///
    /// # Details
    /// Requires majority admin signatures.
    ///
    /// # Parameters
    /// - [`SetTimeLimits`]: Struct containing the new parameters, aggregated
    ///   admin signature, and indices of signing admins.
    ///
    /// # Panics
    /// Panics if signature is invalid, threshold is not met or parameters are
    /// invalid.
    pub fn set_time_limits(&mut self, args: SetTimeLimits) {
        let SetTimeLimits {
            chain_id,
            proposal_ttl_blocks,
            replay_window_blocks,
            sig,
            signers,
        } = args;

        assert!(chain_id == abi::chain_id(), "Invalid chain id");
        assert!(proposal_ttl_blocks > 0, "Invalid proposal TTL");
        assert!(replay_window_blocks > 0, "Invalid replay window");

        let sig_msg = SetTimeLimits::signature_message(
            chain_id,
            self.admin_nonce,
            &self.this_address,
            proposal_ttl_blocks,
            replay_window_blocks,
        );

        self.verify_sig(self.admin_threshold, sig_msg, sig, signers);

        let prev_proposal_ttl_blocks =
            core::mem::replace(&mut self.proposal_ttl, proposal_ttl_blocks);
        let prev_replay_window_blocks =
            core::mem::replace(&mut self.tombstone_ttl, replay_window_blocks);

        self.admin_nonce += 1;

        abi::emit(
            events::UpdateTimeLimits::TOPIC,
            events::UpdateTimeLimits {
                prev_proposal_ttl_blocks,
                prev_replay_window_blocks,
                proposal_ttl_blocks,
                replay_window_blocks,
            },
        );
    }
}

/// Authorization helpers
impl MultiSigV2 {
    /// Verifies admin signatures and threshold.
    ///
    /// # Details
    /// Checks that the aggregated admin signature is valid and the threshold is
    /// met.
    ///
    /// # Parameters
    /// - `threshold`: Required number of signatures.
    /// - `sig_msg`: Signature message.
    /// - `sig`: Aggregated signature.
    /// - `signers`: Indices of signing admins.
    ///
    /// # Panics
    /// Panics if signature is invalid, threshold is not met, or signers are
    /// invalid.
    pub fn verify_sig(
        &self,
        threshold: u8,
        sig_msg: Vec<u8>,
        sig: MultisigSignature,
        signers: impl AsRef<[u8]>,
    ) {
        let signer_idxs = signers.as_ref();

        // threshold should never be 0
        assert!(threshold > 0, "{}", error::THRESHOLD_ZERO);

        // panic if the signers contain duplicates
        assert!(!has_duplicates(signer_idxs), "{}", error::DUPLICATE_SIGNER);

        // panic if the threshold of signers is not met
        assert!(
            signer_idxs.len() >= threshold as usize,
            "{}",
            error::THRESHOLD_NOT_MET
        );

        let signers = signer_idxs
            .iter()
            .map(|index| {
                self.admins
                    .get(*index as usize)
                    .copied()
                    // panic if one of the signer's indices doesn't exist
                    .expect(error::SIGNER_NOT_FOUND)
            })
            .collect::<Vec<_>>();

        // verify the signature
        assert!(
            abi::verify_bls_multisig(sig_msg, signers, sig),
            "{}",
            error::INVALID_SIGNATURE
        );
    }
}
