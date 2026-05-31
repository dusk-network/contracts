// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Phoenix-style private fungible token primitive.
//!
//! `DRC20Phoenix` is deliberately not a public-balance DRC20 variant. It is a
//! private note/nullifier asset model inspired by the genesis transfer
//! contract's Phoenix state machine, but with custom-asset domain separation
//! and without native DUSK transaction semantics such as gas refunds or
//! deposits.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use dusk_core::abi::ContractId;
use dusk_core::BlsScalar;
use dusk_forge::ContractEvent;
#[cfg(not(all(target_family = "wasm", feature = "contract")))]
use dusk_poseidon::{Domain, Hash as PoseidonHash};
use rkyv::{Archive, Deserialize, Serialize};

/// Standard version bound into asset ids and proof intents.
pub const DRC20_PHOENIX_VERSION: u32 = 1;

const ROOT_WINDOW_DEFAULT: usize = 64;
/// Fixed Merkle tree height used by the v1 verifier artifacts.
///
/// Height 23 gives 8,388,608 note slots. That keeps the note/nullifier state in
/// the right order of magnitude for a 3 GB storage budget with the current note
/// representation while leaving room for wallet sync metadata and roots.
pub const DRC20_PHOENIX_TREE_HEIGHT: usize = 23;

/// V1 proof arity: public mint with one private output.
pub const V1_MINT_0_1: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Mint, 0, 1);
/// V1 proof arity: public mint with two private outputs.
pub const V1_MINT_0_2: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Mint, 0, 2);
/// V1 proof arity: private transfer with one input and two outputs.
pub const V1_TRANSFER_1_2: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Transfer, 1, 2);
/// V1 proof arity: private transfer with two inputs and two outputs.
pub const V1_TRANSFER_2_2: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Transfer, 2, 2);
/// V1 proof arity: private transfer with three inputs and two outputs.
pub const V1_TRANSFER_3_2: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Transfer, 3, 2);
/// V1 proof arity: private transfer with four inputs and two outputs.
pub const V1_TRANSFER_4_2: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Transfer, 4, 2);
/// V1 proof arity: private burn with one input and no change output.
pub const V1_BURN_1_0: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 1, 0);
/// V1 proof arity: private burn with one input and one change output.
pub const V1_BURN_1_1: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 1, 1);
/// V1 proof arity: private burn with one input and two change outputs.
pub const V1_BURN_1_2: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 1, 2);
/// V1 proof arity: private burn with two inputs and no change output.
pub const V1_BURN_2_0: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 2, 0);
/// V1 proof arity: private burn with two inputs and one change output.
pub const V1_BURN_2_1: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 2, 1);
/// V1 proof arity: private burn with two inputs and two change outputs.
pub const V1_BURN_2_2: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 2, 2);
/// V1 proof arity: private burn with three inputs and no change output.
pub const V1_BURN_3_0: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 3, 0);
/// V1 proof arity: private burn with three inputs and one change output.
pub const V1_BURN_3_1: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 3, 1);
/// V1 proof arity: private burn with three inputs and two change outputs.
pub const V1_BURN_3_2: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 3, 2);
/// V1 proof arity: private burn with four inputs and no change output.
pub const V1_BURN_4_0: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 4, 0);
/// V1 proof arity: private burn with four inputs and one change output.
pub const V1_BURN_4_1: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 4, 1);
/// V1 proof arity: private burn with four inputs and two change outputs.
pub const V1_BURN_4_2: PrivateAssetVerifierKey =
    PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 4, 2);

/// Supported v1 proof arities.
pub const V1_SUPPORTED_ARITIES: &[PrivateAssetVerifierKey] = &[
    V1_MINT_0_1,
    V1_MINT_0_2,
    V1_TRANSFER_1_2,
    V1_TRANSFER_2_2,
    V1_TRANSFER_3_2,
    V1_TRANSFER_4_2,
    V1_BURN_1_0,
    V1_BURN_1_1,
    V1_BURN_1_2,
    V1_BURN_2_0,
    V1_BURN_2_1,
    V1_BURN_2_2,
    V1_BURN_3_0,
    V1_BURN_3_1,
    V1_BURN_3_2,
    V1_BURN_4_0,
    V1_BURN_4_1,
    V1_BURN_4_2,
];

/// Event topic for private mints.
pub const PRIVATE_MINT_TOPIC: &str = "drc20_phoenix/private_mint";
/// Event topic for private transfers.
pub const PRIVATE_TRANSFER_TOPIC: &str = "drc20_phoenix/private_transfer";
/// Event topic for private burns.
pub const PRIVATE_BURN_TOPIC: &str = "drc20_phoenix/private_burn";
/// Event topic for pause.
pub const PAUSED_TOPIC: &str = "drc20_phoenix/paused";
/// Event topic for unpause.
pub const UNPAUSED_TOPIC: &str = "drc20_phoenix/unpaused";

/// Stable admin id used by the standalone primitive.
///
/// Reference contracts can map this to a Moonlight principal, Phoenix
/// authorization, multisig contract id, or any higher-level authorization
/// module.
pub type AdminId = [u8; 32];

/// Contract errors.
pub mod error {
    /// Token has already been initialized.
    pub const ALREADY_INITIALIZED: &str = "DRC20Phoenix: already initialized";
    /// Token has not been initialized.
    pub const NOT_INITIALIZED: &str = "DRC20Phoenix: not initialized";
    /// Caller is not authorized.
    pub const UNAUTHORIZED: &str = "DRC20Phoenix: unauthorized";
    /// Token is paused.
    pub const PAUSED: &str = "DRC20Phoenix: paused";
    /// Token is not paused.
    pub const NOT_PAUSED: &str = "DRC20Phoenix: not paused";
    /// A zero or malformed value was supplied.
    pub const INVALID_VALUE: &str = "DRC20Phoenix: invalid value";
    /// Asset domain does not match this token.
    pub const INVALID_DOMAIN: &str = "DRC20Phoenix: invalid domain";
    /// Root is unknown or no longer retained.
    pub const UNKNOWN_ROOT: &str = "DRC20Phoenix: unknown root";
    /// Nullifier has already been spent or appears twice in a transaction.
    pub const NULLIFIER_REPLAY: &str = "DRC20Phoenix: nullifier replay";
    /// Note commitment or note domain is invalid.
    pub const MALFORMED_NOTE: &str = "DRC20Phoenix: malformed note";
    /// Proof public inputs do not match the call.
    pub const PUBLIC_INPUT_MISMATCH: &str =
        "DRC20Phoenix: public input mismatch";
    /// Proof verification failed.
    pub const INVALID_PROOF: &str = "DRC20Phoenix: invalid proof";
    /// Verifier config is malformed.
    pub const INVALID_VERIFIER_CONFIG: &str =
        "DRC20Phoenix: invalid verifier config";
    /// No verifier exists for the requested arity.
    pub const UNSUPPORTED_ARITY: &str = "DRC20Phoenix: unsupported arity";
    /// Supply cap would be exceeded.
    pub const CAP_EXCEEDED: &str = "DRC20Phoenix: cap exceeded";
    /// Arithmetic overflow or underflow.
    pub const ARITHMETIC: &str = "DRC20Phoenix: arithmetic error";
}

/// Token metadata shared with DRC20-like assets.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct TokenMetadata {
    /// Display name.
    pub name: String,
    /// Ticker symbol.
    pub symbol: String,
    /// Decimal precision.
    pub decimals: u8,
}

/// Initialization parameters.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct Init {
    /// Token metadata.
    pub metadata: TokenMetadata,
    /// Dusk chain id this asset is bound to.
    pub chain_id: u8,
    /// Contract id this asset is bound to.
    pub contract_id: ContractId,
    /// Deployment salt included in asset-id derivation.
    pub deployment_salt: [u8; 32],
    /// Mint/pause admin.
    pub admin: AdminId,
    /// Optional public mint cap.
    pub cap: Option<u128>,
    /// Number of recent roots to retain. Zero uses the default.
    pub root_window: u16,
    /// Production verifier set for private asset circuits.
    pub verifier_set: Vec<PrivateAssetVerifierConfig>,
}

/// Private asset circuit mode.
#[derive(
    Archive,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub enum PrivateAssetCircuitMode {
    /// Public mint into private notes.
    Mint = 1,
    /// Private transfer between notes.
    Transfer = 2,
    /// Private burn from notes into public burn accounting.
    Burn = 3,
}

impl PrivateAssetCircuitMode {
    fn scalar(self) -> BlsScalar {
        BlsScalar::from(self as u64)
    }
}

/// Versioned verifier key used for production verifier dispatch.
#[derive(
    Archive,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateAssetVerifierKey {
    /// Standard/circuit version.
    pub version: u32,
    /// Circuit mode.
    pub mode: PrivateAssetCircuitMode,
    /// Fixed input-note count.
    pub input_count: u8,
    /// Fixed output-note count.
    pub output_count: u8,
}

impl PrivateAssetVerifierKey {
    /// Creates a v1 verifier key for a mode/arity pair.
    pub const fn new(
        mode: PrivateAssetCircuitMode,
        input_count: u8,
        output_count: u8,
    ) -> Self {
        Self {
            version: DRC20_PHOENIX_VERSION,
            mode,
            input_count,
            output_count,
        }
    }

    /// Returns true when this is one of the standard v1 arities.
    pub fn is_supported_v1(self) -> bool {
        V1_SUPPORTED_ARITIES.contains(&self)
    }

    fn scalars(self) -> [BlsScalar; 4] {
        [
            BlsScalar::from(self.version as u64),
            self.mode.scalar(),
            BlsScalar::from(self.input_count as u64),
            BlsScalar::from(self.output_count as u64),
        ]
    }
}

/// Production verifier data for one fixed arity.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateAssetVerifierConfig {
    /// Versioned mode/arity key.
    pub key: PrivateAssetVerifierKey,
    /// Verifier data bytes consumed by `abi::verify_plonk`.
    pub verifier_data: Vec<u8>,
    /// Expected verifier data hash.
    pub verifier_data_hash: BlsScalar,
}

impl PrivateAssetVerifierConfig {
    /// Builds a config and computes the pinned verifier data hash.
    pub fn new(key: PrivateAssetVerifierKey, verifier_data: Vec<u8>) -> Self {
        let verifier_data_hash =
            verifier_data_hash_for_key(key, &verifier_data);
        Self {
            key,
            verifier_data,
            verifier_data_hash,
        }
    }
}

/// Public verifier metadata returned by query APIs.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateAssetVerifierInfo {
    /// Versioned mode/arity key.
    pub key: PrivateAssetVerifierKey,
    /// Pinned verifier data hash.
    pub verifier_data_hash: BlsScalar,
}

/// Encrypted private note stored in the public note log.
///
/// The note value is not public. The `commitment` must equal
/// [`PrivateAssetNote::computed_commitment`], and the proof must bind each
/// output note to the public output commitments.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateAssetNote {
    /// Asset id this note belongs to.
    pub asset_id: BlsScalar,
    /// Recipient/view-key commitment or stealth address commitment.
    pub owner_commitment: BlsScalar,
    /// Pedersen-style value commitment.
    pub value_commitment: BlsScalar,
    /// Note nonce/randomizer.
    pub nonce: BlsScalar,
    /// Encrypted note payload for wallet scanning.
    pub encrypted_payload: Vec<u8>,
    /// Public note commitment inserted into the note tree.
    pub commitment: BlsScalar,
}

impl PrivateAssetNote {
    /// Creates a note and computes its commitment.
    pub fn new(
        asset_id: BlsScalar,
        owner_commitment: BlsScalar,
        value_commitment: BlsScalar,
        nonce: BlsScalar,
        encrypted_payload: Vec<u8>,
    ) -> Self {
        let mut note = Self {
            asset_id,
            owner_commitment,
            value_commitment,
            nonce,
            encrypted_payload,
            commitment: BlsScalar::from(0),
        };
        note.commitment = note.computed_commitment();
        note
    }

    /// Computes the domain-separated note commitment.
    pub fn computed_commitment(&self) -> BlsScalar {
        compute_note_commitment(
            self.asset_id,
            self.owner_commitment,
            self.value_commitment,
            self.nonce,
            encrypted_payload_hash(&self.encrypted_payload),
        )
    }

    /// Panics unless this note belongs to `asset_id` and is well formed.
    pub fn assert_well_formed(&self, asset_id: BlsScalar) {
        if self.asset_id != asset_id {
            panic!("{}", error::INVALID_DOMAIN);
        }
        if self.computed_commitment() != self.commitment {
            panic!("{}", error::MALFORMED_NOTE);
        }
    }
}

/// Note leaf returned by sync APIs.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateAssetLeaf {
    /// Block height when the note was appended.
    pub block_height: u64,
    /// Append-only note position.
    pub position: u64,
    /// Stored note.
    pub note: PrivateAssetNote,
}

/// Sibling in a Merkle opening.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct MerkleSibling {
    /// Sibling hash.
    pub hash: BlsScalar,
    /// True when the sibling is on the left of the running hash.
    pub is_left: bool,
}

/// Opening for a note commitment.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateNoteOpening {
    /// Note position.
    pub position: u64,
    /// Note commitment at the leaf.
    pub commitment: BlsScalar,
    /// Sibling path.
    pub siblings: Vec<MerkleSibling>,
}

impl PrivateNoteOpening {
    /// Computes the root represented by this opening.
    pub fn root(&self) -> BlsScalar {
        let mut current = self.commitment;
        for sibling in &self.siblings {
            current = if sibling.is_left {
                hash_pair(sibling.hash, current)
            } else {
                hash_pair(current, sibling.hash)
            };
        }
        current
    }

    /// Returns true when this opening resolves to `root`.
    pub fn verifies(&self, root: BlsScalar) -> bool {
        self.root() == root
    }
}

/// Public inputs for a private asset proof.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateAssetPublicInputs {
    /// Standard version.
    pub version: u32,
    /// Chain id.
    pub chain_id: u8,
    /// Token contract id.
    pub contract_id: ContractId,
    /// Token asset id.
    pub asset_id: BlsScalar,
    /// Circuit mode.
    pub mode: PrivateAssetCircuitMode,
    /// Historical root used for input notes.
    pub root: BlsScalar,
    /// Input nullifiers.
    pub nullifiers: Vec<BlsScalar>,
    /// Output note commitments.
    pub output_commitments: Vec<BlsScalar>,
    /// Public mint amount.
    pub public_mint_amount: u128,
    /// Public burn amount.
    pub public_burn_amount: u128,
    /// Intent hash binding the proof to this call.
    pub intent_hash: BlsScalar,
}

impl PrivateAssetPublicInputs {
    /// Converts inputs to the scalar vector consumed by `verify_plonk`.
    pub fn to_scalars(&self) -> Vec<BlsScalar> {
        let mut out = Vec::with_capacity(
            12 + self.nullifiers.len() + self.output_commitments.len(),
        );
        out.push(domain_scalar(b"DRC20Phoenix.public_inputs.v1"));
        out.push(BlsScalar::from(self.version as u64));
        out.push(BlsScalar::from(self.chain_id as u64));
        out.push(hash_bytes_with_domain(
            b"DRC20Phoenix.contract",
            &self.contract_id.to_bytes(),
        ));
        out.push(self.asset_id);
        out.push(self.mode.scalar());
        out.push(self.root);
        out.push(BlsScalar::from(self.nullifiers.len() as u64));
        out.extend_from_slice(&self.nullifiers);
        out.push(BlsScalar::from(self.output_commitments.len() as u64));
        out.extend_from_slice(&self.output_commitments);
        push_u128(&mut out, self.public_mint_amount);
        push_u128(&mut out, self.public_burn_amount);
        out.push(self.intent_hash);
        out
    }
}

/// Query for retained-root membership.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct RootExistsQuery {
    /// Root to check.
    pub root: BlsScalar,
}

/// Query for note opening by append position.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct OpeningQuery {
    /// Note append position.
    pub position: u64,
}

/// Query for already-spent nullifier membership.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct ExistingNullifiersQuery {
    /// Candidate nullifiers.
    pub nullifiers: Vec<BlsScalar>,
}

/// Query for note-leaf sync pagination.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SyncQuery {
    /// Starting append position.
    pub from: u64,
    /// Maximum number of leaves. Zero means no explicit limit.
    pub count_limit: u64,
}

/// Query for nullifier sync pagination.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct SyncNullifiersQuery {
    /// Starting append position in the nullifier log.
    pub from: u64,
    /// Maximum number of nullifiers. Zero means no explicit limit.
    pub count_limit: u64,
}

/// Proof bytes and claimed public inputs.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateAssetProof {
    /// Proof bytes.
    pub proof: Vec<u8>,
    /// Claimed public inputs. The contract reconstructs and compares these
    /// before verifier dispatch.
    pub public_inputs: PrivateAssetPublicInputs,
}

/// Domain-separated intent fields.
pub struct PrivateAssetIntent<'a> {
    /// Chain id.
    pub chain_id: u8,
    /// Contract id.
    pub contract_id: ContractId,
    /// Asset id.
    pub asset_id: BlsScalar,
    /// Circuit mode.
    pub mode: PrivateAssetCircuitMode,
    /// Historical root.
    pub root: BlsScalar,
    /// Nullifiers.
    pub nullifiers: &'a [BlsScalar],
    /// Output commitments.
    pub output_commitments: &'a [BlsScalar],
    /// Public mint amount.
    pub public_mint_amount: u128,
    /// Public burn amount.
    pub public_burn_amount: u128,
    /// Memo hash.
    pub memo_hash: BlsScalar,
}

struct PublicInputContext<'a> {
    mode: PrivateAssetCircuitMode,
    root: BlsScalar,
    nullifiers: &'a [BlsScalar],
    outputs: &'a [PrivateAssetNote],
    public_mint_amount: u128,
    public_burn_amount: u128,
    memo_hash: BlsScalar,
}

/// Public-input builder used by clients and prover integrations.
pub struct PrivateAssetPublicInputBuilder<'a> {
    /// Chain id.
    pub chain_id: u8,
    /// Contract id.
    pub contract_id: ContractId,
    /// Asset id.
    pub asset_id: BlsScalar,
    /// Circuit mode.
    pub mode: PrivateAssetCircuitMode,
    /// Historical root.
    pub root: BlsScalar,
    /// Nullifiers.
    pub nullifiers: &'a [BlsScalar],
    /// Output notes.
    pub outputs: &'a [PrivateAssetNote],
    /// Public mint amount.
    pub public_mint_amount: u128,
    /// Public burn amount.
    pub public_burn_amount: u128,
    /// Memo hash.
    pub memo_hash: BlsScalar,
}

/// Private mint call.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateMint {
    /// Caller/admin id.
    pub caller: AdminId,
    /// Chain id.
    pub chain_id: u8,
    /// Contract id.
    pub contract_id: ContractId,
    /// Asset id.
    pub asset_id: BlsScalar,
    /// Public mint amount.
    pub amount: u128,
    /// Output notes.
    pub outputs: Vec<PrivateAssetNote>,
    /// Proof.
    pub proof: PrivateAssetProof,
    /// Optional memo hash.
    pub memo_hash: BlsScalar,
    /// Block height to store on appended leaves.
    pub block_height: u64,
}

/// Private transfer call.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateTransfer {
    /// Chain id.
    pub chain_id: u8,
    /// Contract id.
    pub contract_id: ContractId,
    /// Asset id.
    pub asset_id: BlsScalar,
    /// Historical root used by the proof.
    pub root: BlsScalar,
    /// Spent nullifiers.
    pub nullifiers: Vec<BlsScalar>,
    /// Output notes.
    pub outputs: Vec<PrivateAssetNote>,
    /// Proof.
    pub proof: PrivateAssetProof,
    /// Optional memo hash.
    pub memo_hash: BlsScalar,
    /// Block height to store on appended leaves.
    pub block_height: u64,
}

/// Private burn call.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateBurn {
    /// Chain id.
    pub chain_id: u8,
    /// Contract id.
    pub contract_id: ContractId,
    /// Asset id.
    pub asset_id: BlsScalar,
    /// Historical root used by the proof.
    pub root: BlsScalar,
    /// Spent nullifiers.
    pub nullifiers: Vec<BlsScalar>,
    /// Change output notes.
    pub outputs: Vec<PrivateAssetNote>,
    /// Public burn amount.
    pub amount: u128,
    /// Proof.
    pub proof: PrivateAssetProof,
    /// Optional memo hash.
    pub memo_hash: BlsScalar,
    /// Block height to store on appended leaves.
    pub block_height: u64,
}

/// Private mint event.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateMintEvent {
    /// Asset id.
    pub asset_id: BlsScalar,
    /// Public mint amount.
    pub amount: u128,
    /// Appended output notes.
    pub notes: Vec<PrivateAssetNote>,
    /// New root.
    pub root: BlsScalar,
}

/// Private transfer event.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateTransferEvent {
    /// Asset id.
    pub asset_id: BlsScalar,
    /// Spent nullifiers.
    pub nullifiers: Vec<BlsScalar>,
    /// Appended output notes.
    pub notes: Vec<PrivateAssetNote>,
    /// New root.
    pub root: BlsScalar,
}

/// Private burn event.
#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PrivateBurnEvent {
    /// Asset id.
    pub asset_id: BlsScalar,
    /// Public burn amount.
    pub amount: u128,
    /// Spent nullifiers.
    pub nullifiers: Vec<BlsScalar>,
    /// Appended change notes.
    pub notes: Vec<PrivateAssetNote>,
    /// New root.
    pub root: BlsScalar,
}

/// Pause event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct PausedEvent {
    /// Admin that paused the token.
    pub admin: AdminId,
}

/// Unpause event.
#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[archive_attr(derive(CheckBytes))]
pub struct UnpausedEvent {
    /// Admin that unpaused the token.
    pub admin: AdminId,
}

impl ContractEvent for PrivateMintEvent {
    const TOPICS: &'static [&'static str] = &[PRIVATE_MINT_TOPIC];
}

impl ContractEvent for PrivateTransferEvent {
    const TOPICS: &'static [&'static str] = &[PRIVATE_TRANSFER_TOPIC];
}

impl ContractEvent for PrivateBurnEvent {
    const TOPICS: &'static [&'static str] = &[PRIVATE_BURN_TOPIC];
}

impl ContractEvent for PausedEvent {
    const TOPICS: &'static [&'static str] = &[PAUSED_TOPIC];
}

impl ContractEvent for UnpausedEvent {
    const TOPICS: &'static [&'static str] = &[UNPAUSED_TOPIC];
}

/// Verifier boundary for private asset proofs.
pub trait PrivateAssetVerifier {
    /// Returns true when `proof` verifies for `public_inputs`.
    fn verify(
        &self,
        verifier_data: &[u8],
        proof: &[u8],
        public_inputs: &[BlsScalar],
    ) -> bool;
}

/// Production verifier using the host PLONK verifier in contract builds.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionVerifier;

impl PrivateAssetVerifier for ProductionVerifier {
    fn verify(
        &self,
        verifier_data: &[u8],
        proof: &[u8],
        public_inputs: &[BlsScalar],
    ) -> bool {
        verify_plonk(verifier_data, proof, public_inputs)
    }
}

/// Private fungible token state.
#[derive(Clone, Debug)]
pub struct Drc20Phoenix {
    initialized: bool,
    metadata: TokenMetadata,
    chain_id: u8,
    contract_id: ContractId,
    asset_id: BlsScalar,
    admin: AdminId,
    cap: Option<u128>,
    minted_supply: u128,
    burned_supply: u128,
    paused: bool,
    tree: PrivateNoteTree,
    nullifier_set: BTreeSet<BlsScalar>,
    nullifier_log: Vec<BlsScalar>,
    root_ring: Vec<BlsScalar>,
    root_set: BTreeSet<BlsScalar>,
    root_window: usize,
    verifier_set: Vec<PrivateAssetVerifierConfig>,
}

impl Default for Drc20Phoenix {
    fn default() -> Self {
        Self::new()
    }
}

impl Drc20Phoenix {
    /// Creates an uninitialized token.
    pub fn new() -> Self {
        Self {
            initialized: false,
            metadata: TokenMetadata {
                name: String::new(),
                symbol: String::new(),
                decimals: 0,
            },
            chain_id: 0,
            contract_id: ContractId::from_bytes([0; 32]),
            asset_id: BlsScalar::from(0),
            admin: [0; 32],
            cap: None,
            minted_supply: 0,
            burned_supply: 0,
            paused: false,
            tree: PrivateNoteTree::new(),
            nullifier_set: BTreeSet::new(),
            nullifier_log: Vec::new(),
            root_ring: Vec::new(),
            root_set: BTreeSet::new(),
            root_window: ROOT_WINDOW_DEFAULT,
            verifier_set: Vec::new(),
        }
    }

    /// Initializes the token.
    pub fn init(&mut self, init: Init) {
        if self.initialized {
            panic!("{}", error::ALREADY_INITIALIZED);
        }
        if init.admin == [0; 32] {
            panic!("{}", error::UNAUTHORIZED);
        }
        if init.metadata.name.is_empty() || init.metadata.symbol.is_empty() {
            panic!("{}", error::INVALID_VALUE);
        }
        assert_valid_verifier_set(&init.verifier_set);

        self.metadata = init.metadata;
        self.chain_id = init.chain_id;
        self.contract_id = init.contract_id;
        self.asset_id = derive_asset_id(
            init.chain_id,
            init.contract_id,
            &self.metadata,
            init.deployment_salt,
        );
        self.admin = init.admin;
        self.cap = init.cap;
        self.root_window = match init.root_window {
            0 => ROOT_WINDOW_DEFAULT,
            n => n as usize,
        };
        self.verifier_set = init.verifier_set;
        self.initialized = true;
        self.checkpoint_root();
    }

    /// Returns token metadata.
    pub fn metadata(&self) -> TokenMetadata {
        self.assert_initialized();
        self.metadata.clone()
    }

    /// Returns token name.
    pub fn name(&self) -> String {
        self.metadata().name
    }

    /// Returns token symbol.
    pub fn symbol(&self) -> String {
        self.metadata().symbol
    }

    /// Returns token decimals.
    pub fn decimals(&self) -> u8 {
        self.assert_initialized();
        self.metadata.decimals
    }

    /// Returns standard version.
    pub const fn version(&self) -> u32 {
        DRC20_PHOENIX_VERSION
    }

    /// Returns the token asset id.
    pub fn asset_id(&self) -> BlsScalar {
        self.assert_initialized();
        self.asset_id
    }

    /// Returns the current root.
    pub fn root(&self) -> BlsScalar {
        self.assert_initialized();
        self.tree.root()
    }

    /// Returns true when `root` is retained.
    pub fn root_exists(&self, root: BlsScalar) -> bool {
        self.assert_initialized();
        self.root_set.contains(&root)
    }

    /// Returns a note opening for `pos`.
    pub fn opening(&self, pos: u64) -> Option<PrivateNoteOpening> {
        self.assert_initialized();
        self.tree.opening(pos)
    }

    /// Returns the number of notes.
    pub fn num_notes(&self) -> u64 {
        self.assert_initialized();
        self.tree.len()
    }

    /// Filters supplied nullifiers down to already-spent nullifiers.
    pub fn existing_nullifiers(
        &self,
        nullifiers: Vec<BlsScalar>,
    ) -> Vec<BlsScalar> {
        self.assert_initialized();
        nullifiers
            .into_iter()
            .filter(|n| self.nullifier_set.contains(n))
            .collect()
    }

    /// Returns note leaves in append order.
    pub fn sync(&self, from: u64, count_limit: u64) -> Vec<PrivateAssetLeaf> {
        self.assert_initialized();
        take_window(&self.tree.leaves, from, count_limit)
    }

    /// Returns nullifiers in append order.
    pub fn sync_nullifiers(
        &self,
        from: u64,
        count_limit: u64,
    ) -> Vec<BlsScalar> {
        self.assert_initialized();
        take_window(&self.nullifier_log, from, count_limit)
    }

    /// Returns public minted supply.
    pub fn minted_supply(&self) -> u128 {
        self.assert_initialized();
        self.minted_supply
    }

    /// Returns public burned supply.
    pub fn burned_supply(&self) -> u128 {
        self.assert_initialized();
        self.burned_supply
    }

    /// Returns net public supply.
    pub fn net_supply(&self) -> u128 {
        self.assert_initialized();
        self.minted_supply
            .checked_sub(self.burned_supply)
            .expect(error::ARITHMETIC)
    }

    /// Returns the optional cap.
    pub fn cap(&self) -> Option<u128> {
        self.assert_initialized();
        self.cap
    }

    /// Returns true when paused.
    pub fn paused(&self) -> bool {
        self.assert_initialized();
        self.paused
    }

    /// Returns a hash over the configured verifier manifest.
    pub fn verifier_data_hash(&self) -> BlsScalar {
        self.verifier_manifest_hash()
    }

    /// Returns a hash over the configured verifier manifest.
    pub fn verifier_manifest_hash(&self) -> BlsScalar {
        self.assert_initialized();
        verifier_manifest_hash(&self.verifier_set)
    }

    /// Returns configured verifier keys and hashes.
    pub fn verifier_manifest(&self) -> Vec<PrivateAssetVerifierInfo> {
        self.assert_initialized();
        self.verifier_set
            .iter()
            .map(|config| PrivateAssetVerifierInfo {
                key: config.key,
                verifier_data_hash: config.verifier_data_hash,
            })
            .collect()
    }

    /// Pauses mint, transfer, and burn.
    pub fn pause(&mut self, caller: AdminId) -> PausedEvent {
        self.assert_initialized();
        self.assert_admin(caller);
        if self.paused {
            panic!("{}", error::PAUSED);
        }
        self.paused = true;
        PausedEvent { admin: caller }
    }

    /// Unpauses mint, transfer, and burn.
    pub fn unpause(&mut self, caller: AdminId) -> UnpausedEvent {
        self.assert_initialized();
        self.assert_admin(caller);
        if !self.paused {
            panic!("{}", error::NOT_PAUSED);
        }
        self.paused = false;
        UnpausedEvent { admin: caller }
    }

    /// Mints private notes using the production verifier.
    pub fn mint_private(&mut self, mint: PrivateMint) -> PrivateMintEvent {
        self.mint_private_with_verifier(mint, &ProductionVerifier)
    }

    /// Transfers private notes using the production verifier.
    pub fn transfer_private(
        &mut self,
        tx: PrivateTransfer,
    ) -> PrivateTransferEvent {
        self.transfer_private_with_verifier(tx, &ProductionVerifier)
    }

    /// Burns private notes using the production verifier.
    pub fn burn_private(&mut self, burn: PrivateBurn) -> PrivateBurnEvent {
        self.burn_private_with_verifier(burn, &ProductionVerifier)
    }

    /// Builds proof public inputs for this token domain.
    pub fn build_public_inputs(
        &self,
        input: PrivateAssetPublicInputBuilder,
    ) -> PrivateAssetPublicInputs {
        self.assert_initialized();
        if input.chain_id != self.chain_id
            || input.contract_id != self.contract_id
            || input.asset_id != self.asset_id
        {
            panic!("{}", error::INVALID_DOMAIN);
        }
        self.public_inputs(PublicInputContext {
            mode: input.mode,
            root: input.root,
            nullifiers: input.nullifiers,
            outputs: input.outputs,
            public_mint_amount: input.public_mint_amount,
            public_burn_amount: input.public_burn_amount,
            memo_hash: input.memo_hash,
        })
    }

    /// Mints private notes using an explicit verifier.
    pub fn mint_private_with_verifier(
        &mut self,
        mint: PrivateMint,
        verifier: &impl PrivateAssetVerifier,
    ) -> PrivateMintEvent {
        self.assert_ready_for_mutation();
        self.assert_admin(mint.caller);
        if mint.amount == 0 {
            panic!("{}", error::INVALID_VALUE);
        }
        self.assert_call_domain(mint.chain_id, mint.contract_id, mint.asset_id);
        self.assert_notes_well_formed(&mint.outputs);
        self.assert_note_capacity(mint.outputs.len());
        let next_supply = self
            .minted_supply
            .checked_add(mint.amount)
            .expect(error::ARITHMETIC);
        if self.cap.is_some_and(|cap| next_supply > cap) {
            panic!("{}", error::CAP_EXCEEDED);
        }

        let expected = self.public_inputs(PublicInputContext {
            mode: PrivateAssetCircuitMode::Mint,
            root: self.root(),
            nullifiers: &[],
            outputs: &mint.outputs,
            public_mint_amount: mint.amount,
            public_burn_amount: 0,
            memo_hash: mint.memo_hash,
        });
        self.verify_expected_inputs(&mint.proof, expected, verifier);

        self.minted_supply = next_supply;
        let notes = self.tree.extend_notes(mint.block_height, mint.outputs);
        self.checkpoint_root();

        PrivateMintEvent {
            asset_id: self.asset_id,
            amount: mint.amount,
            notes,
            root: self.root(),
        }
    }

    /// Transfers private notes using an explicit verifier.
    pub fn transfer_private_with_verifier(
        &mut self,
        tx: PrivateTransfer,
        verifier: &impl PrivateAssetVerifier,
    ) -> PrivateTransferEvent {
        self.assert_ready_for_mutation();
        self.assert_call_domain(tx.chain_id, tx.contract_id, tx.asset_id);
        self.assert_retained_root(tx.root);
        self.assert_notes_well_formed(&tx.outputs);
        self.assert_note_capacity(tx.outputs.len());
        self.assert_nullifiers_unspent(&tx.nullifiers);

        let expected = self.public_inputs(PublicInputContext {
            mode: PrivateAssetCircuitMode::Transfer,
            root: tx.root,
            nullifiers: &tx.nullifiers,
            outputs: &tx.outputs,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash: tx.memo_hash,
        });
        self.verify_expected_inputs(&tx.proof, expected, verifier);

        self.consume_nullifiers(&tx.nullifiers);
        let notes = self.tree.extend_notes(tx.block_height, tx.outputs);
        self.checkpoint_root();

        PrivateTransferEvent {
            asset_id: self.asset_id,
            nullifiers: tx.nullifiers,
            notes,
            root: self.root(),
        }
    }

    /// Burns private notes using an explicit verifier.
    pub fn burn_private_with_verifier(
        &mut self,
        burn: PrivateBurn,
        verifier: &impl PrivateAssetVerifier,
    ) -> PrivateBurnEvent {
        self.assert_ready_for_mutation();
        if burn.amount == 0 {
            panic!("{}", error::INVALID_VALUE);
        }
        self.assert_call_domain(burn.chain_id, burn.contract_id, burn.asset_id);
        self.assert_retained_root(burn.root);
        self.assert_notes_well_formed_allow_empty(&burn.outputs);
        self.assert_note_capacity(burn.outputs.len());
        self.assert_nullifiers_unspent(&burn.nullifiers);
        let next_burned = self
            .burned_supply
            .checked_add(burn.amount)
            .expect(error::ARITHMETIC);
        if next_burned > self.minted_supply {
            panic!("{}", error::ARITHMETIC);
        }

        let expected = self.public_inputs(PublicInputContext {
            mode: PrivateAssetCircuitMode::Burn,
            root: burn.root,
            nullifiers: &burn.nullifiers,
            outputs: &burn.outputs,
            public_mint_amount: 0,
            public_burn_amount: burn.amount,
            memo_hash: burn.memo_hash,
        });
        self.verify_expected_inputs(&burn.proof, expected, verifier);

        self.burned_supply = next_burned;
        self.consume_nullifiers(&burn.nullifiers);
        let notes = self.tree.extend_notes(burn.block_height, burn.outputs);
        self.checkpoint_root();

        PrivateBurnEvent {
            asset_id: self.asset_id,
            amount: burn.amount,
            nullifiers: burn.nullifiers,
            notes,
            root: self.root(),
        }
    }

    fn public_inputs(
        &self,
        input: PublicInputContext,
    ) -> PrivateAssetPublicInputs {
        let output_commitments = input
            .outputs
            .iter()
            .map(|note| note.commitment)
            .collect::<Vec<_>>();
        let intent_hash = intent_hash(PrivateAssetIntent {
            chain_id: self.chain_id,
            contract_id: self.contract_id,
            asset_id: self.asset_id,
            mode: input.mode,
            root: input.root,
            nullifiers: input.nullifiers,
            output_commitments: &output_commitments,
            public_mint_amount: input.public_mint_amount,
            public_burn_amount: input.public_burn_amount,
            memo_hash: input.memo_hash,
        });
        PrivateAssetPublicInputs {
            version: DRC20_PHOENIX_VERSION,
            chain_id: self.chain_id,
            contract_id: self.contract_id,
            asset_id: self.asset_id,
            mode: input.mode,
            root: input.root,
            nullifiers: input.nullifiers.to_vec(),
            output_commitments,
            public_mint_amount: input.public_mint_amount,
            public_burn_amount: input.public_burn_amount,
            intent_hash,
        }
    }

    fn verify_expected_inputs(
        &self,
        proof: &PrivateAssetProof,
        expected: PrivateAssetPublicInputs,
        verifier: &impl PrivateAssetVerifier,
    ) {
        if proof.public_inputs != expected {
            panic!("{}", error::PUBLIC_INPUT_MISMATCH);
        }
        let verifier_data = self.verifier_data_for(&expected);
        if !verifier.verify(verifier_data, &proof.proof, &expected.to_scalars())
        {
            panic!("{}", error::INVALID_PROOF);
        }
    }

    fn verifier_data_for(
        &self,
        public_inputs: &PrivateAssetPublicInputs,
    ) -> &[u8] {
        let input_count = u8::try_from(public_inputs.nullifiers.len())
            .expect(error::UNSUPPORTED_ARITY);
        let output_count = u8::try_from(public_inputs.output_commitments.len())
            .expect(error::UNSUPPORTED_ARITY);
        let key = PrivateAssetVerifierKey {
            version: public_inputs.version,
            mode: public_inputs.mode,
            input_count,
            output_count,
        };
        if !key.is_supported_v1() {
            panic!("{}", error::UNSUPPORTED_ARITY);
        }
        self.verifier_set
            .iter()
            .find(|config| config.key == key)
            .map(|config| config.verifier_data.as_slice())
            .unwrap_or_else(|| panic!("{}", error::UNSUPPORTED_ARITY))
    }

    fn assert_initialized(&self) {
        if !self.initialized {
            panic!("{}", error::NOT_INITIALIZED);
        }
    }

    fn assert_ready_for_mutation(&self) {
        self.assert_initialized();
        if self.paused {
            panic!("{}", error::PAUSED);
        }
    }

    fn assert_admin(&self, caller: AdminId) {
        if caller != self.admin {
            panic!("{}", error::UNAUTHORIZED);
        }
    }

    fn assert_call_domain(
        &self,
        chain_id: u8,
        contract_id: ContractId,
        asset_id: BlsScalar,
    ) {
        if chain_id != self.chain_id
            || contract_id != self.contract_id
            || asset_id != self.asset_id
        {
            panic!("{}", error::INVALID_DOMAIN);
        }
    }

    fn assert_retained_root(&self, root: BlsScalar) {
        if !self.root_set.contains(&root) {
            panic!("{}", error::UNKNOWN_ROOT);
        }
    }

    fn assert_notes_well_formed(&self, notes: &[PrivateAssetNote]) {
        if notes.is_empty() {
            panic!("{}", error::INVALID_VALUE);
        }
        self.assert_notes_well_formed_allow_empty(notes);
    }

    fn assert_notes_well_formed_allow_empty(&self, notes: &[PrivateAssetNote]) {
        for note in notes {
            note.assert_well_formed(self.asset_id);
        }
    }

    fn assert_nullifiers_unspent(&self, nullifiers: &[BlsScalar]) {
        if nullifiers.is_empty() {
            panic!("{}", error::INVALID_VALUE);
        }
        let mut unique = BTreeSet::new();
        for nullifier in nullifiers {
            if !unique.insert(*nullifier)
                || self.nullifier_set.contains(nullifier)
            {
                panic!("{}", error::NULLIFIER_REPLAY);
            }
        }
    }

    fn assert_note_capacity(&self, additional_notes: usize) {
        let capacity = 1usize << DRC20_PHOENIX_TREE_HEIGHT;
        if self.tree.leaves.len().saturating_add(additional_notes) > capacity {
            panic!("{}", error::INVALID_VALUE);
        }
    }

    fn consume_nullifiers(&mut self, nullifiers: &[BlsScalar]) {
        for nullifier in nullifiers {
            if !self.nullifier_set.insert(*nullifier) {
                panic!("{}", error::NULLIFIER_REPLAY);
            }
            self.nullifier_log.push(*nullifier);
        }
    }

    fn checkpoint_root(&mut self) {
        let root = self.tree.root();
        if self.root_set.insert(root) {
            self.root_ring.push(root);
        }
        while self.root_ring.len() > self.root_window {
            let old = self.root_ring.remove(0);
            if !self.root_ring.contains(&old) {
                self.root_set.remove(&old);
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PrivateNoteTree {
    leaves: Vec<PrivateAssetLeaf>,
}

impl PrivateNoteTree {
    fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    fn root(&self) -> BlsScalar {
        merkle_root(self.leaves.iter().map(|leaf| leaf.note.commitment))
    }

    fn extend_notes(
        &mut self,
        block_height: u64,
        notes: Vec<PrivateAssetNote>,
    ) -> Vec<PrivateAssetNote> {
        let mut appended = Vec::with_capacity(notes.len());
        for note in notes {
            let position = self.leaves.len() as u64;
            self.leaves.push(PrivateAssetLeaf {
                block_height,
                position,
                note: note.clone(),
            });
            appended.push(note);
        }
        appended
    }

    fn opening(&self, pos: u64) -> Option<PrivateNoteOpening> {
        let pos_usize = pos as usize;
        let leaf = self.leaves.get(pos_usize)?;
        let mut index = pos_usize;
        let capacity = 1usize << DRC20_PHOENIX_TREE_HEIGHT;
        let mut level = self
            .leaves
            .iter()
            .map(|leaf| leaf.note.commitment)
            .collect::<Vec<_>>();
        if level.len() > capacity {
            return None;
        }
        let defaults = default_subtree_roots();
        let mut siblings = Vec::new();

        for height in 0..DRC20_PHOENIX_TREE_HEIGHT {
            let is_right = index % 2 == 1;
            let sibling_index = if is_right { index - 1 } else { index + 1 };
            let sibling_hash = level
                .get(sibling_index)
                .copied()
                .unwrap_or(defaults[height]);
            siblings.push(MerkleSibling {
                hash: sibling_hash,
                is_left: is_right,
            });

            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(defaults[height]);
                next.push(hash_pair(left, right));
            }
            index /= 2;
            level = next;
        }

        Some(PrivateNoteOpening {
            position: pos,
            commitment: leaf.note.commitment,
            siblings,
        })
    }
}

fn take_window<T: Clone>(items: &[T], from: u64, count_limit: u64) -> Vec<T> {
    let from = from as usize;
    if from >= items.len() {
        return Vec::new();
    }
    let iter = items[from..].iter().cloned();
    if count_limit == 0 {
        iter.collect()
    } else {
        iter.take(count_limit as usize).collect()
    }
}

/// Derives a domain-separated custom asset id.
pub fn derive_asset_id(
    chain_id: u8,
    contract_id: ContractId,
    metadata: &TokenMetadata,
    deployment_salt: [u8; 32],
) -> BlsScalar {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"DRC20Phoenix.asset.v1");
    bytes.push(chain_id);
    bytes.extend_from_slice(&contract_id.to_bytes());
    bytes.extend_from_slice(&(metadata.name.len() as u32).to_be_bytes());
    bytes.extend_from_slice(metadata.name.as_bytes());
    bytes.extend_from_slice(&(metadata.symbol.len() as u32).to_be_bytes());
    bytes.extend_from_slice(metadata.symbol.as_bytes());
    bytes.push(metadata.decimals);
    bytes.extend_from_slice(&deployment_salt);
    hash_bytes(&bytes)
}

/// Computes a circuit-friendly owner commitment from a private spend secret.
pub fn compute_owner_commitment(spend_secret: BlsScalar) -> BlsScalar {
    hash_scalars(b"DRC20Phoenix.owner_commitment.v1", &[spend_secret])
}

/// Computes a circuit-friendly private value commitment.
pub fn compute_value_commitment(
    asset_id: BlsScalar,
    value: u64,
    value_blinder: BlsScalar,
) -> BlsScalar {
    hash_scalars(
        b"DRC20Phoenix.value_commitment.v1",
        &[asset_id, BlsScalar::from(value), value_blinder],
    )
}

/// Computes the hash of an encrypted note payload.
pub fn encrypted_payload_hash(payload: &[u8]) -> BlsScalar {
    hash_bytes_with_domain(b"DRC20Phoenix.note.payload", payload)
}

/// Computes a circuit-friendly private note commitment.
pub fn compute_note_commitment(
    asset_id: BlsScalar,
    owner_commitment: BlsScalar,
    value_commitment: BlsScalar,
    nonce: BlsScalar,
    payload_hash: BlsScalar,
) -> BlsScalar {
    hash_scalars(
        b"DRC20Phoenix.note.v1",
        &[
            asset_id,
            owner_commitment,
            value_commitment,
            nonce,
            payload_hash,
        ],
    )
}

/// Computes a circuit-friendly nullifier for a spent note.
pub fn compute_nullifier(
    asset_id: BlsScalar,
    spend_secret: BlsScalar,
    note_commitment: BlsScalar,
) -> BlsScalar {
    hash_scalars(
        b"DRC20Phoenix.nullifier.v1",
        &[asset_id, spend_secret, note_commitment],
    )
}

/// Computes the pinned verifier data hash for a fixed arity.
pub fn verifier_data_hash_for_key(
    key: PrivateAssetVerifierKey,
    verifier_data: &[u8],
) -> BlsScalar {
    let mut scalars = Vec::with_capacity(5);
    scalars.extend_from_slice(&key.scalars());
    scalars.push(hash_bytes_with_domain(
        b"DRC20Phoenix.verifier_data.bytes.v1",
        verifier_data,
    ));
    hash_scalars(b"DRC20Phoenix.verifier_data_hash.v1", &scalars)
}

/// Computes a manifest hash over all configured verifier keys.
pub fn verifier_manifest_hash(
    verifier_set: &[PrivateAssetVerifierConfig],
) -> BlsScalar {
    let mut scalars = Vec::with_capacity(verifier_set.len() * 5 + 1);
    scalars.push(BlsScalar::from(verifier_set.len() as u64));
    for config in verifier_set {
        scalars.extend_from_slice(&config.key.scalars());
        scalars.push(config.verifier_data_hash);
    }
    hash_scalars(b"DRC20Phoenix.verifier_manifest.v1", &scalars)
}

fn assert_valid_verifier_set(verifier_set: &[PrivateAssetVerifierConfig]) {
    if verifier_set.is_empty() {
        panic!("{}", error::INVALID_VERIFIER_CONFIG);
    }

    let mut seen = BTreeSet::new();
    for config in verifier_set {
        if config.verifier_data.is_empty()
            || !config.key.is_supported_v1()
            || verifier_data_hash_for_key(config.key, &config.verifier_data)
                != config.verifier_data_hash
            || !seen.insert(config.key)
        {
            panic!("{}", error::INVALID_VERIFIER_CONFIG);
        }
    }

    for required in V1_SUPPORTED_ARITIES {
        if !seen.contains(required) {
            panic!("{}", error::INVALID_VERIFIER_CONFIG);
        }
    }
}

/// Builds a proof intent hash.
pub fn intent_hash(intent: PrivateAssetIntent<'_>) -> BlsScalar {
    let mut scalars = Vec::with_capacity(
        10 + intent.nullifiers.len() + intent.output_commitments.len(),
    );
    scalars.push(BlsScalar::from(DRC20_PHOENIX_VERSION as u64));
    scalars.push(BlsScalar::from(intent.chain_id as u64));
    scalars.push(hash_bytes_with_domain(
        b"DRC20Phoenix.intent.contract",
        &intent.contract_id.to_bytes(),
    ));
    scalars.push(intent.asset_id);
    scalars.push(intent.mode.scalar());
    scalars.push(intent.root);
    scalars.push(BlsScalar::from(intent.nullifiers.len() as u64));
    scalars.extend_from_slice(intent.nullifiers);
    scalars.push(BlsScalar::from(intent.output_commitments.len() as u64));
    scalars.extend_from_slice(intent.output_commitments);
    push_u128(&mut scalars, intent.public_mint_amount);
    push_u128(&mut scalars, intent.public_burn_amount);
    scalars.push(intent.memo_hash);
    hash_scalars(b"DRC20Phoenix.intent.v1", &scalars)
}

fn merkle_root(commitments: impl IntoIterator<Item = BlsScalar>) -> BlsScalar {
    let mut level = commitments.into_iter().collect::<Vec<_>>();
    let capacity = 1usize << DRC20_PHOENIX_TREE_HEIGHT;
    if level.len() > capacity {
        panic!("{}", error::INVALID_VALUE);
    }
    let defaults = default_subtree_roots();
    if level.is_empty() {
        return defaults[DRC20_PHOENIX_TREE_HEIGHT];
    }
    for height in 0..DRC20_PHOENIX_TREE_HEIGHT {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(defaults[height]);
            next.push(hash_pair(left, right));
        }
        level = next;
    }
    level[0]
}

fn default_subtree_roots() -> Vec<BlsScalar> {
    let mut roots = Vec::with_capacity(DRC20_PHOENIX_TREE_HEIGHT + 1);
    roots.push(empty_leaf());
    for height in 1..=DRC20_PHOENIX_TREE_HEIGHT {
        let previous = roots[height - 1];
        roots.push(hash_pair(previous, previous));
    }
    roots
}

fn hash_pair(left: BlsScalar, right: BlsScalar) -> BlsScalar {
    hash_scalars(b"DRC20Phoenix.merkle_pair.v1", &[left, right])
}

fn empty_leaf() -> BlsScalar {
    domain_scalar(b"DRC20Phoenix.empty_leaf.v1")
}

fn domain_scalar(domain: &[u8]) -> BlsScalar {
    hash_bytes(domain)
}

fn hash_bytes_with_domain(domain: &[u8], bytes: &[u8]) -> BlsScalar {
    let mut out = Vec::with_capacity(domain.len() + bytes.len() + 8);
    out.extend_from_slice(domain);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
    hash_bytes(&out)
}

fn hash_scalars(domain: &[u8], scalars: &[BlsScalar]) -> BlsScalar {
    let mut input = Vec::with_capacity(scalars.len() + 2);
    input.push(domain_scalar(domain));
    input.push(BlsScalar::from(scalars.len() as u64));
    input.extend_from_slice(scalars);
    poseidon_hash(input)
}

#[cfg(all(target_family = "wasm", feature = "contract"))]
fn poseidon_hash(scalars: Vec<BlsScalar>) -> BlsScalar {
    dusk_core::abi::poseidon_hash(scalars)
}

#[cfg(not(all(target_family = "wasm", feature = "contract")))]
fn poseidon_hash(scalars: Vec<BlsScalar>) -> BlsScalar {
    PoseidonHash::digest(Domain::Other, &scalars)[0]
}

fn push_u128(out: &mut Vec<BlsScalar>, value: u128) {
    out.push(BlsScalar::from((value >> 64) as u64));
    out.push(BlsScalar::from(value as u64));
}

#[cfg(all(target_family = "wasm", feature = "contract"))]
fn hash_bytes(bytes: &[u8]) -> BlsScalar {
    dusk_core::abi::hash(bytes.to_vec())
}

#[cfg(not(all(target_family = "wasm", feature = "contract")))]
fn hash_bytes(bytes: &[u8]) -> BlsScalar {
    BlsScalar::hash_to_scalar(bytes)
}

#[cfg(all(target_family = "wasm", feature = "contract"))]
fn verify_plonk(
    verifier_data: &[u8],
    proof: &[u8],
    public_inputs: &[BlsScalar],
) -> bool {
    dusk_core::abi::verify_plonk(
        verifier_data.to_vec(),
        proof.to_vec(),
        public_inputs.to_vec(),
    )
}

#[cfg(not(all(target_family = "wasm", feature = "contract")))]
fn verify_plonk(
    _verifier_data: &[u8],
    _proof: &[u8],
    _public_inputs: &[BlsScalar],
) -> bool {
    false
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;
    use core::panic::AssertUnwindSafe;
    use std::panic::catch_unwind;

    use proptest::prelude::*;

    use super::*;

    #[derive(Clone, Copy, Debug)]
    struct StrictTestVerifier;

    impl PrivateAssetVerifier for StrictTestVerifier {
        fn verify(
            &self,
            verifier_data: &[u8],
            proof: &[u8],
            public_inputs: &[BlsScalar],
        ) -> bool {
            verifier_data == b"test-verifier"
                && proof == expected_test_proof(public_inputs)
        }
    }

    fn expected_test_proof(public_inputs: &[BlsScalar]) -> Vec<u8> {
        hash_scalars(b"DRC20Phoenix.test_proof", public_inputs)
            .to_bytes()
            .to_vec()
    }

    fn c(byte: u8) -> ContractId {
        ContractId::from_bytes([byte; 32])
    }

    fn s(value: u64) -> BlsScalar {
        BlsScalar::from(value)
    }

    fn admin(byte: u8) -> AdminId {
        [byte; 32]
    }

    fn metadata() -> TokenMetadata {
        TokenMetadata {
            name: String::from("Private Token"),
            symbol: String::from("pTOK"),
            decimals: 9,
        }
    }

    fn init(cap: Option<u128>, root_window: u16) -> Init {
        Init {
            metadata: metadata(),
            chain_id: 7,
            contract_id: c(9),
            deployment_salt: [3; 32],
            admin: admin(1),
            cap,
            root_window,
            verifier_set: test_verifier_set(),
        }
    }

    fn test_verifier_set() -> Vec<PrivateAssetVerifierConfig> {
        V1_SUPPORTED_ARITIES
            .iter()
            .copied()
            .map(|key| {
                PrivateAssetVerifierConfig::new(key, b"test-verifier".to_vec())
            })
            .collect()
    }

    fn token(cap: Option<u128>) -> Drc20Phoenix {
        let mut token = Drc20Phoenix::new();
        token.init(init(cap, 0));
        token
    }

    fn note(asset_id: BlsScalar, seed: u64) -> PrivateAssetNote {
        PrivateAssetNote::new(
            asset_id,
            s(seed + 10),
            s(seed + 20),
            s(seed + 30),
            vec![seed as u8, seed.wrapping_add(1) as u8],
        )
    }

    fn proof_for(inputs: PrivateAssetPublicInputs) -> PrivateAssetProof {
        let scalars = inputs.to_scalars();
        PrivateAssetProof {
            proof: expected_test_proof(&scalars),
            public_inputs: inputs,
        }
    }

    fn mint_call(
        token: &Drc20Phoenix,
        amount: u64,
        outputs: Vec<PrivateAssetNote>,
    ) -> PrivateMint {
        let public_inputs = token.public_inputs(PublicInputContext {
            mode: PrivateAssetCircuitMode::Mint,
            root: token.root(),
            nullifiers: &[],
            outputs: &outputs,
            public_mint_amount: amount.into(),
            public_burn_amount: 0,
            memo_hash: s(900),
        });
        PrivateMint {
            caller: admin(1),
            chain_id: 7,
            contract_id: c(9),
            asset_id: token.asset_id(),
            amount: amount.into(),
            outputs,
            proof: proof_for(public_inputs),
            memo_hash: s(900),
            block_height: 1,
        }
    }

    fn transfer_call(
        token: &Drc20Phoenix,
        root: BlsScalar,
        nullifiers: Vec<BlsScalar>,
        mut outputs: Vec<PrivateAssetNote>,
    ) -> PrivateTransfer {
        if outputs.len() == 1 {
            outputs
                .push(note(token.asset_id(), 60_000 + nullifiers.len() as u64));
        }
        let public_inputs = token.public_inputs(PublicInputContext {
            mode: PrivateAssetCircuitMode::Transfer,
            root,
            nullifiers: &nullifiers,
            outputs: &outputs,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash: s(901),
        });
        PrivateTransfer {
            chain_id: 7,
            contract_id: c(9),
            asset_id: token.asset_id(),
            root,
            nullifiers,
            outputs,
            proof: proof_for(public_inputs),
            memo_hash: s(901),
            block_height: 2,
        }
    }

    fn burn_call(
        token: &Drc20Phoenix,
        root: BlsScalar,
        nullifiers: Vec<BlsScalar>,
        amount: u64,
        outputs: Vec<PrivateAssetNote>,
    ) -> PrivateBurn {
        let public_inputs = token.public_inputs(PublicInputContext {
            mode: PrivateAssetCircuitMode::Burn,
            root,
            nullifiers: &nullifiers,
            outputs: &outputs,
            public_mint_amount: 0,
            public_burn_amount: amount.into(),
            memo_hash: s(902),
        });
        PrivateBurn {
            chain_id: 7,
            contract_id: c(9),
            asset_id: token.asset_id(),
            root,
            nullifiers,
            outputs,
            amount: amount.into(),
            proof: proof_for(public_inputs),
            memo_hash: s(902),
            block_height: 3,
        }
    }

    fn assert_panics(f: impl FnOnce()) {
        assert!(catch_unwind(AssertUnwindSafe(f)).is_err());
    }

    #[test]
    fn init_metadata_asset_id_and_initial_root_are_stable() {
        let token = token(Some(1_000));
        assert_eq!(token.name(), "Private Token");
        assert_eq!(token.symbol(), "pTOK");
        assert_eq!(token.decimals(), 9);
        assert_eq!(token.cap(), Some(1_000));
        assert_eq!(token.num_notes(), 0);
        assert!(token.root_exists(token.root()));
        assert_eq!(token.verifier_manifest().len(), V1_SUPPORTED_ARITIES.len());
        assert_eq!(
            token.verifier_manifest_hash(),
            verifier_manifest_hash(&test_verifier_set())
        );
        assert_eq!(
            token.asset_id(),
            derive_asset_id(7, c(9), &metadata(), [3; 32])
        );
        assert_ne!(
            token.asset_id(),
            derive_asset_id(7, c(10), &metadata(), [3; 32])
        );
    }

    #[test]
    fn public_input_builder_matches_internal_call_binding() {
        let token = token(None);
        let outputs =
            vec![note(token.asset_id(), 1), note(token.asset_id(), 2)];
        let external =
            token.build_public_inputs(PrivateAssetPublicInputBuilder {
                chain_id: 7,
                contract_id: c(9),
                asset_id: token.asset_id(),
                mode: PrivateAssetCircuitMode::Transfer,
                root: token.root(),
                nullifiers: &[s(1), s(2)],
                outputs: &outputs,
                public_mint_amount: 0,
                public_burn_amount: 0,
                memo_hash: s(10),
            });
        let internal = token.public_inputs(PublicInputContext {
            mode: PrivateAssetCircuitMode::Transfer,
            root: token.root(),
            nullifiers: &[s(1), s(2)],
            outputs: &outputs,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash: s(10),
        });
        assert_eq!(external, internal);
        assert_panics(|| {
            token.build_public_inputs(PrivateAssetPublicInputBuilder {
                chain_id: 8,
                contract_id: c(9),
                asset_id: token.asset_id(),
                mode: PrivateAssetCircuitMode::Transfer,
                root: token.root(),
                nullifiers: &[s(1)],
                outputs: &outputs,
                public_mint_amount: 0,
                public_burn_amount: 0,
                memo_hash: s(10),
            });
        });
    }

    #[test]
    fn init_rejects_bad_inputs_and_double_init() {
        let mut token = Drc20Phoenix::new();
        let mut bad_admin = init(None, 0);
        bad_admin.admin = [0; 32];
        assert_panics(|| token.init(bad_admin));
        assert!(!token.initialized);

        let mut empty_verifier_set = init(None, 0);
        empty_verifier_set.verifier_set.clear();
        assert_panics(|| token.init(empty_verifier_set));
        assert!(!token.initialized);

        let mut duplicate_verifier = init(None, 0);
        duplicate_verifier
            .verifier_set
            .push(duplicate_verifier.verifier_set[0].clone());
        assert_panics(|| token.init(duplicate_verifier));
        assert!(!token.initialized);

        let mut missing_verifier = init(None, 0);
        missing_verifier.verifier_set.pop();
        assert_panics(|| token.init(missing_verifier));
        assert!(!token.initialized);

        let mut bad_hash = init(None, 0);
        bad_hash.verifier_set[0].verifier_data_hash = s(999);
        assert_panics(|| token.init(bad_hash));
        assert!(!token.initialized);

        token.init(init(None, 0));
        assert_panics(|| token.init(init(None, 0)));
    }

    #[test]
    fn private_mint_success_and_cap_authority_pause_checks() {
        let mut token = token(Some(100));
        let output = note(token.asset_id(), 1);
        let event = token.mint_private_with_verifier(
            mint_call(&token, 40, vec![output.clone()]),
            &StrictTestVerifier,
        );
        assert_eq!(event.amount, 40);
        assert_eq!(event.notes, vec![output]);
        assert_eq!(token.minted_supply(), 40);
        assert_eq!(token.net_supply(), 40);
        assert_eq!(token.num_notes(), 1);
        assert!(token.opening(0).unwrap().verifies(token.root()));

        let unauthorized = PrivateMint {
            caller: admin(2),
            ..mint_call(&token, 1, vec![note(token.asset_id(), 2)])
        };
        assert_panics(|| {
            token.mint_private_with_verifier(unauthorized, &StrictTestVerifier);
        });

        assert_panics(|| {
            token.mint_private_with_verifier(
                mint_call(&token, 61, vec![note(token.asset_id(), 3)]),
                &StrictTestVerifier,
            );
        });

        token.pause(admin(1));
        assert_panics(|| {
            token.mint_private_with_verifier(
                mint_call(&token, 1, vec![note(token.asset_id(), 4)]),
                &StrictTestVerifier,
            );
        });
        token.unpause(admin(1));
        token.mint_private_with_verifier(
            mint_call(&token, 1, vec![note(token.asset_id(), 5)]),
            &StrictTestVerifier,
        );
    }

    #[test]
    fn private_transfer_rejects_replay_wrong_domain_and_mutations() {
        let mut token = token(None);
        token.mint_private_with_verifier(
            mint_call(&token, 50, vec![note(token.asset_id(), 1)]),
            &StrictTestVerifier,
        );
        let root = token.root();
        let tx = transfer_call(
            &token,
            root,
            vec![s(700)],
            vec![note(token.asset_id(), 2), note(token.asset_id(), 3)],
        );
        let event = token
            .transfer_private_with_verifier(tx.clone(), &StrictTestVerifier);
        assert_eq!(event.nullifiers, vec![s(700)]);
        assert_eq!(token.existing_nullifiers(vec![s(1), s(700)]), vec![s(700)]);
        assert_eq!(token.sync_nullifiers(0, 0), vec![s(700)]);
        assert_eq!(token.num_notes(), 3);

        assert_panics(|| {
            token.transfer_private_with_verifier(
                tx.clone(),
                &StrictTestVerifier,
            );
        });

        token.transfer_private_with_verifier(
            transfer_call(
                &token,
                token.root(),
                vec![s(900), s(1)],
                vec![note(token.asset_id(), 13), note(token.asset_id(), 14)],
            ),
            &StrictTestVerifier,
        );
        assert_eq!(token.sync_nullifiers(0, 0), vec![s(700), s(900), s(1)]);

        let duplicate = transfer_call(
            &token,
            token.root(),
            vec![s(701), s(701)],
            vec![note(token.asset_id(), 4)],
        );
        assert_panics(|| {
            token
                .transfer_private_with_verifier(duplicate, &StrictTestVerifier);
        });

        let mut wrong_root = transfer_call(
            &token,
            s(999_999),
            vec![s(702)],
            vec![note(token.asset_id(), 5)],
        );
        wrong_root.proof = proof_for(token.public_inputs(PublicInputContext {
            mode: PrivateAssetCircuitMode::Transfer,
            root: s(999_999),
            nullifiers: &[s(702)],
            outputs: &wrong_root.outputs,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash: wrong_root.memo_hash,
        }));
        assert_panics(|| {
            token.transfer_private_with_verifier(
                wrong_root,
                &StrictTestVerifier,
            );
        });

        let mut wrong_chain = transfer_call(
            &token,
            token.root(),
            vec![s(703)],
            vec![note(token.asset_id(), 6)],
        );
        wrong_chain.chain_id = 8;
        assert_panics(|| {
            token.transfer_private_with_verifier(
                wrong_chain,
                &StrictTestVerifier,
            );
        });

        let mut wrong_contract = transfer_call(
            &token,
            token.root(),
            vec![s(704)],
            vec![note(token.asset_id(), 7)],
        );
        wrong_contract.contract_id = c(8);
        assert_panics(|| {
            token.transfer_private_with_verifier(
                wrong_contract,
                &StrictTestVerifier,
            );
        });

        let mut wrong_asset = transfer_call(
            &token,
            token.root(),
            vec![s(705)],
            vec![note(token.asset_id(), 8)],
        );
        wrong_asset.asset_id = s(99);
        assert_panics(|| {
            token.transfer_private_with_verifier(
                wrong_asset,
                &StrictTestVerifier,
            );
        });

        let malformed_note_asset = transfer_call(
            &token,
            token.root(),
            vec![s(7050)],
            vec![note(s(99), 80)],
        );
        assert_panics(|| {
            token.transfer_private_with_verifier(
                malformed_note_asset,
                &StrictTestVerifier,
            );
        });

        let mut wrong_mode = transfer_call(
            &token,
            token.root(),
            vec![s(706)],
            vec![note(token.asset_id(), 9)],
        );
        wrong_mode.proof.public_inputs.mode = PrivateAssetCircuitMode::Burn;
        wrong_mode.proof.proof =
            expected_test_proof(&wrong_mode.proof.public_inputs.to_scalars());
        assert_panics(|| {
            token.transfer_private_with_verifier(
                wrong_mode,
                &StrictTestVerifier,
            );
        });

        let mut bad_proof = transfer_call(
            &token,
            token.root(),
            vec![s(707)],
            vec![note(token.asset_id(), 10)],
        );
        bad_proof.proof.proof[0] ^= 1;
        assert_panics(|| {
            token
                .transfer_private_with_verifier(bad_proof, &StrictTestVerifier);
        });

        let mut mutated_output = transfer_call(
            &token,
            token.root(),
            vec![s(708)],
            vec![note(token.asset_id(), 11)],
        );
        mutated_output.outputs[0].encrypted_payload.push(99);
        assert_panics(|| {
            token.transfer_private_with_verifier(
                mutated_output,
                &StrictTestVerifier,
            );
        });

        let mut mutated_nullifier = transfer_call(
            &token,
            token.root(),
            vec![s(709)],
            vec![note(token.asset_id(), 12)],
        );
        mutated_nullifier.nullifiers[0] = s(710);
        assert_panics(|| {
            token.transfer_private_with_verifier(
                mutated_nullifier,
                &StrictTestVerifier,
            );
        });

        token.pause(admin(1));
        assert_panics(|| {
            token.transfer_private_with_verifier(
                transfer_call(
                    &token,
                    token.root(),
                    vec![s(711)],
                    vec![note(token.asset_id(), 15)],
                ),
                &StrictTestVerifier,
            );
        });
        assert!(token.existing_nullifiers(vec![s(711)]).is_empty());
    }

    #[test]
    fn unsupported_arity_is_rejected_before_mutation() {
        let mut token = token(None);
        token.mint_private_with_verifier(
            mint_call(&token, 50, vec![note(token.asset_id(), 1)]),
            &StrictTestVerifier,
        );
        let snapshot = (
            token.minted_supply(),
            token.burned_supply(),
            token.num_notes(),
            token.sync_nullifiers(0, 0),
            token.root(),
        );

        let outputs = vec![note(token.asset_id(), 2)];
        let public_inputs = token.public_inputs(PublicInputContext {
            mode: PrivateAssetCircuitMode::Transfer,
            root: token.root(),
            nullifiers: &[s(9_001)],
            outputs: &outputs,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash: s(903),
        });
        let unsupported = PrivateTransfer {
            chain_id: 7,
            contract_id: c(9),
            asset_id: token.asset_id(),
            root: token.root(),
            nullifiers: vec![s(9_001)],
            outputs,
            proof: proof_for(public_inputs),
            memo_hash: s(903),
            block_height: 4,
        };

        assert_panics(|| {
            token.transfer_private_with_verifier(
                unsupported,
                &StrictTestVerifier,
            );
        });
        assert_eq!(
            snapshot,
            (
                token.minted_supply(),
                token.burned_supply(),
                token.num_notes(),
                token.sync_nullifiers(0, 0),
                token.root(),
            )
        );
    }

    #[test]
    fn burn_success_rejections_and_failed_calls_are_atomic() {
        let mut token = token(None);
        token.mint_private_with_verifier(
            mint_call(&token, 90, vec![note(token.asset_id(), 1)]),
            &StrictTestVerifier,
        );
        let before_root = token.root();
        let burn = burn_call(
            &token,
            before_root,
            vec![s(800)],
            30,
            vec![note(token.asset_id(), 2)],
        );
        let event =
            token.burn_private_with_verifier(burn.clone(), &StrictTestVerifier);
        assert_eq!(event.amount, 30);
        assert_eq!(token.burned_supply(), 30);
        assert_eq!(token.net_supply(), 60);
        assert_eq!(token.sync_nullifiers(0, 0), vec![s(800)]);

        let snapshot = (
            token.minted_supply(),
            token.burned_supply(),
            token.num_notes(),
            token.sync_nullifiers(0, 0),
            token.root(),
        );

        let duplicate = burn_call(
            &token,
            token.root(),
            vec![s(800)],
            1,
            vec![note(token.asset_id(), 3)],
        );
        assert_panics(|| {
            token.burn_private_with_verifier(duplicate, &StrictTestVerifier);
        });
        assert_eq!(
            snapshot,
            (
                token.minted_supply(),
                token.burned_supply(),
                token.num_notes(),
                token.sync_nullifiers(0, 0),
                token.root(),
            )
        );

        let mut mismatch = burn_call(
            &token,
            token.root(),
            vec![s(801)],
            10,
            vec![note(token.asset_id(), 4)],
        );
        mismatch.amount = 11;
        assert_panics(|| {
            token.burn_private_with_verifier(mismatch, &StrictTestVerifier);
        });
        assert_eq!(token.burned_supply(), 30);

        token.pause(admin(1));
        assert_panics(|| {
            token.burn_private_with_verifier(
                burn_call(&token, token.root(), vec![s(802)], 10, Vec::new()),
                &StrictTestVerifier,
            );
        });
        token.unpause(admin(1));
        assert!(token.existing_nullifiers(vec![s(802)]).is_empty());

        let notes_before_full_burn = token.num_notes();
        let full_burn = token.burn_private_with_verifier(
            burn_call(&token, token.root(), vec![s(802)], 10, Vec::new()),
            &StrictTestVerifier,
        );
        assert_eq!(full_burn.amount, 10);
        assert!(full_burn.notes.is_empty());
        assert_eq!(token.num_notes(), notes_before_full_burn);
        assert_eq!(token.burned_supply(), 40);
        assert_eq!(token.sync_nullifiers(0, 0), vec![s(800), s(802)]);
    }

    #[test]
    fn sync_pagination_openings_and_root_window_are_stable() {
        let mut token = Drc20Phoenix::new();
        token.init(init(None, 2));
        let initial_root = token.root();
        for i in 0..4 {
            token.mint_private_with_verifier(
                mint_call(&token, 1, vec![note(token.asset_id(), i + 1)]),
                &StrictTestVerifier,
            );
        }
        assert_eq!(token.num_notes(), 4);
        assert!(!token.root_exists(initial_root));
        assert!(token.root_exists(token.root()));
        assert_eq!(token.sync(0, 2).len(), 2);
        assert_eq!(token.sync(2, 10).len(), 2);
        assert!(token.sync(4, 1).is_empty());
        for pos in 0..token.num_notes() {
            let opening = token.opening(pos).expect("opening");
            assert!(opening.verifies(token.root()));
        }
    }

    #[test]
    fn production_verifier_is_not_permissive_in_native_tests() {
        let mut token = token(None);
        let mint = mint_call(&token, 1, vec![note(token.asset_id(), 1)]);
        assert_panics(|| {
            token.mint_private(mint);
        });
        assert_eq!(token.minted_supply(), 0);
        assert_eq!(token.num_notes(), 0);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn supply_note_and_nullifier_invariants_hold(
            mint_amounts in proptest::collection::vec(1u64..1000, 1..8),
            burn_amounts in proptest::collection::vec(1u64..500, 0..4),
        ) {
            let mut token = token(None);
            let mut expected_unspent_private_value = 0u128;
            let mut seed = 1u64;

            for amount in mint_amounts {
                token.mint_private_with_verifier(
                    mint_call(&token, amount, vec![note(token.asset_id(), seed)]),
                    &StrictTestVerifier,
                );
                seed += 1;
                expected_unspent_private_value += amount as u128;
                prop_assert_eq!(
                    token.net_supply(),
                    expected_unspent_private_value
                );
            }

            let mut spent = BTreeSet::new();
            for amount in burn_amounts {
                if expected_unspent_private_value < amount as u128 {
                    continue;
                }
                let nullifier = s(10_000 + seed);
                prop_assert!(spent.insert(nullifier));
                token.burn_private_with_verifier(
                    burn_call(
                        &token,
                        token.root(),
                        vec![nullifier],
                        amount,
                        vec![note(token.asset_id(), seed)],
                    ),
                    &StrictTestVerifier,
                );
                seed += 1;
                expected_unspent_private_value -= amount as u128;
                prop_assert_eq!(
                    token.net_supply(),
                    expected_unspent_private_value
                );
            }

            let synced = token.sync_nullifiers(0, 0);
            let unique = synced.iter().copied().collect::<BTreeSet<_>>();
            prop_assert_eq!(synced.len(), unique.len());
            prop_assert_eq!(
                token.minted_supply() - token.burned_supply(),
                expected_unspent_private_value
            );
        }
    }
}
