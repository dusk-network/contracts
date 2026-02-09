// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Types and functionality used to interact with the `MultiSig` contract.

#![no_std]
#![feature(cfg_eval)]
#![warn(missing_debug_implementations, unreachable_pub, rustdoc::all)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unused_extern_crates)]
#![deny(unused_must_use)]
#![deny(clippy::pedantic)]
#![deny(unused_crate_dependencies)]

extern crate alloc;

pub mod error;
pub mod events;

use alloc::vec::Vec;

use bytecheck::CheckBytes;
use dusk_core::abi::{ContractId, CONTRACT_ID_BYTES};
use dusk_core::signatures::bls::{MultisigSignature, PublicKey};
use dusk_core::transfer::data::ContractCall;
use rkyv::{Archive, Deserialize, Serialize};

#[cfg(feature = "serde")]
use serde_with::{hex::Hex, serde_as};

/// Operation identifier type.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Archive,
    Serialize,
    Deserialize,
)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OpId(
    #[cfg_attr(feature = "serde", serde_as(as = "Hex"))] pub [u8; 32],
);

/// The maximum amount of admin keys that can be stored on the state.
/// For the contract to operate properly this value must not be larger than
/// `u8::MAX`.
/// A value larger than 15 is not advised as that would create a too high
/// administrative burden.
pub const MAX_ADMINS: usize = 15;

/// A target call description.
/// `salt` allows explicitly repeating the same logical operation by changing
/// `op_id`.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", cfg_eval, serde_as)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Target {
    /// The contract call to be made on the target contract.
    pub call: ContractCall,
    /// A salt to differentiate operations with the same target call.
    #[cfg_attr(feature = "serde", serde_as(as = "Hex"))]
    pub salt: [u8; 32],
}

/// Pending proposal.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Operation {
    /// The target call.
    pub target: Target,
    /// The list of admins that approved this operation so far.
    pub approvals: Vec<PublicKey>,
    /// The block-height deadline after which this proposal expires.
    pub deadline: u64,
    /// The required number of approvals to execute this operation.
    pub threshold: u8,
}

impl Operation {
    /// Returns `true` if the given public key has approved this operation.
    #[must_use]
    pub fn approved_by(&self, pk: &PublicKey) -> bool {
        self.approvals.contains(pk)
    }

    /// Returns `true` if the operation has enough approvals to be executed.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.approvals.len() >= self.threshold as usize
    }
}

// the max address size is the public key raw size `G2Affine::RAW_SIZE`
const ADDRESS_MAX_SIZE: usize = 193;

/// Function arguments for the `init` function.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct InitArgs {
    /// List of admin public keys.
    pub admins: Vec<PublicKey>,
    /// Required number of signatures to approve an admin operation.
    pub admin_threshold: u8,
    /// Required number of signatures to execute a pending proposal.
    pub approval_threshold: u8,
    /// Proposal TTL in blocks.
    pub proposal_ttl: u64,
    /// Replay window in blocks.
    pub tombstone_ttl: u64,
}

/// Function arguments for the `MultiSigV2` function `set_authority`.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SetAuthority {
    /// The chain id for which the authority is being set.
    pub chain_id: u8,
    /// List of new admin keys.
    pub new_admins: Vec<PublicKey>,
    /// Required number of signatures to execute a pending proposal.
    pub new_threshold: u8,
    /// Required number of signatures to approve an admin operation.
    pub new_admin_threshold: u8,
    /// The aggregated admin signature.
    pub sig: MultisigSignature,
    /// The indices of the signing admins.
    pub signers: Vec<u8>,
}

impl SetAuthority {
    /// The signature message for changing the authority is the concatenation
    /// of:
    /// - the chain id
    /// - the admin-nonce in be-bytes
    /// - the contract ID in bytes
    /// - the new admin threshold
    /// - the new proposal threshold
    /// - the serialized public-keys of the new admins.
    #[must_use]
    pub fn signature_message(
        chain_id: u8,
        admin_nonce: u64,
        contract: &ContractId,
        new_admin_threshold: u8,
        new_threshold: u8,
        new_admins: impl AsRef<[PublicKey]>,
    ) -> Vec<u8> {
        let admins_bytes_len = new_admins.as_ref().len() * ADDRESS_MAX_SIZE;
        let new_admins = new_admins.as_ref();
        let mut sig_msg = Vec::with_capacity(
            1 + 8 + 1 + 1 + CONTRACT_ID_BYTES + admins_bytes_len,
        );
        sig_msg.push(chain_id);
        sig_msg.extend(&admin_nonce.to_be_bytes());
        sig_msg.extend(contract.as_bytes());
        sig_msg.push(new_admin_threshold);
        sig_msg.push(new_threshold);
        new_admins
            .iter()
            .for_each(|pk| sig_msg.extend(&pk.to_raw_bytes()));

        sig_msg
    }
}

/// Function arguments for the `MultiSigV2` function `set_time_params`.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SetTimeLimits {
    /// The chain id for which the time limits are being set.
    pub chain_id: u8,
    /// Proposal TTL in blocks.
    pub proposal_ttl_blocks: u64,
    /// Replay window in blocks.
    pub replay_window_blocks: u64,
    /// Aggregated admin signature.
    pub sig: MultisigSignature,
    /// Indices of signing admins.
    pub signers: Vec<u8>,
}

impl SetTimeLimits {
    /// The signature message for setting the time parameters is the
    /// concatenation of:
    /// - the chain id
    /// - the admin-nonce in big endian,
    /// - the contract ID in bytes,
    /// - the new proposal TTL in blocks, and
    /// - the new replay window in blocks.
    #[must_use]
    pub fn signature_message(
        chain_id: u8,
        admin_nonce: u64,
        contract: &ContractId,
        proposal_ttl_blocks: u64,
        replay_window_blocks: u64,
    ) -> Vec<u8> {
        // Signature message: admin_nonce, contract id, new params
        let mut sig_msg = Vec::with_capacity(
            1 + 8 + dusk_core::abi::CONTRACT_ID_BYTES + 8 + 8,
        );
        sig_msg.push(chain_id);
        sig_msg.extend(&admin_nonce.to_be_bytes());
        sig_msg.extend(contract.as_bytes());
        sig_msg.extend(&proposal_ttl_blocks.to_be_bytes());
        sig_msg.extend(&replay_window_blocks.to_be_bytes());
        sig_msg
    }
}
