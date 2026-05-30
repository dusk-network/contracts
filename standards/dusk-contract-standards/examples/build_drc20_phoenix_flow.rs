// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_contract_standards::token::drc20_phoenix::{
    Drc20Phoenix, Init, PrivateAssetCircuitMode, PrivateAssetNote,
    PrivateAssetProof, PrivateAssetPublicInputBuilder, PrivateBurn,
    PrivateMint, PrivateTransfer, TokenMetadata,
};
use dusk_core::abi::ContractId;
use dusk_core::BlsScalar;

const ADMIN: [u8; 32] = [7; 32];

fn main() {
    let contract_id = ContractId::from_bytes([9; 32]);
    let mut token = Drc20Phoenix::new();
    token.init(Init {
        metadata: TokenMetadata {
            name: "Private Example Token".into(),
            symbol: "pEXT".into(),
            decimals: 9,
        },
        chain_id: 7,
        contract_id,
        deployment_salt: [3; 32],
        admin: ADMIN,
        cap: Some(1_000_000),
        root_window: 64,
        verifier_data: b"replace-with-private-asset-verifier-data".to_vec(),
    });

    let mint_outputs =
        vec![note(token.asset_id(), 1), note(token.asset_id(), 2)];
    let mint_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id: 7,
            contract_id,
            asset_id: token.asset_id(),
            mode: PrivateAssetCircuitMode::Mint,
            root: token.root(),
            nullifiers: &[],
            outputs: &mint_outputs,
            public_mint_amount: 100,
            public_burn_amount: 0,
            memo_hash: scalar(900),
        });
    let mint = PrivateMint {
        caller: ADMIN,
        chain_id: 7,
        contract_id,
        asset_id: token.asset_id(),
        amount: 100,
        outputs: mint_outputs,
        proof: placeholder_proof(mint_inputs),
        memo_hash: scalar(900),
        block_height: 1,
    };

    let transfer_outputs =
        vec![note(token.asset_id(), 3), note(token.asset_id(), 4)];
    let transfer_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id: 7,
            contract_id,
            asset_id: token.asset_id(),
            mode: PrivateAssetCircuitMode::Transfer,
            root: token.root(),
            nullifiers: &[scalar(700)],
            outputs: &transfer_outputs,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash: scalar(901),
        });
    let transfer = PrivateTransfer {
        chain_id: 7,
        contract_id,
        asset_id: token.asset_id(),
        root: token.root(),
        nullifiers: vec![scalar(700)],
        outputs: transfer_outputs,
        proof: placeholder_proof(transfer_inputs),
        memo_hash: scalar(901),
        block_height: 2,
    };

    let burn_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id: 7,
            contract_id,
            asset_id: token.asset_id(),
            mode: PrivateAssetCircuitMode::Burn,
            root: token.root(),
            nullifiers: &[scalar(701)],
            outputs: &[],
            public_mint_amount: 0,
            public_burn_amount: 25,
            memo_hash: scalar(902),
        });
    let burn = PrivateBurn {
        chain_id: 7,
        contract_id,
        asset_id: token.asset_id(),
        root: token.root(),
        nullifiers: vec![scalar(701)],
        outputs: Vec::new(),
        amount: 25,
        proof: placeholder_proof(burn_inputs),
        memo_hash: scalar(902),
        block_height: 3,
    };

    assert_eq!(mint.proof.public_inputs.mode, PrivateAssetCircuitMode::Mint);
    assert_eq!(
        transfer.proof.public_inputs.mode,
        PrivateAssetCircuitMode::Transfer
    );
    assert_eq!(burn.proof.public_inputs.mode, PrivateAssetCircuitMode::Burn);
    assert_eq!(mint.proof.public_inputs.asset_id, token.asset_id());
    assert_eq!(transfer.proof.public_inputs.asset_id, token.asset_id());
    assert_eq!(burn.proof.public_inputs.asset_id, token.asset_id());

    println!("asset_id={:?}", token.asset_id().to_bytes());
    println!(
        "mint_inputs={} transfer_inputs={} burn_inputs={}",
        mint.proof.public_inputs.to_scalars().len(),
        transfer.proof.public_inputs.to_scalars().len(),
        burn.proof.public_inputs.to_scalars().len()
    );
}

fn note(asset_id: BlsScalar, seed: u64) -> PrivateAssetNote {
    PrivateAssetNote::new(
        asset_id,
        scalar(seed + 10),
        scalar(seed + 20),
        scalar(seed + 30),
        vec![seed as u8, seed.wrapping_add(1) as u8],
    )
}

fn scalar(value: u64) -> BlsScalar {
    BlsScalar::from(value)
}

fn placeholder_proof(
    public_inputs: dusk_contract_standards::token::drc20_phoenix::PrivateAssetPublicInputs,
) -> PrivateAssetProof {
    PrivateAssetProof {
        proof: b"replace-with-real-private-asset-proof".to_vec(),
        public_inputs,
    }
}
