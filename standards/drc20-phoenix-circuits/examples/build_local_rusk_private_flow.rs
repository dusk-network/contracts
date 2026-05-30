// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::env;
use std::fs;
use std::path::Path;

use drc20_phoenix_circuits::{
    compile, prove, Drc20PhoenixCircuit, FixedPublicInputs, InputNoteWitness,
    OutputNoteWitness, DEV_ARTIFACT_TREE_HEIGHT,
};
use dusk_bytes::Serializable;
use dusk_contract_standards::token::drc20_phoenix::{
    compute_owner_commitment, compute_value_commitment, encrypted_payload_hash,
    AdminId, Drc20Phoenix, Init, PrivateAssetCircuitMode, PrivateAssetNote,
    PrivateAssetProof, PrivateAssetPublicInputBuilder, PrivateAssetVerifier,
    PrivateAssetVerifierConfig, PrivateBurn, PrivateMint, PrivateTransfer,
    TokenMetadata, V1_SUPPORTED_ARITIES,
};
use dusk_core::abi::ContractId;
use dusk_core::BlsScalar;
use dusk_plonk::prelude::PublicParameters;
use rand::rngs::StdRng;
use rand::SeedableRng;

const SETUP_SIZE: usize = 1 << 16;
const DEV_SEED: u64 = 0x4452_4332_3050_484f;
const ADMIN: AdminId = [7; 32];

#[derive(Clone, Copy)]
struct DevVerifier;

impl PrivateAssetVerifier for DevVerifier {
    fn verify(
        &self,
        _verifier_data: &[u8],
        _proof: &[u8],
        _public_inputs: &[BlsScalar],
    ) -> bool {
        true
    }
}

#[derive(Clone)]
struct NoteWitness {
    note: PrivateAssetNote,
    spend_secret: BlsScalar,
    value: u64,
    value_blinder: BlsScalar,
    nonce: BlsScalar,
    payload_hash: BlsScalar,
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("build") => build(&args),
        Some("decode-u32") => decode_u32(&args),
        Some("decode-u64") => decode_u64(&args),
        Some("decode-u128") => decode_u128(&args),
        Some("decode-bool") => decode_bool(&args),
        Some(other) => panic!("unknown command: {other}"),
        None => panic!("usage: build_local_rusk_private_flow build <contract-id-hex> <verifier-data-dir> | decode-u32 <hex> | decode-u64 <hex> | decode-u128 <hex> | decode-bool <hex>"),
    }
}

fn build(args: &[String]) {
    let contract_id = parse_contract_id(args.get(2).expect("contract id hex"));
    let verifier_dir = Path::new(args.get(3).expect("verifier data dir"));
    let verifier_set = verifier_set(verifier_dir);

    let mut token = Drc20Phoenix::new();
    let init = Init {
        metadata: TokenMetadata {
            name: "Local Private Token".into(),
            symbol: "pLOC".into(),
            decimals: 9,
        },
        chain_id: 0,
        contract_id,
        deployment_salt: [9; 32],
        admin: ADMIN,
        cap: Some(1_000),
        root_window: 64,
        verifier_set,
    };
    token.init(init.clone());

    let mut setup_rng = StdRng::seed_from_u64(DEV_SEED);
    let pp = PublicParameters::setup(SETUP_SIZE, &mut setup_rng).unwrap();
    let mut rng = StdRng::seed_from_u64(11);
    let asset_id = token.asset_id();

    let mint_notes = [note(asset_id, 1, 60), note(asset_id, 2, 40)];
    let mint_outputs = mint_notes
        .iter()
        .map(|witness| witness.note.clone())
        .collect::<Vec<_>>();
    let mint_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id: 0,
            contract_id,
            asset_id,
            mode: PrivateAssetCircuitMode::Mint,
            root: token.root(),
            nullifiers: &[],
            outputs: &mint_outputs,
            public_mint_amount: 100,
            public_burn_amount: 0,
            memo_hash: scalar(900),
        });
    let mint_proof = mint_proof(&pp, &mut rng, &mint_inputs, &mint_notes);
    let mint = PrivateMint {
        caller: ADMIN,
        chain_id: 0,
        contract_id,
        asset_id,
        amount: 100,
        outputs: mint_outputs,
        proof: mint_proof,
        memo_hash: scalar(900),
        block_height: 1,
    };
    token.mint_private_with_verifier(mint.clone(), &DevVerifier);

    let transfer_notes = [note(asset_id, 3, 25), note(asset_id, 4, 35)];
    let transfer_outputs = transfer_notes
        .iter()
        .map(|witness| witness.note.clone())
        .collect::<Vec<_>>();
    let transfer_root = token.root();
    let transfer_nullifier =
        dusk_contract_standards::token::drc20_phoenix::compute_nullifier(
            asset_id,
            mint_notes[0].spend_secret,
            mint_notes[0].note.commitment,
        );
    let transfer_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id: 0,
            contract_id,
            asset_id,
            mode: PrivateAssetCircuitMode::Transfer,
            root: transfer_root,
            nullifiers: &[transfer_nullifier],
            outputs: &transfer_outputs,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash: scalar(901),
        });
    let transfer_opening = token.opening(0).unwrap();
    let transfer_proof = transfer_proof(
        &pp,
        &mut rng,
        &transfer_inputs,
        &mint_notes[0],
        &transfer_opening,
        &transfer_notes,
    );
    let transfer = PrivateTransfer {
        chain_id: 0,
        contract_id,
        asset_id,
        root: transfer_root,
        nullifiers: vec![transfer_nullifier],
        outputs: transfer_outputs,
        proof: transfer_proof,
        memo_hash: scalar(901),
        block_height: 2,
    };

    let mut bad_transfer = transfer.clone();
    bad_transfer.proof.proof[0] ^= 1;

    token.transfer_private_with_verifier(transfer.clone(), &DevVerifier);

    let burn_root = token.root();
    let burn_nullifier =
        dusk_contract_standards::token::drc20_phoenix::compute_nullifier(
            asset_id,
            transfer_notes[0].spend_secret,
            transfer_notes[0].note.commitment,
        );
    let burn_outputs = Vec::new();
    let burn_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id: 0,
            contract_id,
            asset_id,
            mode: PrivateAssetCircuitMode::Burn,
            root: burn_root,
            nullifiers: &[burn_nullifier],
            outputs: &burn_outputs,
            public_mint_amount: 0,
            public_burn_amount: 25,
            memo_hash: scalar(902),
        });
    let burn_opening = token.opening(2).unwrap();
    let burn_proof = burn_proof(
        &pp,
        &mut rng,
        &burn_inputs,
        &transfer_notes[0],
        &burn_opening,
    );
    let burn = PrivateBurn {
        chain_id: 0,
        contract_id,
        asset_id,
        root: burn_root,
        nullifiers: vec![burn_nullifier],
        outputs: burn_outputs,
        amount: 25,
        proof: burn_proof,
        memo_hash: scalar(902),
        block_height: 3,
    };

    let pause_args = ADMIN;
    let unpause_args = ADMIN;

    println!("init_args={}", encode(&init));
    println!("mint_args={}", encode(&mint));
    println!("bad_transfer_args={}", encode(&bad_transfer));
    println!("transfer_args={}", encode(&transfer));
    println!("burn_args={}", encode(&burn));
    println!("pause_args={}", encode(&pause_args));
    println!("unpause_args={}", encode(&unpause_args));
    println!("expected_asset_id={}", hex(&asset_id.to_bytes()));
    println!("expected_minted_supply=100");
    println!("expected_burned_supply=25");
    println!("expected_net_supply=75");
    println!("expected_num_notes_after_mint=2");
    println!("expected_num_notes_after_transfer=4");
    println!("expected_num_notes_after_burn=4");
}

fn mint_proof(
    pp: &PublicParameters,
    rng: &mut StdRng,
    inputs: &dusk_contract_standards::token::drc20_phoenix::PrivateAssetPublicInputs,
    outputs: &[NoteWitness; 2],
) -> PrivateAssetProof {
    let fixed = FixedPublicInputs::<0, 2>::from_standard(inputs).unwrap();
    let circuit = Drc20PhoenixCircuit::<DEV_ARTIFACT_TREE_HEIGHT, 0, 2> {
        public: fixed,
        inputs: [],
        outputs: [output_witness(&outputs[0]), output_witness(&outputs[1])],
    };
    prove_for::<0, 2>(pp, rng, inputs.clone(), circuit)
}

fn transfer_proof(
    pp: &PublicParameters,
    rng: &mut StdRng,
    inputs: &dusk_contract_standards::token::drc20_phoenix::PrivateAssetPublicInputs,
    input: &NoteWitness,
    opening: &dusk_contract_standards::token::drc20_phoenix::PrivateNoteOpening,
    outputs: &[NoteWitness; 2],
) -> PrivateAssetProof {
    let fixed = FixedPublicInputs::<1, 2>::from_standard(inputs).unwrap();
    let circuit = Drc20PhoenixCircuit::<DEV_ARTIFACT_TREE_HEIGHT, 1, 2> {
        public: fixed,
        inputs: [input_witness(input, opening)],
        outputs: [output_witness(&outputs[0]), output_witness(&outputs[1])],
    };
    prove_for::<1, 2>(pp, rng, inputs.clone(), circuit)
}

fn burn_proof(
    pp: &PublicParameters,
    rng: &mut StdRng,
    inputs: &dusk_contract_standards::token::drc20_phoenix::PrivateAssetPublicInputs,
    input: &NoteWitness,
    opening: &dusk_contract_standards::token::drc20_phoenix::PrivateNoteOpening,
) -> PrivateAssetProof {
    let fixed = FixedPublicInputs::<1, 0>::from_standard(inputs).unwrap();
    let circuit = Drc20PhoenixCircuit::<DEV_ARTIFACT_TREE_HEIGHT, 1, 0> {
        public: fixed,
        inputs: [input_witness(input, opening)],
        outputs: [],
    };
    prove_for::<1, 0>(pp, rng, inputs.clone(), circuit)
}

fn prove_for<const INPUTS: usize, const OUTPUTS: usize>(
    pp: &PublicParameters,
    rng: &mut StdRng,
    public_inputs: dusk_contract_standards::token::drc20_phoenix::PrivateAssetPublicInputs,
    circuit: Drc20PhoenixCircuit<DEV_ARTIFACT_TREE_HEIGHT, INPUTS, OUTPUTS>,
) -> PrivateAssetProof {
    let (prover, verifier) =
        compile::<DEV_ARTIFACT_TREE_HEIGHT, INPUTS, OUTPUTS>(pp).unwrap();
    let (proof, scalars) = prove(&prover, rng, &circuit).unwrap();
    verifier.verify(&proof, &scalars).unwrap();
    PrivateAssetProof {
        proof: proof.to_bytes().to_vec(),
        public_inputs,
    }
}

fn input_witness(
    note: &NoteWitness,
    opening: &dusk_contract_standards::token::drc20_phoenix::PrivateNoteOpening,
) -> InputNoteWitness<DEV_ARTIFACT_TREE_HEIGHT> {
    let mut path = [BlsScalar::zero(); DEV_ARTIFACT_TREE_HEIGHT];
    let mut path_is_left = [BlsScalar::zero(); DEV_ARTIFACT_TREE_HEIGHT];
    for (idx, sibling) in opening.siblings.iter().enumerate() {
        path[idx] = sibling.hash;
        path_is_left[idx] = if sibling.is_left {
            BlsScalar::one()
        } else {
            BlsScalar::zero()
        };
    }
    InputNoteWitness {
        spend_secret: note.spend_secret,
        value: note.value,
        value_blinder: note.value_blinder,
        nonce: note.nonce,
        payload_hash: note.payload_hash,
        path,
        path_is_left,
    }
}

fn output_witness(note: &NoteWitness) -> OutputNoteWitness {
    OutputNoteWitness {
        owner_commitment: note.note.owner_commitment,
        value: note.value,
        value_blinder: note.value_blinder,
        nonce: note.nonce,
        payload_hash: note.payload_hash,
    }
}

fn note(asset_id: BlsScalar, seed: u64, value: u64) -> NoteWitness {
    let spend_secret = scalar(10_000 + seed);
    let value_blinder = scalar(20_000 + seed);
    let nonce = scalar(30_000 + seed);
    let payload = vec![seed as u8, value as u8];
    let payload_hash = encrypted_payload_hash(&payload);
    let note = PrivateAssetNote::new(
        asset_id,
        compute_owner_commitment(spend_secret),
        compute_value_commitment(asset_id, value, value_blinder),
        nonce,
        payload,
    );
    NoteWitness {
        note,
        spend_secret,
        value,
        value_blinder,
        nonce,
        payload_hash,
    }
}

fn verifier_set(dir: &Path) -> Vec<PrivateAssetVerifierConfig> {
    V1_SUPPORTED_ARITIES
        .iter()
        .copied()
        .map(|key| {
            let file = format!(
                "drc20-phoenix-v{}-{}-{}x{}.vd",
                key.version,
                mode_name(key.mode),
                key.input_count,
                key.output_count
            );
            PrivateAssetVerifierConfig::new(
                key,
                fs::read(dir.join(file)).expect("read verifier data"),
            )
        })
        .collect()
}

fn mode_name(mode: PrivateAssetCircuitMode) -> &'static str {
    match mode {
        PrivateAssetCircuitMode::Mint => "mint",
        PrivateAssetCircuitMode::Transfer => "transfer",
        PrivateAssetCircuitMode::Burn => "burn",
    }
}

fn parse_contract_id(hex_value: &str) -> ContractId {
    let bytes = decode_hex(hex_value);
    let bytes: [u8; 32] = bytes.try_into().expect("32-byte contract id");
    ContractId::from_bytes(bytes)
}

fn scalar(value: u64) -> BlsScalar {
    BlsScalar::from(value)
}

fn encode<T>(value: &T) -> String
where
    T: rkyv::Serialize<rkyv::ser::serializers::AllocSerializer<1048576>>,
{
    hex(&rkyv::to_bytes::<_, 1048576>(value).unwrap())
}

fn decode_u64(args: &[String]) {
    let bytes = decode_hex(args.get(2).expect("hex bytes"));
    let archived = unsafe { rkyv::archived_root::<u64>(&bytes) };
    println!("{}", *archived);
}

fn decode_u32(args: &[String]) {
    let bytes = decode_hex(args.get(2).expect("hex bytes"));
    let archived = unsafe { rkyv::archived_root::<u32>(&bytes) };
    println!("{}", *archived);
}

fn decode_u128(args: &[String]) {
    let bytes = decode_hex(args.get(2).expect("hex bytes"));
    let archived = unsafe { rkyv::archived_root::<u128>(&bytes) };
    println!("{}", *archived);
}

fn decode_bool(args: &[String]) {
    let bytes = decode_hex(args.get(2).expect("hex bytes"));
    let archived = unsafe { rkyv::archived_root::<bool>(&bytes) };
    println!("{}", bool::from(*archived));
}

fn decode_hex(input: &str) -> Vec<u8> {
    let input = input.trim();
    assert!(input.len().is_multiple_of(2), "hex length must be even");
    (0..input.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&input[idx..idx + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
