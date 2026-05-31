// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::collections::VecDeque;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

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
    TokenMetadata, DRC20_PHOENIX_TREE_HEIGHT, V1_SUPPORTED_ARITIES,
};
use dusk_core::abi::ContractId;
use dusk_core::BlsScalar;
use dusk_plonk::prelude::PublicParameters;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

const SETUP_SIZE: usize = 1 << 16;
const DEV_SEED: u64 = 0x4452_4332_3050_484f;
const DUSK_CRS_HASH: &str =
    "6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059";
const DUSK_CRS_FILE: &str = "devnet-piecrust.crs";
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

#[derive(Clone)]
struct SpendableNote {
    witness: NoteWitness,
    position: u64,
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
    let chain_id = args
        .get(4)
        .map(|value| value.parse::<u8>().expect("u8 chain id"))
        .unwrap_or(0);
    let crs_arg = args.get(5).map(String::as_str);
    let verifier_set = verifier_set(verifier_dir);

    let mut token = Drc20Phoenix::new();
    let init = Init {
        metadata: TokenMetadata {
            name: "Local Private Token".into(),
            symbol: "pLOC".into(),
            decimals: 9,
        },
        chain_id,
        contract_id,
        deployment_salt: [9; 32],
        admin: ADMIN,
        cap: Some(1_000),
        root_window: 64,
        verifier_set,
    };
    token.init(init.clone());

    let pp = public_parameters(crs_arg);
    let mut rng = StdRng::seed_from_u64(11);
    let asset_id = token.asset_id();

    let mint_notes = [note(asset_id, 1, 60), note(asset_id, 2, 40)];
    let mint_outputs = mint_notes
        .iter()
        .map(|witness| witness.note.clone())
        .collect::<Vec<_>>();
    let mint_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id,
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
        chain_id,
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
            chain_id,
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
    let initial_transfer_proof = transfer_proof(
        &pp,
        &mut rng,
        &transfer_inputs,
        &mint_notes[0],
        &transfer_opening,
        &transfer_notes,
    );
    let transfer = PrivateTransfer {
        chain_id,
        contract_id,
        asset_id,
        root: transfer_root,
        nullifiers: vec![transfer_nullifier],
        outputs: transfer_outputs,
        proof: initial_transfer_proof,
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
            chain_id,
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
        chain_id,
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
    token.burn_private_with_verifier(burn.clone(), &DevVerifier);

    let extra_transfer_notes = [note(asset_id, 5, 15), note(asset_id, 6, 25)];
    let extra_transfer_outputs = extra_transfer_notes
        .iter()
        .map(|witness| witness.note.clone())
        .collect::<Vec<_>>();
    let extra_transfer_root = token.root();
    let extra_transfer_nullifier =
        dusk_contract_standards::token::drc20_phoenix::compute_nullifier(
            asset_id,
            mint_notes[1].spend_secret,
            mint_notes[1].note.commitment,
        );
    let extra_transfer_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id,
            contract_id,
            asset_id,
            mode: PrivateAssetCircuitMode::Transfer,
            root: extra_transfer_root,
            nullifiers: &[extra_transfer_nullifier],
            outputs: &extra_transfer_outputs,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash: scalar(903),
        });
    let extra_transfer_opening = token.opening(1).unwrap();
    let extra_transfer_proof = transfer_proof(
        &pp,
        &mut rng,
        &extra_transfer_inputs,
        &mint_notes[1],
        &extra_transfer_opening,
        &extra_transfer_notes,
    );
    let extra_transfer = PrivateTransfer {
        chain_id,
        contract_id,
        asset_id,
        root: extra_transfer_root,
        nullifiers: vec![extra_transfer_nullifier],
        outputs: extra_transfer_outputs,
        proof: extra_transfer_proof,
        memo_hash: scalar(903),
        block_height: 4,
    };
    token.transfer_private_with_verifier(extra_transfer.clone(), &DevVerifier);

    let second_extra_transfer_notes =
        [note(asset_id, 7, 10), note(asset_id, 8, 25)];
    let second_extra_transfer_outputs = second_extra_transfer_notes
        .iter()
        .map(|witness| witness.note.clone())
        .collect::<Vec<_>>();
    let second_extra_transfer_root = token.root();
    let second_extra_transfer_nullifier =
        dusk_contract_standards::token::drc20_phoenix::compute_nullifier(
            asset_id,
            transfer_notes[1].spend_secret,
            transfer_notes[1].note.commitment,
        );
    let second_extra_transfer_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id,
            contract_id,
            asset_id,
            mode: PrivateAssetCircuitMode::Transfer,
            root: second_extra_transfer_root,
            nullifiers: &[second_extra_transfer_nullifier],
            outputs: &second_extra_transfer_outputs,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash: scalar(904),
        });
    let second_extra_transfer_opening = token.opening(3).unwrap();
    let second_extra_transfer_proof = transfer_proof(
        &pp,
        &mut rng,
        &second_extra_transfer_inputs,
        &transfer_notes[1],
        &second_extra_transfer_opening,
        &second_extra_transfer_notes,
    );
    let second_extra_transfer = PrivateTransfer {
        chain_id,
        contract_id,
        asset_id,
        root: second_extra_transfer_root,
        nullifiers: vec![second_extra_transfer_nullifier],
        outputs: second_extra_transfer_outputs,
        proof: second_extra_transfer_proof,
        memo_hash: scalar(904),
        block_height: 5,
    };
    token.transfer_private_with_verifier(
        second_extra_transfer.clone(),
        &DevVerifier,
    );

    let mut spendable = VecDeque::from([
        SpendableNote {
            witness: extra_transfer_notes[0].clone(),
            position: 4,
        },
        SpendableNote {
            witness: extra_transfer_notes[1].clone(),
            position: 5,
        },
        SpendableNote {
            witness: second_extra_transfer_notes[0].clone(),
            position: 6,
        },
        SpendableNote {
            witness: second_extra_transfer_notes[1].clone(),
            position: 7,
        },
    ]);
    let follow_up_transfers = build_follow_up_transfers(
        &mut token,
        &pp,
        &mut rng,
        chain_id,
        contract_id,
        asset_id,
        &mut spendable,
        9,
        905,
        6,
    );

    let pause_args = ADMIN;
    let unpause_args = ADMIN;

    println!("init_args={}", encode(&init));
    println!("mint_args={}", encode(&mint));
    println!("bad_transfer_args={}", encode(&bad_transfer));
    println!("transfer_args={}", encode(&transfer));
    println!("burn_args={}", encode(&burn));
    println!("extra_transfer_args={}", encode(&extra_transfer));
    println!(
        "second_extra_transfer_args={}",
        encode(&second_extra_transfer)
    );
    for (idx, transfer) in follow_up_transfers.iter().enumerate() {
        println!("follow_up_transfer_{}_args={}", idx + 1, encode(transfer));
        println!(
            "expected_num_notes_after_follow_up_transfer_{}={}",
            idx + 1,
            10 + (idx as u64 * 2)
        );
    }
    if let Some(transfer) = follow_up_transfers.first() {
        println!("third_extra_transfer_args={}", encode(transfer));
    }
    if let Some(transfer) = follow_up_transfers.get(1) {
        println!("fourth_extra_transfer_args={}", encode(transfer));
    }
    if let Some(transfer) = follow_up_transfers.get(2) {
        println!("fifth_extra_transfer_args={}", encode(transfer));
    }
    if let Some(transfer) = follow_up_transfers.get(3) {
        println!("sixth_extra_transfer_args={}", encode(transfer));
    }
    println!("pause_args={}", encode(&pause_args));
    println!("unpause_args={}", encode(&unpause_args));
    println!("expected_asset_id={}", hex(&asset_id.to_bytes()));
    println!("expected_minted_supply=100");
    println!("expected_burned_supply=25");
    println!("expected_net_supply=75");
    println!("expected_num_notes_after_mint=2");
    println!("expected_num_notes_after_transfer=4");
    println!("expected_num_notes_after_burn=4");
    println!("expected_num_notes_after_extra_transfer=6");
    println!("expected_num_notes_after_second_extra_transfer=8");
    println!(
        "expected_num_notes_after_all_follow_up_transfers={}",
        token.num_notes()
    );
    println!("expected_num_notes_after_third_extra_transfer=10");
    println!("expected_num_notes_after_fourth_extra_transfer=12");
    println!("expected_num_notes_after_fifth_extra_transfer=14");
    println!("expected_num_notes_after_sixth_extra_transfer=16");
}

#[allow(clippy::too_many_arguments)]
fn build_follow_up_transfers(
    token: &mut Drc20Phoenix,
    pp: &PublicParameters,
    rng: &mut StdRng,
    chain_id: u8,
    contract_id: ContractId,
    asset_id: BlsScalar,
    spendable: &mut VecDeque<SpendableNote>,
    first_seed: u64,
    first_memo: u64,
    first_block_height: u64,
) -> Vec<PrivateTransfer> {
    let capacity = 1u64 << DRC20_PHOENIX_TREE_HEIGHT;
    let mut next_seed = first_seed;
    let mut next_memo = first_memo;
    let mut next_block_height = first_block_height;
    let mut transfers = Vec::new();

    while token.num_notes() + 2 <= capacity {
        let Some(input) = spendable.pop_front() else {
            break;
        };
        let first_value = input.witness.value / 2;
        let second_value = input.witness.value - first_value;
        let outputs = [
            note(asset_id, next_seed, first_value),
            note(asset_id, next_seed + 1, second_value),
        ];
        let first_output_position = token.num_notes();
        let transfer = transfer_call(
            token,
            pp,
            rng,
            chain_id,
            contract_id,
            asset_id,
            &input.witness,
            input.position,
            outputs.clone(),
            scalar(next_memo),
            next_block_height,
        );
        spendable.push_back(SpendableNote {
            witness: outputs[0].clone(),
            position: first_output_position,
        });
        spendable.push_back(SpendableNote {
            witness: outputs[1].clone(),
            position: first_output_position + 1,
        });
        transfers.push(transfer);
        next_seed += 2;
        next_memo += 1;
        next_block_height += 1;
    }

    transfers
}

#[allow(clippy::too_many_arguments)]
fn transfer_call(
    token: &mut Drc20Phoenix,
    pp: &PublicParameters,
    rng: &mut StdRng,
    chain_id: u8,
    contract_id: ContractId,
    asset_id: BlsScalar,
    input: &NoteWitness,
    input_position: u64,
    outputs: [NoteWitness; 2],
    memo_hash: BlsScalar,
    block_height: u64,
) -> PrivateTransfer {
    let output_notes = outputs
        .iter()
        .map(|witness| witness.note.clone())
        .collect::<Vec<_>>();
    let root = token.root();
    let nullifier =
        dusk_contract_standards::token::drc20_phoenix::compute_nullifier(
            asset_id,
            input.spend_secret,
            input.note.commitment,
        );
    let public_inputs =
        token.build_public_inputs(PrivateAssetPublicInputBuilder {
            chain_id,
            contract_id,
            asset_id,
            mode: PrivateAssetCircuitMode::Transfer,
            root,
            nullifiers: &[nullifier],
            outputs: &output_notes,
            public_mint_amount: 0,
            public_burn_amount: 0,
            memo_hash,
        });
    let opening = token.opening(input_position).unwrap();
    let proof =
        transfer_proof(pp, rng, &public_inputs, input, &opening, &outputs);
    let transfer = PrivateTransfer {
        chain_id,
        contract_id,
        asset_id,
        root,
        nullifiers: vec![nullifier],
        outputs: output_notes,
        proof,
        memo_hash,
        block_height,
    };
    token.transfer_private_with_verifier(transfer.clone(), &DevVerifier);
    transfer
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

fn public_parameters(crs_arg: Option<&str>) -> PublicParameters {
    if matches!(crs_arg, Some("--dev")) {
        if env::var_os("DRC20_PHOENIX_ALLOW_DEV_CRS").is_none() {
            panic!(
                "--dev requires DRC20_PHOENIX_ALLOW_DEV_CRS=1 to avoid accidental dev proofs"
            );
        }
        let mut setup_rng = StdRng::seed_from_u64(DEV_SEED);
        return PublicParameters::setup(SETUP_SIZE, &mut setup_rng)
            .expect("setup development public parameters");
    }

    let path = crs_arg.map(PathBuf::from).unwrap_or_else(default_crs_path);
    let bytes = fs::read(&path).unwrap_or_else(|err| {
        panic!("read Dusk CRS from {} failed: {err}", path.display())
    });
    let sha256 = sha256_hex(&bytes);
    if sha256 != DUSK_CRS_HASH {
        panic!(
            "Dusk CRS hash mismatch for {}: expected {}, got {}",
            path.display(),
            DUSK_CRS_HASH,
            sha256
        );
    }
    PublicParameters::from_slice(&bytes)
        .expect("decode Dusk CRS public parameters")
}

fn default_crs_path() -> PathBuf {
    if let Some(path) = env::var_os("DUSK_CRS_PATH") {
        return PathBuf::from(path);
    }
    let home = env::var_os("HOME").expect("HOME must be set or pass CRS path");
    Path::new(&home)
        .join(".dusk")
        .join("rusk")
        .join(DUSK_CRS_FILE)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
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
