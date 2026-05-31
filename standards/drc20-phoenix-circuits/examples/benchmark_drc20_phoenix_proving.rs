// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use drc20_phoenix_circuits::{
    compile, prove, verifier_data, Drc20PhoenixCircuit, FixedPublicInputs,
    InputNoteWitness, OutputNoteWitness,
};
use dusk_bytes::Serializable;
use dusk_contract_standards::token::drc20_phoenix::{
    compute_note_commitment, compute_owner_commitment,
    compute_value_commitment, encrypted_payload_hash, intent_hash,
    PrivateAssetCircuitMode, PrivateAssetIntent, PrivateAssetNote,
    PrivateAssetPublicInputs, DRC20_PHOENIX_VERSION,
};
use dusk_core::abi::ContractId;
use dusk_plonk::prelude::{BlsScalar, PublicParameters, Verifier};
use dusk_poseidon::{Domain, Hash};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

const SETUP_SIZE: usize = 1 << 16;
const DEV_SEED: u64 = 0x4452_4332_3050_484f;
const DUSK_CRS_HASH: &str =
    "6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059";
const DUSK_CRS_FILE: &str = "devnet-piecrust.crs";

#[derive(Clone)]
struct NoteWitness {
    note: PrivateAssetNote,
    spend_secret: BlsScalar,
    value: u64,
    value_blinder: BlsScalar,
    nonce: BlsScalar,
    payload_hash: BlsScalar,
}

struct BenchRow {
    height: usize,
    proof_type: &'static str,
    arity: &'static str,
    public_inputs: usize,
    constraints: usize,
    compile: Duration,
    witness: Duration,
    prove: Duration,
    verify: Duration,
    serialize: Duration,
    proof_bytes: usize,
    verifier_data_bytes: usize,
    verifier_hwm_kb: Option<u64>,
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let crs_arg = args.get(1).map(String::as_str);

    println!("# DRC20Phoenix proving benchmark");
    println!();
    println!("crs_arg={}", crs_arg.unwrap_or("<default-dusk-crs>"));
    println!("heights=17,20,23");
    println!("proofs=mint_0x2,transfer_1x2,burn_1x0,transfer_4x2");
    println!();

    let (pp, crs_load) = timed(|| public_parameters(crs_arg));
    println!(
        "setup,phase=crs_load,elapsed_ms={},hwm_kb={}",
        ms(crs_load),
        hwm_kb()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into())
    );

    println!();
    println!("| height | proof | arity | public inputs | constraints | compile ms | witness+PI ms | prove ms | verify ms | serialize ms | proof bytes | verifier data bytes | hwm KB |");
    println!("| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    run_height::<17>(&pp);
    run_height::<20>(&pp);
    run_height::<23>(&pp);
}

fn run_height<const HEIGHT: usize>(pp: &PublicParameters) {
    print_row(bench_mint::<HEIGHT>(pp));
    print_row(bench_transfer::<HEIGHT>(pp));
    print_row(bench_burn::<HEIGHT>(pp));
    print_row(bench_transfer_four::<HEIGHT>(pp));
}

fn print_row(row: BenchRow) {
    println!(
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
        row.height,
        row.proof_type,
        row.arity,
        row.public_inputs,
        row.constraints,
        ms(row.compile),
        ms(row.witness),
        ms(row.prove),
        ms(row.verify),
        ms(row.serialize),
        row.proof_bytes,
        row.verifier_data_bytes,
        row.verifier_hwm_kb
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    io::stdout().flush().expect("flush benchmark row");
}

fn bench_mint<const HEIGHT: usize>(pp: &PublicParameters) -> BenchRow {
    let (provers, compile_time) =
        timed(|| compile::<HEIGHT, 0, 2>(pp).expect("compile mint"));
    let (prover, verifier) = provers;
    let constraints = verifier_constraints(&verifier);
    let vd = verifier_data(&verifier);
    let public_inputs = 14 + 2;
    let mut rng = StdRng::seed_from_u64(11 + HEIGHT as u64);
    let (circuit, witness_time) =
        timed(|| mint_circuit::<HEIGHT>(scalar(9), 60, 40));
    let (proof_result, prove_time) =
        timed(|| prove(&prover, &mut rng, &circuit).expect("prove mint"));
    let (proof, scalars) = proof_result;
    let (_, verify_time) =
        timed(|| verifier.verify(&proof, &scalars).expect("verify mint"));
    let (proof_bytes, serialize_time) = timed(|| proof.to_bytes().to_vec());

    row::<HEIGHT>(
        "mint",
        "0x2",
        public_inputs,
        constraints,
        compile_time,
        witness_time,
        prove_time,
        verify_time,
        serialize_time,
        proof_bytes,
        vd.len(),
    )
}

fn bench_transfer<const HEIGHT: usize>(pp: &PublicParameters) -> BenchRow {
    let (provers, compile_time) =
        timed(|| compile::<HEIGHT, 1, 2>(pp).expect("compile transfer"));
    let (prover, verifier) = provers;
    let constraints = verifier_constraints(&verifier);
    let vd = verifier_data(&verifier);
    let public_inputs = 14 + 1 + 2;
    let mut rng = StdRng::seed_from_u64(22 + HEIGHT as u64);
    let (circuit, witness_time) =
        timed(|| transfer_circuit::<HEIGHT>(scalar(9), 60, 25, 35));
    let (proof_result, prove_time) =
        timed(|| prove(&prover, &mut rng, &circuit).expect("prove transfer"));
    let (proof, scalars) = proof_result;
    let (_, verify_time) = timed(|| {
        verifier
            .verify(&proof, &scalars)
            .expect("verify transfer")
    });
    let (proof_bytes, serialize_time) = timed(|| proof.to_bytes().to_vec());

    row::<HEIGHT>(
        "transfer",
        "1x2",
        public_inputs,
        constraints,
        compile_time,
        witness_time,
        prove_time,
        verify_time,
        serialize_time,
        proof_bytes,
        vd.len(),
    )
}

fn bench_burn<const HEIGHT: usize>(pp: &PublicParameters) -> BenchRow {
    let (provers, compile_time) =
        timed(|| compile::<HEIGHT, 1, 0>(pp).expect("compile burn"));
    let (prover, verifier) = provers;
    let constraints = verifier_constraints(&verifier);
    let vd = verifier_data(&verifier);
    let public_inputs = 14 + 1;
    let mut rng = StdRng::seed_from_u64(33 + HEIGHT as u64);
    let (circuit, witness_time) =
        timed(|| burn_circuit::<HEIGHT>(scalar(9), 25));
    let (proof_result, prove_time) =
        timed(|| prove(&prover, &mut rng, &circuit).expect("prove burn"));
    let (proof, scalars) = proof_result;
    let (_, verify_time) =
        timed(|| verifier.verify(&proof, &scalars).expect("verify burn"));
    let (proof_bytes, serialize_time) = timed(|| proof.to_bytes().to_vec());

    row::<HEIGHT>(
        "burn",
        "1x0",
        public_inputs,
        constraints,
        compile_time,
        witness_time,
        prove_time,
        verify_time,
        serialize_time,
        proof_bytes,
        vd.len(),
    )
}

fn bench_transfer_four<const HEIGHT: usize>(pp: &PublicParameters) -> BenchRow {
    let (provers, compile_time) =
        timed(|| compile::<HEIGHT, 4, 2>(pp).expect("compile transfer 4x2"));
    let (prover, verifier) = provers;
    let constraints = verifier_constraints(&verifier);
    let vd = verifier_data(&verifier);
    let public_inputs = 14 + 4 + 2;
    let mut rng = StdRng::seed_from_u64(44 + HEIGHT as u64);
    let (circuit, witness_time) =
        timed(|| transfer_four_circuit::<HEIGHT>(scalar(9)));
    let (proof_result, prove_time) = timed(|| {
        prove(&prover, &mut rng, &circuit).expect("prove transfer 4x2")
    });
    let (proof, scalars) = proof_result;
    let (_, verify_time) = timed(|| {
        verifier
            .verify(&proof, &scalars)
            .expect("verify transfer 4x2")
    });
    let (proof_bytes, serialize_time) = timed(|| proof.to_bytes().to_vec());

    row::<HEIGHT>(
        "transfer",
        "4x2",
        public_inputs,
        constraints,
        compile_time,
        witness_time,
        prove_time,
        verify_time,
        serialize_time,
        proof_bytes,
        vd.len(),
    )
}

#[allow(clippy::too_many_arguments)]
fn row<const HEIGHT: usize>(
    proof_type: &'static str,
    arity: &'static str,
    public_inputs: usize,
    constraints: usize,
    compile: Duration,
    witness: Duration,
    prove: Duration,
    verify: Duration,
    serialize: Duration,
    proof: Vec<u8>,
    verifier_data_bytes: usize,
) -> BenchRow {
    BenchRow {
        height: HEIGHT,
        proof_type,
        arity,
        public_inputs,
        constraints,
        compile,
        witness,
        prove,
        verify,
        serialize,
        proof_bytes: proof.len(),
        verifier_data_bytes,
        verifier_hwm_kb: hwm_kb(),
    }
}

fn mint_circuit<const HEIGHT: usize>(
    asset_id: BlsScalar,
    value_a: u64,
    value_b: u64,
) -> Drc20PhoenixCircuit<HEIGHT, 0, 2> {
    let outputs = [note(asset_id, 1, value_a), note(asset_id, 2, value_b)];
    let output_notes = outputs
        .iter()
        .map(|witness| witness.note.clone())
        .collect::<Vec<_>>();
    let public = standard_inputs(
        PrivateAssetCircuitMode::Mint,
        asset_id,
        empty_tree_root(HEIGHT),
        &[],
        &output_notes,
        u128::from(value_a) + u128::from(value_b),
        0,
        scalar(900),
    );
    Drc20PhoenixCircuit {
        public: FixedPublicInputs::<0, 2>::from_standard(&public).unwrap(),
        inputs: [],
        outputs: [output_witness(&outputs[0]), output_witness(&outputs[1])],
    }
}

fn transfer_circuit<const HEIGHT: usize>(
    asset_id: BlsScalar,
    input_value: u64,
    output_a: u64,
    output_b: u64,
) -> Drc20PhoenixCircuit<HEIGHT, 1, 2> {
    let input = note(asset_id, 3, input_value);
    let outputs = [note(asset_id, 4, output_a), note(asset_id, 5, output_b)];
    let output_notes = outputs
        .iter()
        .map(|witness| witness.note.clone())
        .collect::<Vec<_>>();
    let (path, path_is_left, root) =
        opening_for_zero_position::<HEIGHT>(input.note.commitment);
    let nullifier = drc20_phoenix_circuits::nullifier(
        asset_id,
        input.spend_secret,
        input.note.commitment,
    );
    let public = standard_inputs(
        PrivateAssetCircuitMode::Transfer,
        asset_id,
        root,
        &[nullifier],
        &output_notes,
        0,
        0,
        scalar(901),
    );
    Drc20PhoenixCircuit {
        public: FixedPublicInputs::<1, 2>::from_standard(&public).unwrap(),
        inputs: [input_witness(&input, path, path_is_left)],
        outputs: [output_witness(&outputs[0]), output_witness(&outputs[1])],
    }
}

fn burn_circuit<const HEIGHT: usize>(
    asset_id: BlsScalar,
    input_value: u64,
) -> Drc20PhoenixCircuit<HEIGHT, 1, 0> {
    let input = note(asset_id, 6, input_value);
    let (path, path_is_left, root) =
        opening_for_zero_position::<HEIGHT>(input.note.commitment);
    let nullifier = drc20_phoenix_circuits::nullifier(
        asset_id,
        input.spend_secret,
        input.note.commitment,
    );
    let public = standard_inputs(
        PrivateAssetCircuitMode::Burn,
        asset_id,
        root,
        &[nullifier],
        &[],
        0,
        u128::from(input_value),
        scalar(902),
    );
    Drc20PhoenixCircuit {
        public: FixedPublicInputs::<1, 0>::from_standard(&public).unwrap(),
        inputs: [input_witness(&input, path, path_is_left)],
        outputs: [],
    }
}

fn transfer_four_circuit<const HEIGHT: usize>(
    asset_id: BlsScalar,
) -> Drc20PhoenixCircuit<HEIGHT, 4, 2> {
    let input = note(asset_id, 7, 15);
    let outputs = [note(asset_id, 8, 30), note(asset_id, 9, 30)];
    let output_notes = outputs
        .iter()
        .map(|witness| witness.note.clone())
        .collect::<Vec<_>>();
    let (path, path_is_left, root) =
        opening_for_zero_position::<HEIGHT>(input.note.commitment);
    let nullifier = drc20_phoenix_circuits::nullifier(
        asset_id,
        input.spend_secret,
        input.note.commitment,
    );
    let nullifiers = [nullifier; 4];
    let public = standard_inputs(
        PrivateAssetCircuitMode::Transfer,
        asset_id,
        root,
        &nullifiers,
        &output_notes,
        0,
        0,
        scalar(903),
    );
    Drc20PhoenixCircuit {
        public: FixedPublicInputs::<4, 2>::from_standard(&public).unwrap(),
        inputs: [
            input_witness(&input, path, path_is_left),
            input_witness(&input, path, path_is_left),
            input_witness(&input, path, path_is_left),
            input_witness(&input, path, path_is_left),
        ],
        outputs: [output_witness(&outputs[0]), output_witness(&outputs[1])],
    }
}

#[allow(clippy::too_many_arguments)]
fn standard_inputs(
    mode: PrivateAssetCircuitMode,
    asset_id: BlsScalar,
    root: BlsScalar,
    nullifiers: &[BlsScalar],
    outputs: &[PrivateAssetNote],
    public_mint_amount: u128,
    public_burn_amount: u128,
    memo_hash: BlsScalar,
) -> PrivateAssetPublicInputs {
    let chain_id = 2;
    let contract_id = ContractId::from_bytes([7; 32]);
    let output_commitments = outputs
        .iter()
        .map(|note| note.commitment)
        .collect::<Vec<_>>();
    let intent_hash = intent_hash(PrivateAssetIntent {
        chain_id,
        contract_id,
        asset_id,
        mode,
        root,
        nullifiers,
        output_commitments: &output_commitments,
        public_mint_amount,
        public_burn_amount,
        memo_hash,
    });

    PrivateAssetPublicInputs {
        version: DRC20_PHOENIX_VERSION,
        chain_id,
        contract_id,
        asset_id,
        mode,
        root,
        nullifiers: nullifiers.to_vec(),
        output_commitments,
        public_mint_amount,
        public_burn_amount,
        intent_hash,
    }
}

fn note(asset_id: BlsScalar, seed: u64, value: u64) -> NoteWitness {
    let spend_secret = scalar(10_000 + seed);
    let value_blinder = scalar(20_000 + seed);
    let nonce = scalar(30_000 + seed);
    let payload = vec![seed as u8, value as u8];
    let payload_hash = encrypted_payload_hash(&payload);
    let owner_commitment = compute_owner_commitment(spend_secret);
    let value_commitment =
        compute_value_commitment(asset_id, value, value_blinder);
    let note = PrivateAssetNote::new(
        asset_id,
        owner_commitment,
        value_commitment,
        nonce,
        payload,
    );
    assert_eq!(
        note.commitment,
        compute_note_commitment(
            asset_id,
            owner_commitment,
            value_commitment,
            nonce,
            payload_hash
        )
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

fn input_witness<const HEIGHT: usize>(
    note: &NoteWitness,
    path: [BlsScalar; HEIGHT],
    path_is_left: [BlsScalar; HEIGHT],
) -> InputNoteWitness<HEIGHT> {
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

fn opening_for_zero_position<const HEIGHT: usize>(
    leaf: BlsScalar,
) -> ([BlsScalar; HEIGHT], [BlsScalar; HEIGHT], BlsScalar) {
    let defaults = default_subtree_roots(HEIGHT);
    let mut path = [BlsScalar::zero(); HEIGHT];
    let path_is_left = [BlsScalar::zero(); HEIGHT];
    let mut root = leaf;

    for height in 0..HEIGHT {
        path[height] = defaults[height];
        root = hash_pair(root, defaults[height]);
    }

    (path, path_is_left, root)
}

fn empty_tree_root(height: usize) -> BlsScalar {
    default_subtree_roots(height)[height]
}

fn default_subtree_roots(height: usize) -> Vec<BlsScalar> {
    let mut roots = Vec::with_capacity(height + 1);
    roots.push(domain_scalar(b"DRC20Phoenix.empty_leaf.v1"));
    for level in 1..=height {
        let child = roots[level - 1];
        roots.push(hash_pair(child, child));
    }
    roots
}

fn hash_pair(left: BlsScalar, right: BlsScalar) -> BlsScalar {
    poseidon(b"DRC20Phoenix.merkle_pair.v1", &[left, right])
}

fn poseidon(domain: &[u8], scalars: &[BlsScalar]) -> BlsScalar {
    let mut input = Vec::with_capacity(scalars.len() + 2);
    input.push(domain_scalar(domain));
    input.push(BlsScalar::from(scalars.len() as u64));
    input.extend_from_slice(scalars);
    Hash::digest(Domain::Other, &input)[0]
}

fn domain_scalar(domain: &[u8]) -> BlsScalar {
    BlsScalar::hash_to_scalar(domain)
}

fn verifier_constraints(verifier: &Verifier) -> usize {
    let bytes = verifier.to_bytes();
    let constraints = bytes
        .get(40..48)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_be_bytes)
        .expect("verifier constraints header") as usize;
    constraints
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
    let sha256 = hex(&Sha256::digest(bytes.as_slice()));
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

fn hwm_kb() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmHWM:").and_then(|rest| {
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
    })
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let value = f();
    (value, start.elapsed())
}

fn ms(duration: Duration) -> u128 {
    duration.as_millis()
}

fn scalar(value: u64) -> BlsScalar {
    BlsScalar::from(value)
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
