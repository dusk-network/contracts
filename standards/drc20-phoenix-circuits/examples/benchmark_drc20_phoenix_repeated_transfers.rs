// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use drc20_phoenix_circuits::{
    proving::{Drc20PhoenixProvingContext, ProverCacheConfig},
    Drc20PhoenixCircuit, FixedPublicInputs, InputNoteWitness,
    OutputNoteWitness, DEV_ARTIFACT_TREE_HEIGHT,
};
use dusk_contract_standards::token::drc20_phoenix::{
    compute_note_commitment, compute_owner_commitment,
    compute_value_commitment, encrypted_payload_hash, intent_hash,
    PrivateAssetCircuitMode, PrivateAssetIntent, PrivateAssetNote,
    PrivateAssetPublicInputs, PrivateAssetVerifierKey, DRC20_PHOENIX_VERSION,
};
use dusk_core::abi::ContractId;
use dusk_plonk::prelude::{BlsScalar, PublicParameters};
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

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let transfers = arg_usize(&args, "--transfers").unwrap_or(50);
    let compare_compile_each_time =
        args.iter().any(|arg| arg == "--compare-compile-each-time");
    let crs_arg = arg_value(&args, "--crs");

    let total_start = Instant::now();
    let ((pp, crs_hash), crs_load) = timed(|| public_parameters(crs_arg));
    let setup_start = Instant::now();
    let mut ctx = proving_context(pp, crs_hash);
    ctx.ensure(PrivateAssetVerifierKey::new(
        PrivateAssetCircuitMode::Transfer,
        1,
        2,
    ))
    .expect("load transfer 1x2 prover");
    let setup_time = setup_start.elapsed();
    let mut rng = StdRng::seed_from_u64(77);
    let asset_id = scalar(9);
    let mut proof_times = Vec::with_capacity(transfers);

    for idx in 0..transfers {
        let circuit = transfer_circuit::<DEV_ARTIFACT_TREE_HEIGHT>(
            asset_id,
            10_000 + idx as u64 * 3,
            60,
            25,
            35,
        );
        let (circuit, public_inputs) = circuit;
        let start = Instant::now();
        let proof = ctx
            .prove_fixed::<_, 1, 2>(&mut rng, public_inputs, &circuit)
            .expect("prove transfer");
        assert!(
            !proof.proof.is_empty(),
            "proof bytes must be present for transfer {idx}"
        );
        proof_times.push(start.elapsed());
    }

    println!("# DRC20Phoenix repeated transfer benchmark");
    println!("transfers={transfers}");
    println!("tree_height={DEV_ARTIFACT_TREE_HEIGHT}");
    println!("crs_load_ms={}", ms(crs_load));
    println!("context_setup_ms={}", ms(setup_time));
    for info in ctx.loaded_artifacts() {
        println!(
            "artifact,mode={:?},arity={}x{},source={:?},load_ms={},constraints={},prover_bytes={},verifier_bytes={}",
            info.key.mode,
            info.key.input_count,
            info.key.output_count,
            info.source,
            ms(info.load_time),
            info.constraints,
            info.prover_bytes,
            info.verifier_bytes
        );
    }
    println!("first_proof_ms={}", ms(proof_times[0]));
    println!("median_proof_ms={}", ms(percentile(&proof_times, 50)));
    println!("p95_proof_ms={}", ms(percentile(&proof_times, 95)));
    println!("total_proof_ms={}", ms(proof_times.iter().sum()));
    println!("total_wall_ms={}", ms(total_start.elapsed()));
    println!("notes_generated={}", transfers * 2);
    println!(
        "hwm_kb={}",
        hwm_kb()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into())
    );

    if compare_compile_each_time {
        println!();
        println!("compile_each_time_comparison=enabled");
        println!(
            "compile_each_time_note=run benchmark_drc20_phoenix_proving for isolated compile/prove rows; this benchmark intentionally keeps the repeated path persistent"
        );
    }
}

fn transfer_circuit<const HEIGHT: usize>(
    asset_id: BlsScalar,
    seed: u64,
    input_value: u64,
    output_a: u64,
    output_b: u64,
) -> (
    Drc20PhoenixCircuit<HEIGHT, 1, 2>,
    PrivateAssetPublicInputs,
) {
    let input = note(asset_id, seed, input_value);
    let outputs = [
        note(asset_id, seed + 1, output_a),
        note(asset_id, seed + 2, output_b),
    ];
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
        scalar(901 + seed),
    );

    (
        Drc20PhoenixCircuit {
            public: FixedPublicInputs::<1, 2>::from_standard(&public).unwrap(),
            inputs: [input_witness(&input, path, path_is_left)],
            outputs: [
                output_witness(&outputs[0]),
                output_witness(&outputs[1]),
            ],
        },
        public,
    )
}

fn standard_inputs(
    mode: PrivateAssetCircuitMode,
    asset_id: BlsScalar,
    root: BlsScalar,
    nullifiers: &[BlsScalar],
    outputs: &[PrivateAssetNote],
    memo_hash: BlsScalar,
) -> PrivateAssetPublicInputs {
    let output_commitments = outputs
        .iter()
        .map(|note| note.commitment)
        .collect::<Vec<_>>();
    standard_inputs_from_commitments(
        mode,
        asset_id,
        root,
        nullifiers,
        &output_commitments,
        memo_hash,
    )
}

fn standard_inputs_from_commitments(
    mode: PrivateAssetCircuitMode,
    asset_id: BlsScalar,
    root: BlsScalar,
    nullifiers: &[BlsScalar],
    output_commitments: &[BlsScalar],
    memo_hash: BlsScalar,
) -> PrivateAssetPublicInputs {
    let chain_id = 2;
    let contract_id = ContractId::from_bytes([7; 32]);
    let intent_hash = intent_hash(PrivateAssetIntent {
        chain_id,
        contract_id,
        asset_id,
        mode,
        root,
        nullifiers,
        output_commitments,
        public_mint_amount: 0,
        public_burn_amount: 0,
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
        output_commitments: output_commitments.to_vec(),
        public_mint_amount: 0,
        public_burn_amount: 0,
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

fn default_subtree_roots(height: usize) -> Vec<BlsScalar> {
    let mut roots = Vec::with_capacity(height + 1);
    roots.push(BlsScalar::hash_to_scalar(b"DRC20Phoenix.empty_leaf.v1"));
    for level in 1..=height {
        let child = roots[level - 1];
        roots.push(hash_pair(child, child));
    }
    roots
}

fn hash_pair(left: BlsScalar, right: BlsScalar) -> BlsScalar {
    let input = vec![
        BlsScalar::hash_to_scalar(b"DRC20Phoenix.merkle_pair.v1"),
        BlsScalar::from(2),
        left,
        right,
    ];
    Hash::digest(Domain::Other, &input)[0]
}

fn proving_context(
    pp: PublicParameters,
    crs_hash: String,
) -> Drc20PhoenixProvingContext<DEV_ARTIFACT_TREE_HEIGHT> {
    let Some(directory) = env::var_os("DRC20_PHOENIX_PROVER_CACHE_DIR") else {
        return Drc20PhoenixProvingContext::without_cache(pp);
    };
    let mut cache = ProverCacheConfig::new(PathBuf::from(directory), crs_hash);
    cache.force_rebuild =
        env::var_os("DRC20_PHOENIX_FORCE_PROVER_CACHE_REBUILD").is_some();
    Drc20PhoenixProvingContext::with_cache(pp, cache)
}

fn public_parameters(crs_arg: Option<&str>) -> (PublicParameters, String) {
    if matches!(crs_arg, Some("--dev")) {
        if env::var_os("DRC20_PHOENIX_ALLOW_DEV_CRS").is_none() {
            panic!(
                "--dev requires DRC20_PHOENIX_ALLOW_DEV_CRS=1 to avoid accidental dev proofs"
            );
        }
        let mut setup_rng = StdRng::seed_from_u64(DEV_SEED);
        return (
            PublicParameters::setup(SETUP_SIZE, &mut setup_rng)
                .expect("setup development public parameters"),
            format!("dev-seed-{DEV_SEED:x}-setup-{SETUP_SIZE}"),
        );
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
    (
        PublicParameters::from_slice(&bytes)
            .expect("decode Dusk CRS public parameters"),
        sha256,
    )
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

fn percentile(values: &[Duration], percentile: usize) -> Duration {
    let mut values = values.to_vec();
    values.sort();
    let index = ((values.len() - 1) * percentile).div_ceil(100);
    values[index]
}

fn hwm_kb() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmHWM:").and_then(|rest| {
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
    })
}

fn arg_usize(args: &[String], name: &str) -> Option<usize> {
    arg_value(args, name).map(|value| value.parse().expect("usize argument"))
}

fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find_map(|window| {
        (window[0] == name).then_some(window[1].as_str())
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
