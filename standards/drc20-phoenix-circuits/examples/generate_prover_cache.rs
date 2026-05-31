// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use drc20_phoenix_circuits::{
    proving::{Drc20PhoenixProvingContext, ProverCacheConfig},
    DEV_ARTIFACT_TREE_HEIGHT,
};
use dusk_contract_standards::token::drc20_phoenix::{
    PrivateAssetCircuitMode, PrivateAssetVerifierKey, V1_SUPPORTED_ARITIES,
};
use dusk_plonk::prelude::PublicParameters;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

const SETUP_SIZE: usize = 1 << 16;
const DEV_SEED: u64 = 0x4452_4332_3050_484f;
const DUSK_CRS_HASH: &str =
    "6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059";
const DUSK_CRS_FILE: &str = "devnet-piecrust.crs";

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let cache_dir = arg_value(&args, "--cache-dir")
        .map(PathBuf::from)
        .unwrap_or_else(default_cache_dir);
    let crs_arg = arg_value(&args, "--crs");
    let only = arg_value(&args, "--only").map(parse_key);
    let force = args.iter().any(|arg| arg == "--force");

    let (pp, crs_hash) = public_parameters(crs_arg);
    let mut cache = ProverCacheConfig::new(cache_dir.clone(), crs_hash);
    cache.force_rebuild = force;
    let mut ctx =
        Drc20PhoenixProvingContext::<DEV_ARTIFACT_TREE_HEIGHT>::with_cache(
            pp, cache,
        );

    let keys = only
        .map(|key| vec![key])
        .unwrap_or_else(|| V1_SUPPORTED_ARITIES.to_vec());

    println!("cache_dir={}", cache_dir.display());
    println!("tree_height={DEV_ARTIFACT_TREE_HEIGHT}");
    for key in keys {
        let info = ctx.ensure(key).expect("generate prover artifact");
        println!(
            "artifact,mode={:?},arity={}x{},source={:?},load_ms={},constraints={},prover_bytes={},prover_sha256={},verifier_sha256={}",
            info.key.mode,
            info.key.input_count,
            info.key.output_count,
            info.source,
            info.load_time.as_millis(),
            info.constraints,
            info.prover_bytes,
            info.prover_sha256,
            info.verifier_sha256
        );
    }
}

fn parse_key(value: &str) -> PrivateAssetVerifierKey {
    let (mode, arity) = value.split_once('-').expect("--only mode-IxO");
    let (inputs, outputs) = arity.split_once('x').expect("--only mode-IxO");
    let mode = match mode {
        "mint" => PrivateAssetCircuitMode::Mint,
        "transfer" => PrivateAssetCircuitMode::Transfer,
        "burn" => PrivateAssetCircuitMode::Burn,
        _ => panic!("unknown mode: {mode}"),
    };
    PrivateAssetVerifierKey::new(
        mode,
        inputs.parse().expect("input count"),
        outputs.parse().expect("output count"),
    )
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

fn default_cache_dir() -> PathBuf {
    PathBuf::from("target").join("drc20-phoenix-prover-cache")
}

fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find_map(|window| {
        (window[0] == name).then_some(window[1].as_str())
    })
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
