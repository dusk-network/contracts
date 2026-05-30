// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::env;
use std::fs;
use std::path::PathBuf;

use drc20_phoenix_circuits::{
    compile, verifier_config, verifier_data, DEV_ARTIFACT_TREE_HEIGHT,
    SUPPORTED_ARITIES, TRANSCRIPT_LABEL,
};
use dusk_contract_standards::token::drc20_phoenix::{
    PrivateAssetCircuitMode, PrivateAssetVerifierConfig,
    PrivateAssetVerifierKey,
};
use dusk_plonk::prelude::PublicParameters;
use rand::rngs::StdRng;
use rand::SeedableRng;

const SETUP_SIZE: usize = 1 << 16;
const DEV_SEED: u64 = 0x4452_4332_3050_484f;

fn main() {
    let out_dir =
        env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
            PathBuf::from("standards/drc20-phoenix-circuits/verifier-data")
        });
    fs::create_dir_all(&out_dir).expect("create verifier-data directory");

    let mut rng = StdRng::seed_from_u64(DEV_SEED);
    eprintln!("setting up development public parameters: {SETUP_SIZE}");
    let pp = PublicParameters::setup(SETUP_SIZE, &mut rng)
        .expect("setup development public parameters");

    let mut configs = Vec::new();
    for arity in SUPPORTED_ARITIES {
        eprintln!(
            "compiling {} {}x{}",
            mode_name(arity.key.mode),
            arity.key.input_count,
            arity.key.output_count
        );
        let config = compile_config(&pp, arity.key);
        let filename = filename(arity.key);
        fs::write(out_dir.join(&filename), &config.verifier_data)
            .expect("write verifier data");
        configs.push((arity.key, arity.public_input_count, filename, config));
    }

    fs::write(out_dir.join("manifest.json"), manifest(&configs))
        .expect("write verifier manifest");
}

fn compile_config(
    pp: &PublicParameters,
    key: PrivateAssetVerifierKey,
) -> PrivateAssetVerifierConfig {
    match (key.mode, key.input_count, key.output_count) {
        (PrivateAssetCircuitMode::Mint, 0, 1) => compile_one::<0, 1>(pp, key),
        (PrivateAssetCircuitMode::Mint, 0, 2) => compile_one::<0, 2>(pp, key),
        (PrivateAssetCircuitMode::Transfer, 1, 2) => {
            compile_one::<1, 2>(pp, key)
        }
        (PrivateAssetCircuitMode::Transfer, 2, 2) => {
            compile_one::<2, 2>(pp, key)
        }
        (PrivateAssetCircuitMode::Transfer, 3, 2) => {
            compile_one::<3, 2>(pp, key)
        }
        (PrivateAssetCircuitMode::Transfer, 4, 2) => {
            compile_one::<4, 2>(pp, key)
        }
        (PrivateAssetCircuitMode::Burn, 1, 0) => compile_one::<1, 0>(pp, key),
        (PrivateAssetCircuitMode::Burn, 1, 1) => compile_one::<1, 1>(pp, key),
        (PrivateAssetCircuitMode::Burn, 1, 2) => compile_one::<1, 2>(pp, key),
        (PrivateAssetCircuitMode::Burn, 2, 0) => compile_one::<2, 0>(pp, key),
        (PrivateAssetCircuitMode::Burn, 2, 1) => compile_one::<2, 1>(pp, key),
        (PrivateAssetCircuitMode::Burn, 2, 2) => compile_one::<2, 2>(pp, key),
        (PrivateAssetCircuitMode::Burn, 3, 0) => compile_one::<3, 0>(pp, key),
        (PrivateAssetCircuitMode::Burn, 3, 1) => compile_one::<3, 1>(pp, key),
        (PrivateAssetCircuitMode::Burn, 3, 2) => compile_one::<3, 2>(pp, key),
        (PrivateAssetCircuitMode::Burn, 4, 0) => compile_one::<4, 0>(pp, key),
        (PrivateAssetCircuitMode::Burn, 4, 1) => compile_one::<4, 1>(pp, key),
        (PrivateAssetCircuitMode::Burn, 4, 2) => compile_one::<4, 2>(pp, key),
        _ => panic!("unsupported arity: {:?}", key),
    }
}

fn compile_one<const INPUTS: usize, const OUTPUTS: usize>(
    pp: &PublicParameters,
    key: PrivateAssetVerifierKey,
) -> PrivateAssetVerifierConfig {
    let (_, verifier) =
        compile::<DEV_ARTIFACT_TREE_HEIGHT, INPUTS, OUTPUTS>(pp)
            .expect("compile circuit");
    verifier_config(key, verifier_data(&verifier))
}

fn filename(key: PrivateAssetVerifierKey) -> String {
    format!(
        "drc20-phoenix-v{}-{}-{}x{}.vd",
        key.version,
        mode_name(key.mode),
        key.input_count,
        key.output_count
    )
}

fn manifest(
    configs: &[(
        PrivateAssetVerifierKey,
        usize,
        String,
        PrivateAssetVerifierConfig,
    )],
) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"status\": \"development-generated\",\n");
    out.push_str(
        "  \"warning\": \"Verifier data generated with deterministic development public parameters; audit and production CRS pinning required before mainnet use.\",\n",
    );
    out.push_str(&format!(
        "  \"transcript_label\": \"{}\",\n",
        String::from_utf8_lossy(TRANSCRIPT_LABEL)
    ));
    out.push_str(&format!(
        "  \"tree_height\": {},\n",
        DEV_ARTIFACT_TREE_HEIGHT
    ));
    out.push_str(&format!("  \"setup_size\": {},\n", SETUP_SIZE));
    out.push_str(&format!("  \"dev_seed\": {},\n", DEV_SEED));
    out.push_str("  \"verifiers\": [\n");
    for (idx, (key, public_input_count, file, config)) in
        configs.iter().enumerate()
    {
        out.push_str("    {\n");
        out.push_str(&format!("      \"version\": {},\n", key.version));
        out.push_str(&format!(
            "      \"mode\": \"{}\",\n",
            mode_name(key.mode)
        ));
        out.push_str(&format!("      \"input_count\": {},\n", key.input_count));
        out.push_str(&format!(
            "      \"output_count\": {},\n",
            key.output_count
        ));
        out.push_str(&format!(
            "      \"public_input_count\": {},\n",
            public_input_count
        ));
        out.push_str(&format!("      \"file\": \"{}\",\n", file));
        out.push_str(&format!(
            "      \"verifier_data_hash\": \"{}\"\n",
            hex(&config.verifier_data_hash.to_bytes())
        ));
        out.push_str("    }");
        if idx + 1 != configs.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

fn mode_name(mode: PrivateAssetCircuitMode) -> &'static str {
    match mode {
        PrivateAssetCircuitMode::Mint => "mint",
        PrivateAssetCircuitMode::Transfer => "transfer",
        PrivateAssetCircuitMode::Burn => "burn",
    }
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
