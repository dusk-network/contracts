// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

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
use sha2::{Digest, Sha256};

const SETUP_SIZE: usize = 1 << 16;
const DEV_SEED: u64 = 0x4452_4332_3050_484f;
const DUSK_CRS_HASH: &str =
    "6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059";
const DUSK_CRS_FILE: &str = "devnet-piecrust.crs";

struct CrsMetadata {
    status: &'static str,
    warning: &'static str,
    source: String,
    sha256: String,
}

fn main() {
    let args = env::args_os().collect::<Vec<_>>();
    let out_dir = args.get(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("standards/drc20-phoenix-circuits/verifier-data")
    });
    let crs_arg = args.get(2).and_then(|value| value.to_str());
    fs::create_dir_all(&out_dir).expect("create verifier-data directory");

    let (pp, crs) = public_parameters(crs_arg);

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

    fs::write(out_dir.join("manifest.json"), manifest(&configs, &crs))
        .expect("write verifier manifest");
}

fn public_parameters(crs_arg: Option<&str>) -> (PublicParameters, CrsMetadata) {
    if matches!(crs_arg, Some("--dev")) {
        if env::var_os("DRC20_PHOENIX_ALLOW_DEV_CRS").is_none() {
            panic!(
                "--dev requires DRC20_PHOENIX_ALLOW_DEV_CRS=1 to avoid accidental dev artifacts"
            );
        }
        let mut rng = StdRng::seed_from_u64(DEV_SEED);
        eprintln!("setting up development public parameters: {SETUP_SIZE}");
        let pp = PublicParameters::setup(SETUP_SIZE, &mut rng)
            .expect("setup development public parameters");
        return (
            pp,
            CrsMetadata {
                status: "development-generated",
                warning: "Verifier data generated with deterministic development public parameters; do not use for production.",
                source: "deterministic-dev-setup".into(),
                sha256: format!("dev-seed:{DEV_SEED}"),
            },
        );
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
    eprintln!("loading Dusk CRS: {} ({sha256})", path.display());
    let pp = PublicParameters::from_slice(&bytes)
        .expect("decode Dusk CRS public parameters");
    (
        pp,
        CrsMetadata {
            status: "dusk-crs-generated",
            warning: "Verifier data generated from the official Dusk CRS; circuit and artifact audit still required before production use.",
            source: path.display().to_string(),
            sha256,
        },
    )
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
    crs: &CrsMetadata,
) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"status\": \"{}\",\n", crs.status));
    out.push_str(&format!("  \"warning\": \"{}\",\n", crs.warning));
    out.push_str("  \"crs\": {\n");
    out.push_str("    \"name\": \"Dusk devnet-piecrust\",\n");
    out.push_str(&format!("    \"source\": \"{}\",\n", crs.source));
    out.push_str(&format!("    \"sha256\": \"{}\"\n", crs.sha256));
    out.push_str("  },\n");
    out.push_str(&format!(
        "  \"transcript_label\": \"{}\",\n",
        String::from_utf8_lossy(TRANSCRIPT_LABEL)
    ));
    out.push_str(&format!(
        "  \"tree_height\": {},\n",
        DEV_ARTIFACT_TREE_HEIGHT
    ));
    out.push_str(&format!("  \"setup_size\": {},\n", SETUP_SIZE));
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
