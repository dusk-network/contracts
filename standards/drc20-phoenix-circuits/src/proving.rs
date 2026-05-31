// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Wallet-side proving context and local prover cache.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use dusk_contract_standards::token::drc20_phoenix::{
    PrivateAssetCircuitMode, PrivateAssetProof, PrivateAssetPublicInputs,
    PrivateAssetVerifierKey,
};
use dusk_plonk::prelude::{Prover, PublicParameters, Verifier};
use sha2::{Digest, Sha256};

use crate::{
    compile, prove_envelope, verifier_constraints, Drc20PhoenixCircuit, Error,
    TRANSCRIPT_LABEL,
};

const CACHE_FORMAT: &str = "drc20-phoenix-prover-cache-v1";

/// Cache configuration for local prover artifacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverCacheConfig {
    /// Directory where prover/verifier artifacts are read and written.
    pub directory: PathBuf,
    /// Expected SHA-256 of the CRS used to compile artifacts.
    pub crs_sha256: String,
    /// Recompile and overwrite cached artifacts.
    pub force_rebuild: bool,
}

impl ProverCacheConfig {
    /// Creates a cache config.
    pub fn new(directory: PathBuf, crs_sha256: String) -> Self {
        Self {
            directory,
            crs_sha256,
            force_rebuild: false,
        }
    }
}

/// Source used for a compiled arity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProverArtifactSource {
    /// The arity was compiled from public parameters.
    Compiled,
    /// The arity was loaded from a validated cache artifact.
    Cache,
}

/// Timing and metadata for one arity load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverArtifactInfo {
    /// Versioned mode/arity key.
    pub key: PrivateAssetVerifierKey,
    /// Merkle tree height.
    pub tree_height: usize,
    /// Artifact source.
    pub source: ProverArtifactSource,
    /// Time spent compiling or loading.
    pub load_time: Duration,
    /// Constraint count.
    pub constraints: usize,
    /// Serialized prover bytes.
    pub prover_bytes: usize,
    /// Serialized verifier bytes.
    pub verifier_bytes: usize,
    /// Prover artifact SHA-256.
    pub prover_sha256: String,
    /// Verifier artifact SHA-256.
    pub verifier_sha256: String,
}

struct CompiledArity {
    prover: Prover,
    verifier: Verifier,
    info: ProverArtifactInfo,
}

/// Persistent proving context for wallet/client flows.
pub struct Drc20PhoenixProvingContext<const HEIGHT: usize> {
    pp: PublicParameters,
    cache: Option<ProverCacheConfig>,
    compiled: BTreeMap<PrivateAssetVerifierKey, CompiledArity>,
}

impl<const HEIGHT: usize> Drc20PhoenixProvingContext<HEIGHT> {
    /// Creates a context that compiles arities lazily and does not cache them.
    pub fn without_cache(pp: PublicParameters) -> Self {
        Self {
            pp,
            cache: None,
            compiled: BTreeMap::new(),
        }
    }

    /// Creates a context that lazily loads or writes local prover artifacts.
    pub fn with_cache(
        pp: PublicParameters,
        cache: ProverCacheConfig,
    ) -> Self {
        Self {
            pp,
            cache: Some(cache),
            compiled: BTreeMap::new(),
        }
    }

    /// Returns metadata for arities already loaded by this context.
    pub fn loaded_artifacts(&self) -> Vec<ProverArtifactInfo> {
        self.compiled
            .values()
            .map(|compiled| compiled.info.clone())
            .collect()
    }

    /// Proves a fixed-arity circuit with the persistent prover/verifier.
    pub fn prove_fixed<
        R: rand::RngCore + rand::CryptoRng,
        const INPUTS: usize,
        const OUTPUTS: usize,
    >(
        &mut self,
        rng: &mut R,
        public_inputs: PrivateAssetPublicInputs,
        circuit: &Drc20PhoenixCircuit<HEIGHT, INPUTS, OUTPUTS>,
    ) -> Result<PrivateAssetProof, Error> {
        let key = PrivateAssetVerifierKey::new(
            public_inputs.mode,
            INPUTS as u8,
            OUTPUTS as u8,
        );
        let compiled = self.compiled(key)?;
        prove_envelope(
            &compiled.prover,
            &compiled.verifier,
            rng,
            public_inputs,
            circuit,
        )
    }

    /// Ensures a supported arity has been loaded and returns its metadata.
    pub fn ensure(
        &mut self,
        key: PrivateAssetVerifierKey,
    ) -> Result<ProverArtifactInfo, Error> {
        Ok(self.compiled(key)?.info.clone())
    }

    fn compiled(
        &mut self,
        key: PrivateAssetVerifierKey,
    ) -> Result<&CompiledArity, Error> {
        if !key.is_supported_v1() {
            return Err(Error::UnsupportedArity);
        }
        if !self.compiled.contains_key(&key) {
            let compiled = self.load_or_compile(key)?;
            self.compiled.insert(key, compiled);
        }
        Ok(self
            .compiled
            .get(&key)
            .expect("compiled arity inserted before lookup"))
    }

    fn load_or_compile(
        &self,
        key: PrivateAssetVerifierKey,
    ) -> Result<CompiledArity, Error> {
        if let Some(cache) = &self.cache {
            if !cache.force_rebuild {
                if let Some(compiled) = self.try_load_cache(key, cache)? {
                    return Ok(compiled);
                }
            }
        }
        self.compile_and_cache(key)
    }

    fn compile_and_cache(
        &self,
        key: PrivateAssetVerifierKey,
    ) -> Result<CompiledArity, Error> {
        let start = Instant::now();
        let (prover, verifier) = compile_for_key::<HEIGHT>(&self.pp, key)?;
        let load_time = start.elapsed();
        let prover_bytes = prover.to_bytes();
        let verifier_bytes = verifier.to_bytes();
        let info = ProverArtifactInfo {
            key,
            tree_height: HEIGHT,
            source: ProverArtifactSource::Compiled,
            load_time,
            constraints: verifier_constraints(&verifier),
            prover_bytes: prover_bytes.len(),
            verifier_bytes: verifier_bytes.len(),
            prover_sha256: sha256_hex(&prover_bytes),
            verifier_sha256: sha256_hex(&verifier_bytes),
        };

        if let Some(cache) = &self.cache {
            write_cache(cache, &info, &prover_bytes, &verifier_bytes)?;
        }

        Ok(CompiledArity {
            prover,
            verifier,
            info,
        })
    }

    fn try_load_cache(
        &self,
        key: PrivateAssetVerifierKey,
        cache: &ProverCacheConfig,
    ) -> Result<Option<CompiledArity>, Error> {
        let metadata_path = metadata_path(&cache.directory, key, HEIGHT);
        let prover_path = prover_path(&cache.directory, key, HEIGHT);
        let verifier_path = verifier_path(&cache.directory, key, HEIGHT);
        if !metadata_path.exists()
            || !prover_path.exists()
            || !verifier_path.exists()
        {
            return Ok(None);
        }

        let start = Instant::now();
        let metadata = fs::read_to_string(&metadata_path)?;
        let prover_bytes = fs::read(&prover_path)?;
        let verifier_bytes = fs::read(&verifier_path)?;
        validate_metadata(
            &metadata,
            key,
            HEIGHT,
            &cache.crs_sha256,
            &prover_bytes,
            &verifier_bytes,
        )?;
        let prover = Prover::try_from_bytes(&prover_bytes)
            .map_err(|err| Error::Cache(format!("invalid prover bytes: {err}")))?;
        let verifier = Verifier::try_from_bytes(&verifier_bytes).map_err(
            |err| Error::Cache(format!("invalid verifier bytes: {err}")),
        )?;
        let info = ProverArtifactInfo {
            key,
            tree_height: HEIGHT,
            source: ProverArtifactSource::Cache,
            load_time: start.elapsed(),
            constraints: verifier_constraints(&verifier),
            prover_bytes: prover_bytes.len(),
            verifier_bytes: verifier_bytes.len(),
            prover_sha256: sha256_hex(&prover_bytes),
            verifier_sha256: sha256_hex(&verifier_bytes),
        };
        Ok(Some(CompiledArity {
            prover,
            verifier,
            info,
        }))
    }
}

fn compile_for_key<const HEIGHT: usize>(
    pp: &PublicParameters,
    key: PrivateAssetVerifierKey,
) -> Result<(Prover, Verifier), Error> {
    match (key.mode, key.input_count, key.output_count) {
        (PrivateAssetCircuitMode::Mint, 0, 1) => {
            compile::<HEIGHT, 0, 1>(pp)
        }
        (PrivateAssetCircuitMode::Mint, 0, 2) => {
            compile::<HEIGHT, 0, 2>(pp)
        }
        (PrivateAssetCircuitMode::Transfer, 1, 2) => {
            compile::<HEIGHT, 1, 2>(pp)
        }
        (PrivateAssetCircuitMode::Transfer, 2, 2) => {
            compile::<HEIGHT, 2, 2>(pp)
        }
        (PrivateAssetCircuitMode::Transfer, 3, 2) => {
            compile::<HEIGHT, 3, 2>(pp)
        }
        (PrivateAssetCircuitMode::Transfer, 4, 2) => {
            compile::<HEIGHT, 4, 2>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 1, 0) => {
            compile::<HEIGHT, 1, 0>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 1, 1) => {
            compile::<HEIGHT, 1, 1>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 1, 2) => {
            compile::<HEIGHT, 1, 2>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 2, 0) => {
            compile::<HEIGHT, 2, 0>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 2, 1) => {
            compile::<HEIGHT, 2, 1>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 2, 2) => {
            compile::<HEIGHT, 2, 2>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 3, 0) => {
            compile::<HEIGHT, 3, 0>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 3, 1) => {
            compile::<HEIGHT, 3, 1>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 3, 2) => {
            compile::<HEIGHT, 3, 2>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 4, 0) => {
            compile::<HEIGHT, 4, 0>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 4, 1) => {
            compile::<HEIGHT, 4, 1>(pp)
        }
        (PrivateAssetCircuitMode::Burn, 4, 2) => {
            compile::<HEIGHT, 4, 2>(pp)
        }
        _ => Err(Error::UnsupportedArity),
    }
}

fn write_cache(
    cache: &ProverCacheConfig,
    info: &ProverArtifactInfo,
    prover_bytes: &[u8],
    verifier_bytes: &[u8],
) -> Result<(), Error> {
    fs::create_dir_all(&cache.directory)?;
    let metadata = metadata(info, &cache.crs_sha256);
    fs::write(
        metadata_path(&cache.directory, info.key, info.tree_height),
        metadata,
    )?;
    fs::write(
        prover_path(&cache.directory, info.key, info.tree_height),
        prover_bytes,
    )?;
    fs::write(
        verifier_path(&cache.directory, info.key, info.tree_height),
        verifier_bytes,
    )?;
    Ok(())
}

fn validate_metadata(
    metadata: &str,
    key: PrivateAssetVerifierKey,
    tree_height: usize,
    crs_sha256: &str,
    prover_bytes: &[u8],
    verifier_bytes: &[u8],
) -> Result<(), Error> {
    let expected = [
        ("format", CACHE_FORMAT.to_string()),
        ("version", key.version.to_string()),
        ("mode", mode_name(key.mode).to_string()),
        ("input_count", key.input_count.to_string()),
        ("output_count", key.output_count.to_string()),
        ("tree_height", tree_height.to_string()),
        ("crs_sha256", crs_sha256.to_string()),
        ("transcript_label_hex", hex(TRANSCRIPT_LABEL)),
        ("prover_sha256", sha256_hex(prover_bytes)),
        ("verifier_sha256", sha256_hex(verifier_bytes)),
    ];

    for (name, expected_value) in expected {
        let actual = metadata_value(metadata, name)
            .ok_or_else(|| Error::Cache(format!("missing {name}")))?;
        if actual != expected_value {
            return Err(Error::Cache(format!(
                "{name} mismatch: expected {expected_value}, got {actual}"
            )));
        }
    }

    Ok(())
}

fn metadata(info: &ProverArtifactInfo, crs_sha256: &str) -> String {
    format!(
        "format={}\nversion={}\nmode={}\ninput_count={}\noutput_count={}\ntree_height={}\ncrs_sha256={}\ntranscript_label_hex={}\nconstraints={}\nprover_bytes={}\nverifier_bytes={}\nprover_sha256={}\nverifier_sha256={}\n",
        CACHE_FORMAT,
        info.key.version,
        mode_name(info.key.mode),
        info.key.input_count,
        info.key.output_count,
        info.tree_height,
        crs_sha256,
        hex(TRANSCRIPT_LABEL),
        info.constraints,
        info.prover_bytes,
        info.verifier_bytes,
        info.prover_sha256,
        info.verifier_sha256,
    )
}

fn metadata_value(metadata: &str, key: &str) -> Option<String> {
    metadata.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name == key).then(|| value.to_string())
    })
}

fn metadata_path(
    directory: &Path,
    key: PrivateAssetVerifierKey,
    height: usize,
) -> PathBuf {
    directory.join(format!("{}.meta", artifact_name(key, height)))
}

fn prover_path(
    directory: &Path,
    key: PrivateAssetVerifierKey,
    height: usize,
) -> PathBuf {
    directory.join(format!("{}.prover", artifact_name(key, height)))
}

fn verifier_path(
    directory: &Path,
    key: PrivateAssetVerifierKey,
    height: usize,
) -> PathBuf {
    directory.join(format!("{}.verifier", artifact_name(key, height)))
}

fn artifact_name(key: PrivateAssetVerifierKey, height: usize) -> String {
    format!(
        "drc20-phoenix-v{}-{}-{}x{}-h{}",
        key.version,
        mode_name(key.mode),
        key.input_count,
        key.output_count,
        height
    )
}

fn mode_name(mode: PrivateAssetCircuitMode) -> &'static str {
    match mode {
        PrivateAssetCircuitMode::Mint => "mint",
        PrivateAssetCircuitMode::Transfer => "transfer",
        PrivateAssetCircuitMode::Burn => "burn",
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_arity_is_rejected_before_compile() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let pp = PublicParameters::setup(1 << 8, &mut rng).unwrap();
        let mut ctx = Drc20PhoenixProvingContext::<2>::without_cache(pp);
        let key = PrivateAssetVerifierKey::new(
            PrivateAssetCircuitMode::Transfer,
            1,
            1,
        );
        assert!(matches!(ctx.ensure(key), Err(Error::UnsupportedArity)));
    }

    #[test]
    fn cache_metadata_rejects_wrong_crs_hash() {
        let key =
            PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Mint, 0, 2);
        let info = ProverArtifactInfo {
            key,
            tree_height: 23,
            source: ProverArtifactSource::Compiled,
            load_time: Duration::from_millis(0),
            constraints: 1,
            prover_bytes: 3,
            verifier_bytes: 3,
            prover_sha256: sha256_hex(b"abc"),
            verifier_sha256: sha256_hex(b"def"),
        };
        let metadata = metadata(&info, "good");
        let err =
            validate_metadata(&metadata, key, 23, "bad", b"abc", b"def")
                .unwrap_err();
        assert!(matches!(err, Error::Cache(_)));
    }

    use rand::SeedableRng;
}
