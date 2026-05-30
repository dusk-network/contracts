// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! DRC20Phoenix private-asset circuits.
//!
//! This crate is the first dedicated circuit package for DRC20Phoenix. It does
//! not reuse the native DUSK Phoenix `TxCircuit`; it defines a custom
//! note/nullifier/value-conservation statement for fixed arities.

use dusk_contract_standards::token::drc20_phoenix::{
    compute_note_commitment, compute_nullifier, compute_value_commitment,
    verifier_data_hash_for_key, PrivateAssetCircuitMode,
    PrivateAssetPublicInputs, PrivateAssetVerifierConfig,
    PrivateAssetVerifierKey,
};
use dusk_plonk::prelude::{
    BlsScalar, Circuit, Compiler, Composer, Constraint, Error as PlonkError,
    Proof, Prover, PublicParameters, Verifier, Witness,
};
#[cfg(test)]
use dusk_poseidon::Hash;
use dusk_poseidon::{Domain, HashGadget};

/// Transcript label for DRC20Phoenix circuits.
pub const TRANSCRIPT_LABEL: &[u8] = b"DRC20Phoenix.private_asset.v1";

/// V1 Merkle height used by the development verifier artifacts.
///
/// Production deployments should pin the audited height and CRS in their
/// verifier manifest. The small default keeps native proof tests tractable.
pub const DEV_ARTIFACT_TREE_HEIGHT: usize = 2;

/// Metadata for one supported fixed-arity circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupportedArity {
    /// Verifier key.
    pub key: PrivateAssetVerifierKey,
    /// Flattened public input count.
    pub public_input_count: usize,
}

/// V1 supported arities for verifier-data generation.
pub const SUPPORTED_ARITIES: &[SupportedArity] = &[
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Mint, 0, 1),
        public_input_count: public_input_count(0, 1),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Mint, 0, 2),
        public_input_count: public_input_count(0, 2),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(
            PrivateAssetCircuitMode::Transfer,
            1,
            2,
        ),
        public_input_count: public_input_count(1, 2),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(
            PrivateAssetCircuitMode::Transfer,
            2,
            2,
        ),
        public_input_count: public_input_count(2, 2),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(
            PrivateAssetCircuitMode::Transfer,
            3,
            2,
        ),
        public_input_count: public_input_count(3, 2),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(
            PrivateAssetCircuitMode::Transfer,
            4,
            2,
        ),
        public_input_count: public_input_count(4, 2),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 1, 0),
        public_input_count: public_input_count(1, 0),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 1, 1),
        public_input_count: public_input_count(1, 1),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 1, 2),
        public_input_count: public_input_count(1, 2),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 2, 0),
        public_input_count: public_input_count(2, 0),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 2, 1),
        public_input_count: public_input_count(2, 1),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 2, 2),
        public_input_count: public_input_count(2, 2),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 3, 0),
        public_input_count: public_input_count(3, 0),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 3, 1),
        public_input_count: public_input_count(3, 1),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 3, 2),
        public_input_count: public_input_count(3, 2),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 4, 0),
        public_input_count: public_input_count(4, 0),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 4, 1),
        public_input_count: public_input_count(4, 1),
    },
    SupportedArity {
        key: PrivateAssetVerifierKey::new(PrivateAssetCircuitMode::Burn, 4, 2),
        public_input_count: public_input_count(4, 2),
    },
];

const fn public_input_count(inputs: usize, outputs: usize) -> usize {
    14 + inputs + outputs
}

/// Error returned by circuit helpers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The supplied standards public inputs do not match this fixed arity.
    #[error("public input arity mismatch")]
    Arity,
    /// The supplied public input mode is not compatible with this circuit.
    #[error("public input mode mismatch")]
    Mode,
    /// Public mint/burn amount exceeds the v1 circuit's u64 amount range.
    #[error("public amount exceeds u64")]
    Amount,
    /// PLONK error.
    #[error("plonk: {0}")]
    Plonk(#[from] PlonkError),
}

/// Fixed public inputs consumed by a DRC20Phoenix circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedPublicInputs<const INPUTS: usize, const OUTPUTS: usize> {
    /// Flattened public inputs in the exact standards order.
    pub scalars: Vec<BlsScalar>,
    /// Asset id public input.
    pub asset_id: BlsScalar,
    /// Mode public input.
    pub mode: PrivateAssetCircuitMode,
    /// Root public input.
    pub root: BlsScalar,
    /// Nullifier public inputs.
    pub nullifiers: [BlsScalar; INPUTS],
    /// Output note commitment public inputs.
    pub output_commitments: [BlsScalar; OUTPUTS],
    /// Public mint amount, v1 u64 range.
    pub public_mint_amount: u64,
    /// Public burn amount, v1 u64 range.
    pub public_burn_amount: u64,
}

impl<const INPUTS: usize, const OUTPUTS: usize>
    FixedPublicInputs<INPUTS, OUTPUTS>
{
    /// Converts standards public inputs into fixed-arity circuit inputs.
    pub fn from_standard(
        inputs: &PrivateAssetPublicInputs,
    ) -> Result<Self, Error> {
        if inputs.nullifiers.len() != INPUTS
            || inputs.output_commitments.len() != OUTPUTS
        {
            return Err(Error::Arity);
        }
        let public_mint_amount = u64::try_from(inputs.public_mint_amount)
            .map_err(|_| Error::Amount)?;
        let public_burn_amount = u64::try_from(inputs.public_burn_amount)
            .map_err(|_| Error::Amount)?;

        Ok(Self {
            scalars: inputs.to_scalars(),
            asset_id: inputs.asset_id,
            mode: inputs.mode,
            root: inputs.root,
            nullifiers: inputs
                .nullifiers
                .clone()
                .try_into()
                .map_err(|_| Error::Arity)?,
            output_commitments: inputs
                .output_commitments
                .clone()
                .try_into()
                .map_err(|_| Error::Arity)?,
            public_mint_amount,
            public_burn_amount,
        })
    }
}

impl<const INPUTS: usize, const OUTPUTS: usize> Default
    for FixedPublicInputs<INPUTS, OUTPUTS>
{
    fn default() -> Self {
        Self {
            scalars: vec![BlsScalar::zero(); 14 + INPUTS + OUTPUTS],
            asset_id: BlsScalar::zero(),
            mode: PrivateAssetCircuitMode::Transfer,
            root: BlsScalar::zero(),
            nullifiers: [BlsScalar::zero(); INPUTS],
            output_commitments: [BlsScalar::zero(); OUTPUTS],
            public_mint_amount: 0,
            public_burn_amount: 0,
        }
    }
}

/// Witness data for one input note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputNoteWitness<const HEIGHT: usize> {
    /// Private spend secret. The owner commitment is `H(secret)`.
    pub spend_secret: BlsScalar,
    /// Note value.
    pub value: u64,
    /// Value blinder.
    pub value_blinder: BlsScalar,
    /// Note nonce.
    pub nonce: BlsScalar,
    /// Hash of the encrypted payload.
    pub payload_hash: BlsScalar,
    /// Merkle path siblings.
    pub path: [BlsScalar; HEIGHT],
    /// Merkle path direction bits. `1` means sibling is left.
    pub path_is_left: [BlsScalar; HEIGHT],
}

impl<const HEIGHT: usize> Default for InputNoteWitness<HEIGHT> {
    fn default() -> Self {
        Self {
            spend_secret: BlsScalar::zero(),
            value: 0,
            value_blinder: BlsScalar::zero(),
            nonce: BlsScalar::zero(),
            payload_hash: BlsScalar::zero(),
            path: [BlsScalar::zero(); HEIGHT],
            path_is_left: [BlsScalar::zero(); HEIGHT],
        }
    }
}

/// Witness data for one output note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputNoteWitness {
    /// Recipient owner commitment.
    pub owner_commitment: BlsScalar,
    /// Note value.
    pub value: u64,
    /// Value blinder.
    pub value_blinder: BlsScalar,
    /// Note nonce.
    pub nonce: BlsScalar,
    /// Hash of the encrypted payload.
    pub payload_hash: BlsScalar,
}

impl Default for OutputNoteWitness {
    fn default() -> Self {
        Self {
            owner_commitment: BlsScalar::zero(),
            value: 0,
            value_blinder: BlsScalar::zero(),
            nonce: BlsScalar::zero(),
            payload_hash: BlsScalar::zero(),
        }
    }
}

/// Fixed-arity DRC20Phoenix private-asset circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drc20PhoenixCircuit<
    const HEIGHT: usize,
    const INPUTS: usize,
    const OUTPUTS: usize,
> {
    /// Fixed public input set.
    pub public: FixedPublicInputs<INPUTS, OUTPUTS>,
    /// Input note witnesses.
    pub inputs: [InputNoteWitness<HEIGHT>; INPUTS],
    /// Output note witnesses.
    pub outputs: [OutputNoteWitness; OUTPUTS],
}

impl<const HEIGHT: usize, const INPUTS: usize, const OUTPUTS: usize> Default
    for Drc20PhoenixCircuit<HEIGHT, INPUTS, OUTPUTS>
{
    fn default() -> Self {
        Self {
            public: FixedPublicInputs::default(),
            inputs: [InputNoteWitness::default(); INPUTS],
            outputs: [OutputNoteWitness::default(); OUTPUTS],
        }
    }
}

impl<const HEIGHT: usize, const INPUTS: usize, const OUTPUTS: usize> Circuit
    for Drc20PhoenixCircuit<HEIGHT, INPUTS, OUTPUTS>
{
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let publics = self
            .public
            .scalars
            .iter()
            .map(|scalar| composer.append_public(*scalar))
            .collect::<Vec<_>>();
        let asset_id = publics[4];
        let root = publics[6];
        let nullifier_offset = 8;
        let output_offset = 9 + INPUTS;
        let mint_hi = publics[9 + INPUTS + OUTPUTS];
        let public_mint = publics[10 + INPUTS + OUTPUTS];
        let burn_hi = publics[11 + INPUTS + OUTPUTS];
        let public_burn = publics[12 + INPUTS + OUTPUTS];
        composer.assert_equal_constant(mint_hi, BlsScalar::zero(), None);
        composer.assert_equal_constant(burn_hi, BlsScalar::zero(), None);

        let mut input_sum = public_mint;
        for (idx, input) in self.inputs.iter().enumerate() {
            let spend_secret = composer.append_witness(input.spend_secret);
            let value = composer.append_witness(input.value);
            composer.component_range::<32>(value);
            input_sum = add(composer, input_sum, value);

            let value_blinder = composer.append_witness(input.value_blinder);
            let nonce = composer.append_witness(input.nonce);
            let payload_hash = composer.append_witness(input.payload_hash);

            let owner_commitment = hash_gadget(
                composer,
                b"DRC20Phoenix.owner_commitment.v1",
                &[spend_secret],
            );
            let value_commitment = hash_gadget(
                composer,
                b"DRC20Phoenix.value_commitment.v1",
                &[asset_id, value, value_blinder],
            );
            let note_commitment = hash_gadget(
                composer,
                b"DRC20Phoenix.note.v1",
                &[
                    asset_id,
                    owner_commitment,
                    value_commitment,
                    nonce,
                    payload_hash,
                ],
            );

            let nullifier = hash_gadget(
                composer,
                b"DRC20Phoenix.nullifier.v1",
                &[asset_id, spend_secret, note_commitment],
            );
            let expected_nullifier = publics[nullifier_offset + idx];
            composer.assert_equal(nullifier, expected_nullifier);

            let computed_root =
                merkle_root_gadget(composer, note_commitment, input);
            composer.assert_equal(computed_root, root);
        }

        let mut output_sum = public_burn;
        for (idx, output) in self.outputs.iter().enumerate() {
            let owner_commitment =
                composer.append_witness(output.owner_commitment);
            let value = composer.append_witness(output.value);
            composer.component_range::<32>(value);
            output_sum = add(composer, output_sum, value);
            let value_blinder = composer.append_witness(output.value_blinder);
            let nonce = composer.append_witness(output.nonce);
            let payload_hash = composer.append_witness(output.payload_hash);

            let value_commitment = hash_gadget(
                composer,
                b"DRC20Phoenix.value_commitment.v1",
                &[asset_id, value, value_blinder],
            );
            let note_commitment = hash_gadget(
                composer,
                b"DRC20Phoenix.note.v1",
                &[
                    asset_id,
                    owner_commitment,
                    value_commitment,
                    nonce,
                    payload_hash,
                ],
            );
            let expected_commitment = publics[output_offset + idx];
            composer.assert_equal(note_commitment, expected_commitment);
        }

        composer.assert_equal(input_sum, output_sum);
        Ok(())
    }
}

/// Compiles a fixed-arity DRC20Phoenix circuit.
pub fn compile<
    const HEIGHT: usize,
    const INPUTS: usize,
    const OUTPUTS: usize,
>(
    pp: &PublicParameters,
) -> Result<(Prover, Verifier), Error> {
    Compiler::compile::<Drc20PhoenixCircuit<HEIGHT, INPUTS, OUTPUTS>>(
        pp,
        TRANSCRIPT_LABEL,
    )
    .map_err(Error::from)
}

/// Proves a fixed-arity DRC20Phoenix circuit.
pub fn prove<
    R: rand::RngCore + rand::CryptoRng,
    const HEIGHT: usize,
    const INPUTS: usize,
    const OUTPUTS: usize,
>(
    prover: &Prover,
    rng: &mut R,
    circuit: &Drc20PhoenixCircuit<HEIGHT, INPUTS, OUTPUTS>,
) -> Result<(Proof, Vec<BlsScalar>), Error> {
    prover.prove(rng, circuit).map_err(Error::from)
}

/// Returns verifier data bytes suitable for contract initialization.
pub fn verifier_data(verifier: &Verifier) -> Vec<u8> {
    verifier.to_bytes()
}

/// Builds a standards verifier config from verifier bytes.
pub fn verifier_config(
    key: PrivateAssetVerifierKey,
    verifier_data: Vec<u8>,
) -> PrivateAssetVerifierConfig {
    PrivateAssetVerifierConfig {
        key,
        verifier_data_hash: verifier_data_hash_for_key(key, &verifier_data),
        verifier_data,
    }
}

/// Native note commitment helper matching the circuit.
pub fn note_commitment(
    asset_id: BlsScalar,
    owner_commitment: BlsScalar,
    value: u64,
    value_blinder: BlsScalar,
    nonce: BlsScalar,
    payload_hash: BlsScalar,
) -> BlsScalar {
    let value_commitment =
        compute_value_commitment(asset_id, value, value_blinder);
    compute_note_commitment(
        asset_id,
        owner_commitment,
        value_commitment,
        nonce,
        payload_hash,
    )
}

/// Native nullifier helper matching the circuit.
pub fn nullifier(
    asset_id: BlsScalar,
    spend_secret: BlsScalar,
    note_commitment: BlsScalar,
) -> BlsScalar {
    compute_nullifier(asset_id, spend_secret, note_commitment)
}

fn add(composer: &mut Composer, lhs: Witness, rhs: Witness) -> Witness {
    composer.gate_add(Constraint::new().left(1).a(lhs).right(1).b(rhs))
}

fn hash_gadget(
    composer: &mut Composer,
    domain: &[u8],
    inputs: &[Witness],
) -> Witness {
    let domain = constant(composer, domain_scalar(domain));
    let len = constant(composer, BlsScalar::from(inputs.len() as u64));
    let mut all = Vec::with_capacity(inputs.len() + 2);
    all.push(domain);
    all.push(len);
    all.extend_from_slice(inputs);
    HashGadget::digest(composer, Domain::Other, &all)[0]
}

fn merkle_root_gadget<const HEIGHT: usize>(
    composer: &mut Composer,
    leaf: Witness,
    input: &InputNoteWitness<HEIGHT>,
) -> Witness {
    let mut current = leaf;
    for (sibling, is_left) in input.path.iter().zip(input.path_is_left.iter()) {
        let sibling = composer.append_witness(*sibling);
        let is_left = composer.append_witness(*is_left);
        composer.component_boolean(is_left);
        let left = composer.component_select(is_left, sibling, current);
        let right = composer.component_select(is_left, current, sibling);
        current = hash_gadget(
            composer,
            b"DRC20Phoenix.merkle_pair.v1",
            &[left, right],
        );
    }
    current
}

fn constant(composer: &mut Composer, value: BlsScalar) -> Witness {
    let witness = composer.append_witness(value);
    composer.assert_equal_constant(witness, value, None);
    witness
}

fn domain_scalar(domain: &[u8]) -> BlsScalar {
    BlsScalar::hash_to_scalar(domain)
}

#[cfg(test)]
fn poseidon(domain: &[u8], scalars: &[BlsScalar]) -> BlsScalar {
    let mut input = Vec::with_capacity(scalars.len() + 2);
    input.push(domain_scalar(domain));
    input.push(BlsScalar::from(scalars.len() as u64));
    input.extend_from_slice(scalars);
    Hash::digest(Domain::Other, &input)[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_contract_standards::token::drc20_phoenix::{
        compute_owner_commitment, intent_hash, PrivateAssetIntent,
        PrivateAssetPublicInputs, DRC20_PHOENIX_VERSION, V1_SUPPORTED_ARITIES,
    };
    use dusk_core::abi::ContractId;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const HEIGHT: usize = 2;

    #[test]
    fn native_helpers_match_standards_helpers() {
        let asset_id = BlsScalar::from(9);
        let spend_secret = BlsScalar::from(10);
        let owner = compute_owner_commitment(spend_secret);
        let commitment = note_commitment(
            asset_id,
            owner,
            42,
            BlsScalar::from(11),
            BlsScalar::from(12),
            BlsScalar::from(13),
        );
        assert_eq!(
            commitment,
            compute_note_commitment(
                asset_id,
                owner,
                compute_value_commitment(asset_id, 42, BlsScalar::from(11)),
                BlsScalar::from(12),
                BlsScalar::from(13),
            )
        );
        assert_eq!(
            nullifier(asset_id, spend_secret, commitment),
            compute_nullifier(asset_id, spend_secret, commitment)
        );
    }

    #[test]
    fn fixed_public_inputs_preserve_standards_order() {
        let asset_id = BlsScalar::from(9);
        let output = BlsScalar::from(33);
        let inputs = standard_inputs(
            PrivateAssetCircuitMode::Mint,
            asset_id,
            BlsScalar::from(1),
            Vec::new(),
            vec![output],
            42,
            0,
        );
        let fixed = FixedPublicInputs::<0, 1>::from_standard(&inputs).unwrap();
        assert_eq!(fixed.scalars, inputs.to_scalars());
        assert_eq!(fixed.output_commitments, [output]);
        assert_eq!(fixed.public_mint_amount, 42);
    }

    #[test]
    fn supported_arities_match_standards_manifest() {
        let circuit_keys = SUPPORTED_ARITIES
            .iter()
            .map(|arity| arity.key)
            .collect::<Vec<_>>();
        assert_eq!(circuit_keys, V1_SUPPORTED_ARITIES);
        for arity in SUPPORTED_ARITIES {
            assert_eq!(
                arity.public_input_count,
                14 + arity.key.input_count as usize
                    + arity.key.output_count as usize
            );
        }
    }

    #[test]
    fn proves_and_verifies_mint_circuit() {
        let asset_id = BlsScalar::from(9);
        let owner = BlsScalar::from(100);
        let value_blinder = BlsScalar::from(11);
        let nonce = BlsScalar::from(12);
        let payload_hash = BlsScalar::from(13);
        let output = note_commitment(
            asset_id,
            owner,
            42,
            value_blinder,
            nonce,
            payload_hash,
        );
        let public =
            FixedPublicInputs::<0, 1>::from_standard(&standard_inputs(
                PrivateAssetCircuitMode::Mint,
                asset_id,
                BlsScalar::from(1),
                Vec::new(),
                vec![output],
                42,
                0,
            ))
            .unwrap();
        let circuit = Drc20PhoenixCircuit::<HEIGHT, 0, 1> {
            public: public.clone(),
            inputs: [],
            outputs: [OutputNoteWitness {
                owner_commitment: owner,
                value: 42,
                value_blinder,
                nonce,
                payload_hash,
            }],
        };

        let mut rng = StdRng::seed_from_u64(7);
        let pp = PublicParameters::setup(1 << 15, &mut rng).unwrap();
        let (prover, verifier) = compile::<HEIGHT, 0, 1>(&pp).unwrap();
        let (proof, public_inputs) =
            prove(&prover, &mut rng, &circuit).unwrap();
        assert_eq!(public_inputs, public.scalars);
        verifier.verify(&proof, &public_inputs).unwrap();
        assert!(!verifier_data(&verifier).is_empty());
    }

    #[test]
    fn proves_and_rejects_bad_transfer_public_inputs() {
        let asset_id = BlsScalar::from(9);
        let spend_secret = BlsScalar::from(10);
        let owner = compute_owner_commitment(spend_secret);
        let value_blinder = BlsScalar::from(11);
        let nonce = BlsScalar::from(12);
        let payload_hash = BlsScalar::from(13);
        let leaf = note_commitment(
            asset_id,
            owner,
            42,
            value_blinder,
            nonce,
            payload_hash,
        );
        let sibling_0 = BlsScalar::from(20);
        let sibling_1 = BlsScalar::from(21);
        let root_0 =
            poseidon(b"DRC20Phoenix.merkle_pair.v1", &[leaf, sibling_0]);
        let root =
            poseidon(b"DRC20Phoenix.merkle_pair.v1", &[sibling_1, root_0]);
        let nf = nullifier(asset_id, spend_secret, leaf);

        let out_owner = BlsScalar::from(101);
        let output = note_commitment(
            asset_id,
            out_owner,
            42,
            BlsScalar::from(31),
            BlsScalar::from(32),
            BlsScalar::from(33),
        );
        let public =
            FixedPublicInputs::<1, 1>::from_standard(&standard_inputs(
                PrivateAssetCircuitMode::Transfer,
                asset_id,
                root,
                vec![nf],
                vec![output],
                0,
                0,
            ))
            .unwrap();
        let circuit = Drc20PhoenixCircuit::<HEIGHT, 1, 1> {
            public: public.clone(),
            inputs: [InputNoteWitness {
                spend_secret,
                value: 42,
                value_blinder,
                nonce,
                payload_hash,
                path: [sibling_0, sibling_1],
                path_is_left: [BlsScalar::zero(), BlsScalar::one()],
            }],
            outputs: [OutputNoteWitness {
                owner_commitment: out_owner,
                value: 42,
                value_blinder: BlsScalar::from(31),
                nonce: BlsScalar::from(32),
                payload_hash: BlsScalar::from(33),
            }],
        };

        let mut rng = StdRng::seed_from_u64(8);
        let pp = PublicParameters::setup(1 << 16, &mut rng).unwrap();
        let (prover, verifier) = compile::<HEIGHT, 1, 1>(&pp).unwrap();
        let (proof, public_inputs) =
            prove(&prover, &mut rng, &circuit).unwrap();
        verifier.verify(&proof, &public_inputs).unwrap();

        let mut bad_public_inputs = public_inputs;
        bad_public_inputs[9] = BlsScalar::from(999);
        assert!(verifier.verify(&proof, &bad_public_inputs).is_err());
    }

    fn standard_inputs(
        mode: PrivateAssetCircuitMode,
        asset_id: BlsScalar,
        root: BlsScalar,
        nullifiers: Vec<BlsScalar>,
        output_commitments: Vec<BlsScalar>,
        public_mint_amount: u128,
        public_burn_amount: u128,
    ) -> PrivateAssetPublicInputs {
        let contract_id = ContractId::from_bytes([7; 32]);
        let memo_hash = BlsScalar::from(99);
        let intent = intent_hash(PrivateAssetIntent {
            chain_id: 7,
            contract_id,
            asset_id,
            mode,
            root,
            nullifiers: &nullifiers,
            output_commitments: &output_commitments,
            public_mint_amount,
            public_burn_amount,
            memo_hash,
        });
        PrivateAssetPublicInputs {
            version: DRC20_PHOENIX_VERSION,
            chain_id: 7,
            contract_id,
            asset_id,
            mode,
            root,
            nullifiers,
            output_commitments,
            public_mint_amount,
            public_burn_amount,
            intent_hash: intent,
        }
    }
}
