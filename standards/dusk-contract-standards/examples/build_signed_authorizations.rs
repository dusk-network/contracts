use std::vec::Vec;

use dusk_contract_standards::auth::{
    AuthorizedAction, MoonlightAuthorization, PhoenixSignatureAuthorization,
    SignedAuthorization,
};
use dusk_contract_standards::core::{NonceDomain, Principal};
use dusk_core::abi::ContractId;
use dusk_core::signatures::bls::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
};
use dusk_core::signatures::schnorr::{
    PublicKey as SchnorrPublicKey, SecretKey as SchnorrSecretKey,
};
use dusk_core::JubJubScalar;
use dusk_vm::host_queries;
use rand::rngs::StdRng;
use rand::SeedableRng;

const SIGNED_APPROVE_DOMAIN: NonceDomain = [12u8; 32];
const SIGNED_APPROVE_ACTION: [u8; 32] = [18u8; 32];
const EXAMPLE_EXPIRES_AT: u64 = 1_000;

fn main() {
    let contract = ContractId::from_bytes([42u8; 32]);
    let spender = Principal::Contract(ContractId::from_bytes([7u8; 32]));

    let moonlight_sk = moonlight_secret(11);
    let moonlight_pk = BlsPublicKey::from(&moonlight_sk);
    let moonlight_owner = Principal::moonlight(&moonlight_pk);
    let moonlight_action =
        drc20_signed_approve_action(contract, moonlight_owner, spender, 100, 0);
    let moonlight = SignedAuthorization::Moonlight(MoonlightAuthorization {
        action: moonlight_action,
        public_key: moonlight_pk,
        signature: moonlight_sk.sign(&moonlight_action.message_bytes()),
    });
    moonlight.assert_action(
        contract,
        SIGNED_APPROVE_DOMAIN,
        SIGNED_APPROVE_ACTION,
        drc20_approve_payload_hash(moonlight_owner, spender, 100),
    );

    let mut rng = StdRng::seed_from_u64(99);
    let phoenix_sk = SchnorrSecretKey::from(JubJubScalar::from(12u64));
    let phoenix_pk = SchnorrPublicKey::from(&phoenix_sk);
    let phoenix_owner = Principal::phoenix_public_key(&phoenix_pk);
    let phoenix_action =
        drc20_signed_approve_action(contract, phoenix_owner, spender, 100, 0);
    let phoenix = SignedAuthorization::Phoenix(PhoenixSignatureAuthorization {
        action: phoenix_action,
        public_key: phoenix_pk,
        signature: phoenix_sk.sign(&mut rng, phoenix_action.message_hash()),
        replay_key: None,
    });
    phoenix.assert_action(
        contract,
        SIGNED_APPROVE_DOMAIN,
        SIGNED_APPROVE_ACTION,
        drc20_approve_payload_hash(phoenix_owner, spender, 100),
    );
}

fn drc20_signed_approve_action(
    contract: ContractId,
    owner: Principal,
    spender: Principal,
    amount: u64,
    nonce: u64,
) -> AuthorizedAction {
    AuthorizedAction {
        contract,
        domain: SIGNED_APPROVE_DOMAIN,
        action_id: SIGNED_APPROVE_ACTION,
        nonce,
        expires_at: EXAMPLE_EXPIRES_AT,
        principal: owner,
        payload_hash: drc20_approve_payload_hash(owner, spender, amount),
    }
}

fn drc20_approve_payload_hash(
    owner: Principal,
    spender: Principal,
    amount: u64,
) -> [u8; 32] {
    let mut bytes = Vec::from(&b"drc20.approve"[..]);
    push_principal(&mut bytes, owner);
    push_principal(&mut bytes, spender);
    bytes.extend_from_slice(&amount.to_be_bytes());
    host_queries::keccak256(bytes)
}

fn moonlight_secret(seed: u64) -> BlsSecretKey {
    let mut rng = StdRng::seed_from_u64(seed);
    BlsSecretKey::random(&mut rng)
}

fn push_principal(bytes: &mut Vec<u8>, principal: Principal) {
    let principal = principal.to_bytes();
    bytes.extend_from_slice(&(principal.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&principal);
}
