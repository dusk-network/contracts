// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::fs;
use std::path::{Path, PathBuf};

use bytecheck::CheckBytes;
use dusk_contract_standards::auth::{
    AuthorizedAction, PhoenixSignatureAuthorization, SignedAuthorization,
};
use dusk_contract_standards::core::{NonceDomain, NonceQuery, Principal};
use dusk_core::abi::{ContractId, StandardBufSerializer};
use dusk_core::signatures::schnorr::{
    PublicKey as SchnorrPublicKey, SecretKey as SchnorrSecretKey,
};
use dusk_core::JubJubScalar;
use dusk_vm::host_queries;
use dusk_vm::{ContractData, Session, VM};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rkyv::validation::validators::DefaultValidator;
use rkyv::{Archive, Deserialize, Infallible, Serialize};

const CHAIN_ID: u8 = 0xD5;
const GAS_LIMIT: u64 = 1_000_000_000;
const OWNER_BYTES: [u8; 32] = [1u8; 32];

const PROXY_ADMIN_DOMAIN: NonceDomain = [31u8; 32];
const SET_VALUE_ACTION: [u8; 32] = [32u8; 32];
const PREPARE_UPGRADE_ACTION: [u8; 32] = [33u8; 32];
const ACTIVATE_UPGRADE_ACTION: [u8; 32] = [34u8; 32];
const CANCEL_UPGRADE_ACTION: [u8; 32] = [35u8; 32];

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[archive_attr(derive(CheckBytes))]
struct ProxyCounterInit {
    admin: Principal,
    implementation: ContractId,
    upgrade_delay: u64,
    rollback_window: u64,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct ProxySetValue {
    value: u64,
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct PrepareUpgrade {
    implementation: ContractId,
    migrate_data: Vec<u8>,
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct AdminCall {
    authorization: Option<SignedAuthorization>,
}

#[test]
#[ignore = "requires release proxy reference Wasm; run after the wasm build"]
fn proxy_reference_contract_enforces_signed_admin_paths() {
    let _hard_fork_guard =
        host_queries::set_hard_fork(host_queries::HardFork::Aegis);
    let vm = VM::ephemeral().expect("create ephemeral VM");
    let mut session = vm.genesis_session(CHAIN_ID);

    let admin = phoenix_principal(7);
    let implementation_a = ContractId::from_bytes([40u8; 32]);
    let implementation_b = ContractId::from_bytes([41u8; 32]);
    let contract = deploy(
        &mut session,
        "proxy_counter.wasm",
        [32u8; 32],
        &ProxyCounterInit {
            admin,
            implementation: implementation_a,
            upgrade_delay: 0,
            rollback_window: 0,
        },
    );

    assert_eq!(
        query_contract_id(&mut session, contract, "implementation", &()),
        implementation_a
    );
    assert_eq!(query_u64(&mut session, contract, "value", &()), 0);

    let mut rng = StdRng::seed_from_u64(3333);
    let admin_sk = SchnorrSecretKey::from(JubJubScalar::from(7u64));
    let admin_pk = SchnorrPublicKey::from(&admin_sk);
    assert_eq!(admin, Principal::phoenix_public_key(&admin_pk));

    assert!(session
        .call::<_, ()>(
            contract,
            "set_value",
            &ProxySetValue {
                value: 7,
                authorization: None,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_eq!(query_u64(&mut session, contract, "value", &()), 0);
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 0);

    let set_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            PROXY_ADMIN_DOMAIN,
            SET_VALUE_ACTION,
            0,
            value_payload_hash(7),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "set_value",
            &ProxySetValue {
                value: 7,
                authorization: Some(set_auth.clone()),
            },
            GAS_LIMIT,
        )
        .expect("set proxy value by signed admin");
    assert_eq!(query_u64(&mut session, contract, "value", &()), 7);
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 1);

    assert!(session
        .call::<_, ()>(
            contract,
            "set_value",
            &ProxySetValue {
                value: 7,
                authorization: Some(set_auth),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_eq!(query_u64(&mut session, contract, "value", &()), 7);
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 1);

    let wrong_payload = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            PROXY_ADMIN_DOMAIN,
            SET_VALUE_ACTION,
            1,
            value_payload_hash(8),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value",
            &ProxySetValue {
                value: 9,
                authorization: Some(wrong_payload),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_eq!(query_u64(&mut session, contract, "value", &()), 7);
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 1);

    let wrong_contract = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            ContractId::from_bytes([99u8; 32]),
            admin,
            PROXY_ADMIN_DOMAIN,
            SET_VALUE_ACTION,
            1,
            value_payload_hash(8),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value",
            &ProxySetValue {
                value: 8,
                authorization: Some(wrong_contract),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_eq!(query_u64(&mut session, contract, "value", &()), 7);
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 1);

    let wrong_action = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            PROXY_ADMIN_DOMAIN,
            [0xaf; 32],
            1,
            value_payload_hash(8),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value",
            &ProxySetValue {
                value: 8,
                authorization: Some(wrong_action),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_eq!(query_u64(&mut session, contract, "value", &()), 7);
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 1);

    let prepare_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            PROXY_ADMIN_DOMAIN,
            PREPARE_UPGRADE_ACTION,
            1,
            prepare_payload_hash(implementation_b, &[1, 2, 3]),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "prepare_upgrade",
            &PrepareUpgrade {
                implementation: implementation_b,
                migrate_data: vec![1, 2, 3],
                authorization: Some(prepare_auth),
            },
            GAS_LIMIT,
        )
        .expect("prepare upgrade by signed admin");
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 2);
    assert_eq!(
        query_contract_id(&mut session, contract, "implementation", &()),
        implementation_a
    );

    let cancel_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            PROXY_ADMIN_DOMAIN,
            CANCEL_UPGRADE_ACTION,
            2,
            empty_payload_hash(b"proxy.cancel_upgrade"),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "cancel_pending_upgrade",
            &AdminCall {
                authorization: Some(cancel_auth),
            },
            GAS_LIMIT,
        )
        .expect("cancel pending upgrade by signed admin");
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 3);

    let prepare_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            PROXY_ADMIN_DOMAIN,
            PREPARE_UPGRADE_ACTION,
            3,
            prepare_payload_hash(implementation_b, &[4]),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "prepare_upgrade",
            &PrepareUpgrade {
                implementation: implementation_b,
                migrate_data: vec![4],
                authorization: Some(prepare_auth),
            },
            GAS_LIMIT,
        )
        .expect("prepare second upgrade by signed admin");
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 4);

    let migration: Vec<u8> = session
        .call(
            contract,
            "activate_upgrade",
            &AdminCall {
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(
                        &mut rng,
                        &admin_sk,
                        admin_pk,
                        authorized_action(
                            contract,
                            admin,
                            PROXY_ADMIN_DOMAIN,
                            ACTIVATE_UPGRADE_ACTION,
                            4,
                            empty_payload_hash(b"proxy.activate_upgrade"),
                        ),
                    ),
                )),
            },
            GAS_LIMIT,
        )
        .expect("activate upgrade by signed admin")
        .data;
    assert_eq!(migration, vec![4]);
    assert_contract_nonce(&mut session, contract, admin, PROXY_ADMIN_DOMAIN, 5);
    assert_eq!(
        query_contract_id(&mut session, contract, "implementation", &()),
        implementation_b
    );
}

fn authorized_action(
    contract: ContractId,
    principal: Principal,
    domain: NonceDomain,
    action_id: [u8; 32],
    nonce: u64,
    payload_hash: [u8; 32],
) -> AuthorizedAction {
    AuthorizedAction {
        chain_id: CHAIN_ID,
        contract,
        domain,
        action_id,
        nonce,
        expires_at: 0,
        principal,
        payload_hash,
    }
}

fn phoenix_auth(
    rng: &mut StdRng,
    secret_key: &SchnorrSecretKey,
    public_key: SchnorrPublicKey,
    action: AuthorizedAction,
) -> PhoenixSignatureAuthorization {
    PhoenixSignatureAuthorization {
        action,
        public_key,
        signature: secret_key.sign(rng, action.message_hash()),
        replay_key: None,
    }
}

fn assert_contract_nonce(
    session: &mut Session,
    contract: ContractId,
    principal: Principal,
    domain: NonceDomain,
    nonce: u64,
) {
    let actual_nonce = query_u64(
        session,
        contract,
        "nonce",
        &NonceQuery { principal, domain },
    );
    assert_eq!(actual_nonce, nonce);
}

fn value_payload_hash(value: u64) -> [u8; 32] {
    let mut bytes = Vec::from(&b"proxy.value"[..]);
    bytes.extend_from_slice(&value.to_be_bytes());
    host_queries::keccak256(bytes)
}

fn prepare_payload_hash(
    implementation: ContractId,
    migrate_data: &[u8],
) -> [u8; 32] {
    let mut bytes = Vec::from(&b"proxy.prepare"[..]);
    bytes.extend_from_slice(&implementation.to_bytes());
    bytes.extend_from_slice(&(migrate_data.len() as u32).to_be_bytes());
    bytes.extend_from_slice(migrate_data);
    host_queries::keccak256(bytes)
}

fn empty_payload_hash(tag: &[u8]) -> [u8; 32] {
    host_queries::keccak256(Vec::from(tag))
}

fn phoenix_principal(seed: u64) -> Principal {
    let secret = SchnorrSecretKey::from(JubJubScalar::from(seed));
    let public = SchnorrPublicKey::from(&secret);
    Principal::phoenix_public_key(&public)
}

fn query_u64<A>(
    session: &mut Session,
    contract: ContractId,
    method: &str,
    args: &A,
) -> u64
where
    A: for<'a> Serialize<StandardBufSerializer<'a>>,
    A::Archived: for<'a> CheckBytes<DefaultValidator<'a>>,
{
    query(session, contract, method, args)
}

fn query_contract_id<A>(
    session: &mut Session,
    contract: ContractId,
    method: &str,
    args: &A,
) -> ContractId
where
    A: for<'a> Serialize<StandardBufSerializer<'a>>,
    A::Archived: for<'a> CheckBytes<DefaultValidator<'a>>,
{
    query(session, contract, method, args)
}

fn query<R, A>(
    session: &mut Session,
    contract: ContractId,
    method: &str,
    args: &A,
) -> R
where
    A: for<'a> Serialize<StandardBufSerializer<'a>>,
    A::Archived: for<'a> CheckBytes<DefaultValidator<'a>>,
    R: Archive,
    R::Archived:
        Deserialize<R, Infallible> + for<'a> CheckBytes<DefaultValidator<'a>>,
{
    session
        .call(contract, method, args, GAS_LIMIT)
        .unwrap_or_else(|err| panic!("query {method}: {err}"))
        .data
}

fn deploy<A>(
    session: &mut Session,
    wasm_name: &str,
    contract_id: [u8; 32],
    init: &A,
) -> ContractId
where
    A: for<'a> Serialize<StandardBufSerializer<'a>>,
{
    let id = ContractId::from_bytes(contract_id);
    let wasm = fs::read(wasm_path(wasm_name))
        .unwrap_or_else(|err| panic!("read {wasm_name}: {err}"));
    session
        .deploy(
            &wasm,
            ContractData::builder()
                .owner(OWNER_BYTES)
                .contract_id(id)
                .init_arg(init),
            GAS_LIMIT,
        )
        .unwrap_or_else(|err| panic!("deploy {wasm_name}: {err}"))
}

fn wasm_path(name: &str) -> PathBuf {
    workspace_root()
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release")
        .join(name)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}
