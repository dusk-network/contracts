// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::fs;
use std::path::{Path, PathBuf};

use bytecheck::CheckBytes;
use dusk_contract_standards::access::Role;
use dusk_contract_standards::auth::{
    AuthorizedAction, MoonlightAuthorization, PhoenixSignatureAuthorization,
    SignedAuthorization,
};
use dusk_contract_standards::core::{NonceDomain, NonceQuery, Principal};
use dusk_contract_standards::token::drc20::{
    events::{
        Approval as Drc20Approval, Transfer as Drc20Transfer, APPROVAL_TOPIC,
        TRANSFER_TOPIC,
    },
    Allowance, BalanceOf, Init as TokenInit, InitBalance, SignedApproveCall,
    TransferCall, TransferFromCall, ZERO_PRINCIPAL,
};
use dusk_core::abi::{ContractId, Metadata, StandardBufSerializer};
use dusk_core::signatures::bls::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
};
use dusk_core::signatures::schnorr::{
    PublicKey as SchnorrPublicKey, SecretKey as SchnorrSecretKey,
};
use dusk_core::transfer::TRANSFER_CONTRACT;
use dusk_core::JubJubScalar;
use dusk_vm::host_queries;
use dusk_vm::{ContractData, Session, VM};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rkyv::validation::validators::DefaultValidator;
use rkyv::{check_archived_root, Archive, Deserialize, Infallible, Serialize};

const CHAIN_ID: u8 = 0xD5;
const GAS_LIMIT: u64 = 1_000_000_000;
const OWNER_BYTES: [u8; 32] = [1u8; 32];

const MINTER_ROLE: Role = [1u8; 32];
const PAUSER_ROLE: Role = [2u8; 32];
const TOKEN_ADMIN_DOMAIN: NonceDomain = [11u8; 32];
const SIGNED_APPROVE_DOMAIN: NonceDomain = [12u8; 32];
const MINT_ACTION: [u8; 32] = [13u8; 32];
const PAUSE_ACTION: [u8; 32] = [14u8; 32];
const UNPAUSE_ACTION: [u8; 32] = [15u8; 32];
const GRANT_ROLE_ACTION: [u8; 32] = [16u8; 32];
const REVOKE_ROLE_ACTION: [u8; 32] = [17u8; 32];
const SIGNED_APPROVE_ACTION: [u8; 32] = [18u8; 32];

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[archive_attr(derive(CheckBytes))]
struct Drc20ExampleInit {
    admin: Principal,
    token: TokenInit,
    cap: u64,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct Drc20MintCall {
    to: Principal,
    amount: u64,
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct Drc20AdminCall {
    authorization: Option<SignedAuthorization>,
}

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[archive_attr(derive(CheckBytes))]
struct RoleQuery {
    role: Role,
    account: Principal,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct RoleCall {
    role: Role,
    account: Principal,
    authorization: Option<SignedAuthorization>,
}

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[archive_attr(derive(CheckBytes))]
struct VotesQuery {
    account: Principal,
    timepoint: u64,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[archive_attr(derive(CheckBytes))]
struct ForwardCall {
    contract: ContractId,
    function: String,
    args: Vec<u8>,
}

#[test]
fn drc20_reference_contract_enforces_composed_security_paths() {
    let _hard_fork_guard =
        host_queries::set_hard_fork(host_queries::HardFork::Aegis);
    let vm = VM::ephemeral().expect("create ephemeral VM");
    let mut session = vm.genesis_session(CHAIN_ID);

    let admin = phoenix_principal(7);
    let moonlight_owner_sk = moonlight_secret(333);
    let moonlight_owner_pk = BlsPublicKey::from(&moonlight_owner_sk);
    let moonlight_owner = Principal::moonlight(&moonlight_owner_pk);
    let moonlight_router = deploy(
        &mut session,
        "moonlight_call_router.wasm",
        TRANSFER_CONTRACT.to_bytes(),
        &(),
    );
    let contract = deploy(
        &mut session,
        "drc20_roles_pausable.wasm",
        [20u8; 32],
        &Drc20ExampleInit {
            admin,
            token: TokenInit {
                name: "VM Dusk Token".into(),
                symbol: "VDUSK".into(),
                decimals: 9,
                initial_balances: vec![
                    InitBalance {
                        account: admin,
                        amount: 1_000,
                    },
                    InitBalance {
                        account: moonlight_owner,
                        amount: 10,
                    },
                ],
            },
            cap: 1_016,
        },
    );

    assert_eq!(
        query_u64(&mut session, contract, "total_supply", &()),
        1_010
    );
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "balance_of",
            &BalanceOf { account: admin },
        ),
        1_000
    );
    assert_balance_votes_mirror(&mut session, contract, admin);
    assert_balance_votes_mirror(&mut session, contract, moonlight_owner);
    assert_total_votes_mirror(&mut session, contract);
    assert!(query_bool(
        &mut session,
        contract,
        "has_role",
        &RoleQuery {
            role: MINTER_ROLE,
            account: admin,
        },
    ));
    assert!(query_bool(
        &mut session,
        contract,
        "has_role",
        &RoleQuery {
            role: PAUSER_ROLE,
            account: admin,
        },
    ));

    let mut rng = StdRng::seed_from_u64(2222);
    let admin_sk = SchnorrSecretKey::from(JubJubScalar::from(7u64));
    let admin_pk = SchnorrPublicKey::from(&admin_sk);
    assert_eq!(admin, Principal::phoenix_public_key(&admin_pk));

    let mint_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            TOKEN_ADMIN_DOMAIN,
            MINT_ACTION,
            0,
            mint_payload_hash(admin, 5),
        ),
    ));
    let mint_receipt = session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc20MintCall {
                to: admin,
                amount: 5,
                authorization: Some(mint_auth.clone()),
            },
            GAS_LIMIT,
        )
        .expect("mint by signed Phoenix admin");
    assert_single_event(
        &mint_receipt.events,
        contract,
        TRANSFER_TOPIC,
        Drc20Transfer {
            from: ZERO_PRINCIPAL,
            to: admin,
            amount: 5,
        },
    );
    assert_eq!(
        query_u64(&mut session, contract, "total_supply", &()),
        1_015
    );
    assert_balance_votes_mirror(&mut session, contract, admin);
    assert_total_votes_mirror(&mut session, contract);
    assert_contract_nonce(&mut session, contract, admin, TOKEN_ADMIN_DOMAIN, 1);

    assert!(session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc20MintCall {
                to: admin,
                amount: 5,
                authorization: Some(mint_auth),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(&mut session, contract, admin, TOKEN_ADMIN_DOMAIN, 1);

    let cap_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            TOKEN_ADMIN_DOMAIN,
            MINT_ACTION,
            1,
            mint_payload_hash(admin, 2),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc20MintCall {
                to: admin,
                amount: 2,
                authorization: Some(cap_auth),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_eq!(
        query_u64(&mut session, contract, "total_supply", &()),
        1_015
    );
    assert_balance_votes_mirror(&mut session, contract, admin);
    assert_total_votes_mirror(&mut session, contract);
    assert_contract_nonce(&mut session, contract, admin, TOKEN_ADMIN_DOMAIN, 1);

    let spender = Principal::phoenix([88u8; 32]);
    let approve_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            SIGNED_APPROVE_DOMAIN,
            SIGNED_APPROVE_ACTION,
            0,
            approve_payload_hash(admin, spender, 33),
        ),
    ));
    let approve_receipt = session
        .call::<_, ()>(
            contract,
            "approve_by_authorization",
            &SignedApproveCall {
                owner: admin,
                spender,
                amount: 33,
                authorization: approve_auth.clone(),
            },
            GAS_LIMIT,
        )
        .expect("approve by signed Phoenix owner");
    assert_single_event(
        &approve_receipt.events,
        contract,
        APPROVAL_TOPIC,
        Drc20Approval {
            owner: admin,
            spender,
            amount: 33,
        },
    );
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "allowance",
            &Allowance {
                owner: admin,
                spender,
            },
        ),
        33
    );
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        SIGNED_APPROVE_DOMAIN,
        1,
    );

    assert!(session
        .call::<_, ()>(
            contract,
            "approve_by_authorization",
            &SignedApproveCall {
                owner: admin,
                spender,
                amount: 33,
                authorization: approve_auth,
            },
            GAS_LIMIT,
        )
        .is_err());

    let bad_approve_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            SIGNED_APPROVE_DOMAIN,
            SIGNED_APPROVE_ACTION,
            1,
            approve_payload_hash(admin, spender, 34),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "approve_by_authorization",
            &SignedApproveCall {
                owner: admin,
                spender,
                amount: 35,
                authorization: bad_approve_auth,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "allowance",
            &Allowance {
                owner: admin,
                spender,
            },
        ),
        33
    );
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        SIGNED_APPROVE_DOMAIN,
        1,
    );

    let wrong_owner_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            SIGNED_APPROVE_DOMAIN,
            SIGNED_APPROVE_ACTION,
            1,
            approve_payload_hash(admin, spender, 36),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "approve_by_authorization",
            &SignedApproveCall {
                owner: moonlight_owner,
                spender,
                amount: 36,
                authorization: wrong_owner_auth,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "allowance",
            &Allowance {
                owner: admin,
                spender,
            },
        ),
        33
    );
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        SIGNED_APPROVE_DOMAIN,
        1,
    );

    let wrong_domain_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            TOKEN_ADMIN_DOMAIN,
            SIGNED_APPROVE_ACTION,
            1,
            approve_payload_hash(admin, spender, 36),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "approve_by_authorization",
            &SignedApproveCall {
                owner: admin,
                spender,
                amount: 36,
                authorization: wrong_domain_auth,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "allowance",
            &Allowance {
                owner: admin,
                spender,
            },
        ),
        33
    );
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        SIGNED_APPROVE_DOMAIN,
        1,
    );
    assert_contract_nonce(&mut session, contract, admin, TOKEN_ADMIN_DOMAIN, 1);

    let moonlight_approve_action = authorized_action(
        contract,
        moonlight_owner,
        SIGNED_APPROVE_DOMAIN,
        SIGNED_APPROVE_ACTION,
        0,
        approve_payload_hash(moonlight_owner, admin, 44),
    );
    let moonlight_approve_receipt = session
        .call::<_, ()>(
            contract,
            "approve_by_authorization",
            &SignedApproveCall {
                owner: moonlight_owner,
                spender: admin,
                amount: 44,
                authorization: SignedAuthorization::Moonlight(moonlight_auth(
                    &moonlight_owner_sk,
                    moonlight_owner_pk,
                    moonlight_approve_action,
                )),
            },
            GAS_LIMIT,
        )
        .expect("approve by signed Moonlight owner");
    assert_single_event(
        &moonlight_approve_receipt.events,
        contract,
        APPROVAL_TOPIC,
        Drc20Approval {
            owner: moonlight_owner,
            spender: admin,
            amount: 44,
        },
    );
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "allowance",
            &Allowance {
                owner: moonlight_owner,
                spender: admin,
            },
        ),
        44
    );
    assert_contract_nonce(
        &mut session,
        contract,
        moonlight_owner,
        SIGNED_APPROVE_DOMAIN,
        1,
    );

    let pause_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            TOKEN_ADMIN_DOMAIN,
            PAUSE_ACTION,
            1,
            empty_payload_hash(b"drc20.pause"),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "pause",
            &Drc20AdminCall {
                authorization: Some(pause_auth),
            },
            GAS_LIMIT,
        )
        .expect("pause by signed Phoenix admin");
    assert!(query_bool(&mut session, contract, "paused", &()));
    assert_contract_nonce(&mut session, contract, admin, TOKEN_ADMIN_DOMAIN, 2);

    assert!(session
        .call::<_, ()>(
            contract,
            "transfer",
            &TransferCall {
                to: spender,
                amount: 1,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert!(session
        .call::<_, ()>(
            contract,
            "transfer_from",
            &TransferFromCall {
                owner: admin,
                to: spender,
                amount: 1,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert!(session
        .call::<_, ()>(contract, "burn", &1u64, GAS_LIMIT)
        .is_err());

    let paused_mint = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            TOKEN_ADMIN_DOMAIN,
            MINT_ACTION,
            2,
            mint_payload_hash(admin, 1),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc20MintCall {
                to: admin,
                amount: 1,
                authorization: Some(paused_mint),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(&mut session, contract, admin, TOKEN_ADMIN_DOMAIN, 2);

    let unpause_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            TOKEN_ADMIN_DOMAIN,
            UNPAUSE_ACTION,
            2,
            empty_payload_hash(b"drc20.unpause"),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "unpause",
            &Drc20AdminCall {
                authorization: Some(unpause_auth),
            },
            GAS_LIMIT,
        )
        .expect("unpause by signed Phoenix admin");
    assert!(!query_bool(&mut session, contract, "paused", &()));
    assert_contract_nonce(&mut session, contract, admin, TOKEN_ADMIN_DOMAIN, 3);

    let new_pauser =
        Principal::moonlight(&BlsPublicKey::from(&moonlight_secret(444)));
    let grant_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            TOKEN_ADMIN_DOMAIN,
            GRANT_ROLE_ACTION,
            3,
            role_payload_hash(PAUSER_ROLE, new_pauser),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "grant_role",
            &RoleCall {
                role: PAUSER_ROLE,
                account: new_pauser,
                authorization: Some(grant_auth),
            },
            GAS_LIMIT,
        )
        .expect("grant role by signed Phoenix admin");
    assert!(query_bool(
        &mut session,
        contract,
        "has_role",
        &RoleQuery {
            role: PAUSER_ROLE,
            account: new_pauser,
        },
    ));
    assert_contract_nonce(&mut session, contract, admin, TOKEN_ADMIN_DOMAIN, 4);

    let revoke_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            TOKEN_ADMIN_DOMAIN,
            REVOKE_ROLE_ACTION,
            4,
            role_payload_hash(PAUSER_ROLE, new_pauser),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "revoke_role",
            &RoleCall {
                role: PAUSER_ROLE,
                account: new_pauser,
                authorization: Some(revoke_auth),
            },
            GAS_LIMIT,
        )
        .expect("revoke role by signed Phoenix admin");
    assert!(!query_bool(
        &mut session,
        contract,
        "has_role",
        &RoleQuery {
            role: PAUSER_ROLE,
            account: new_pauser,
        },
    ));
    assert_contract_nonce(&mut session, contract, admin, TOKEN_ADMIN_DOMAIN, 5);

    let transfer = TransferCall {
        to: admin,
        amount: 3,
    };
    assert!(session
        .call::<_, ()>(contract, "transfer", &transfer, GAS_LIMIT)
        .is_err());
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "balance_of",
            &BalanceOf {
                account: moonlight_owner,
            },
        ),
        10
    );
    assert_balance_votes_mirror(&mut session, contract, admin);
    assert_balance_votes_mirror(&mut session, contract, moonlight_owner);
    assert_total_votes_mirror(&mut session, contract);

    session
        .set_meta(Metadata::PUBLIC_SENDER, Some(moonlight_owner_pk))
        .expect("set Moonlight public sender");
    session
        .call::<_, Vec<u8>>(
            moonlight_router,
            "forward",
            &ForwardCall {
                contract,
                function: "transfer".into(),
                args: Session::serialize_data(&transfer)
                    .expect("serialize routed transfer"),
            },
            GAS_LIMIT,
        )
        .expect("route transfer by observed Moonlight holder");
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "balance_of",
            &BalanceOf { account: admin },
        ),
        1_008
    );
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "balance_of",
            &BalanceOf {
                account: moonlight_owner,
            },
        ),
        7
    );
    assert_balance_votes_mirror(&mut session, contract, admin);
    assert_balance_votes_mirror(&mut session, contract, moonlight_owner);
    assert_total_votes_mirror(&mut session, contract);

    session
        .call::<_, Vec<u8>>(
            moonlight_router,
            "forward",
            &ForwardCall {
                contract,
                function: "burn".into(),
                args: Session::serialize_data(&2u64)
                    .expect("serialize routed burn"),
            },
            GAS_LIMIT,
        )
        .expect("route burn by observed Moonlight holder");
    assert_eq!(
        query_u64(
            &mut session,
            contract,
            "balance_of",
            &BalanceOf {
                account: moonlight_owner,
            },
        ),
        5
    );
    assert_eq!(
        query_u64(&mut session, contract, "total_supply", &()),
        1_013
    );
    assert_balance_votes_mirror(&mut session, contract, moonlight_owner);
    assert_total_votes_mirror(&mut session, contract);
    assert!(session.remove_meta(Metadata::PUBLIC_SENDER).is_some());
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

fn moonlight_auth(
    secret_key: &BlsSecretKey,
    public_key: BlsPublicKey,
    action: AuthorizedAction,
) -> MoonlightAuthorization {
    MoonlightAuthorization {
        action,
        public_key,
        signature: secret_key.sign(&action.message_bytes()),
    }
}

fn moonlight_secret(seed: u64) -> BlsSecretKey {
    let mut rng = StdRng::seed_from_u64(seed);
    BlsSecretKey::random(&mut rng)
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

fn mint_payload_hash(to: Principal, amount: u64) -> [u8; 32] {
    let mut bytes = Vec::from(&b"drc20.mint"[..]);
    push_principal(&mut bytes, to);
    bytes.extend_from_slice(&amount.to_be_bytes());
    host_queries::keccak256(bytes)
}

fn approve_payload_hash(
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

fn role_payload_hash(role: Role, account: Principal) -> [u8; 32] {
    let mut bytes = Vec::from(&b"drc20.role"[..]);
    bytes.extend_from_slice(&role);
    push_principal(&mut bytes, account);
    host_queries::keccak256(bytes)
}

fn empty_payload_hash(tag: &[u8]) -> [u8; 32] {
    host_queries::keccak256(Vec::from(tag))
}

fn push_principal(bytes: &mut Vec<u8>, principal: Principal) {
    let principal = principal.to_bytes();
    bytes.extend_from_slice(&(principal.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&principal);
}

fn phoenix_principal(seed: u64) -> Principal {
    let secret = SchnorrSecretKey::from(JubJubScalar::from(seed));
    let public = SchnorrPublicKey::from(&secret);
    Principal::phoenix_public_key(&public)
}

fn query_bool<A>(
    session: &mut Session,
    contract: ContractId,
    method: &str,
    args: &A,
) -> bool
where
    A: for<'a> Serialize<StandardBufSerializer<'a>>,
    A::Archived: for<'a> CheckBytes<DefaultValidator<'a>>,
{
    query(session, contract, method, args)
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

fn assert_balance_votes_mirror(
    session: &mut Session,
    contract: ContractId,
    account: Principal,
) {
    let balance =
        query_u64(session, contract, "balance_of", &BalanceOf { account });
    assert_eq!(
        query_u64(session, contract, "latest_votes", &account),
        balance
    );
    assert_eq!(
        query_u64(
            session,
            contract,
            "past_votes",
            &VotesQuery {
                account,
                timepoint: u64::MAX,
            },
        ),
        balance
    );
}

fn assert_total_votes_mirror(session: &mut Session, contract: ContractId) {
    let total_supply = query_u64(session, contract, "total_supply", &());
    assert_eq!(
        query_u64(session, contract, "latest_total_votes", &()),
        total_supply
    );
    assert_eq!(
        query_u64(session, contract, "past_total_supply", &u64::MAX),
        total_supply
    );
}

fn assert_single_event<T>(
    events: &[dusk_core::abi::Event],
    source: ContractId,
    topic: &str,
    expected: T,
) where
    T: Archive + PartialEq + core::fmt::Debug,
    T::Archived:
        Deserialize<T, Infallible> + for<'a> CheckBytes<DefaultValidator<'a>>,
{
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.source, source);
    assert_eq!(event.topic, topic);
    let archived = check_archived_root::<T>(&event.data).expect("event data");
    let actual = archived.deserialize(&mut Infallible).expect("event decode");
    assert_eq!(actual, expected);
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
