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
use dusk_contract_standards::token::drc721::{
    GetApproved, Init as TokenInit, InitToken, IsApprovedForAll, OwnerOf,
    RoyaltyInfo, RoyaltyQuery, RoyaltyQuote, SignedApproveCall,
    SignedSetApprovalForAllCall, TransferFromCall,
};
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

const NFT_ADMIN_DOMAIN: NonceDomain = [21u8; 32];
const MINT_ACTION: [u8; 32] = [22u8; 32];
const PAUSE_ACTION: [u8; 32] = [23u8; 32];
const UNPAUSE_ACTION: [u8; 32] = [24u8; 32];
const SET_DEFAULT_ROYALTY_ACTION: [u8; 32] = [25u8; 32];
const NFT_SIGNED_APPROVE_DOMAIN: NonceDomain = [29u8; 32];
const NFT_SIGNED_APPROVE_ACTION: [u8; 32] = [30u8; 32];
const NFT_SIGNED_APPROVAL_FOR_ALL_ACTION: [u8; 32] = [31u8; 32];

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[archive_attr(derive(CheckBytes))]
struct Drc721ExampleInit {
    owner: Principal,
    token: TokenInit,
    default_royalty: Option<RoyaltyInfo>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct Drc721MintCall {
    to: Principal,
    token_id: u64,
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct Drc721AdminCall {
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct Drc721SetDefaultRoyaltyCall {
    info: RoyaltyInfo,
    authorization: Option<SignedAuthorization>,
}

#[test]
fn drc721_reference_contract_enforces_signed_admin_and_pause_paths() {
    let _hard_fork_guard =
        host_queries::set_hard_fork(host_queries::HardFork::Aegis);
    let vm = VM::ephemeral().expect("create ephemeral VM");
    let mut session = vm.genesis_session(CHAIN_ID);

    let admin = phoenix_principal(7);
    let royalty_receiver = Principal::Contract(ContractId::from_bytes([9; 32]));
    let contract = deploy(
        &mut session,
        "drc721_collection.wasm",
        [21u8; 32],
        &Drc721ExampleInit {
            owner: admin,
            token: TokenInit {
                name: "VM Dusk Collection".into(),
                symbol: "VDNFT".into(),
                base_uri: "ipfs://vm-nft/".into(),
                initial_tokens: vec![InitToken {
                    account: admin,
                    token_id: 1,
                }],
            },
            default_royalty: Some(RoyaltyInfo {
                receiver: royalty_receiver,
                basis_points: 250,
            }),
        },
    );

    assert_eq!(
        query_string(&mut session, contract, "name", &()),
        "VM Dusk Collection"
    );
    assert_eq!(query_u64(&mut session, contract, "total_supply", &()), 1);
    assert_eq!(
        query_principal(
            &mut session,
            contract,
            "owner_of",
            &OwnerOf { token_id: 1 }
        ),
        admin
    );
    assert_eq!(
        query_royalty(
            &mut session,
            contract,
            "royalty_info",
            &RoyaltyQuery {
                token_id: 1,
                sale_price: 10_000,
            },
        ),
        RoyaltyQuote {
            receiver: royalty_receiver,
            amount: 250,
        }
    );

    let mut rng = StdRng::seed_from_u64(4444);
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
            NFT_ADMIN_DOMAIN,
            MINT_ACTION,
            0,
            mint_payload_hash(admin, 43),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc721MintCall {
                to: admin,
                token_id: 43,
                authorization: Some(mint_auth.clone()),
            },
            GAS_LIMIT,
        )
        .expect("mint NFT by signed Phoenix owner");
    assert_eq!(
        query_principal(
            &mut session,
            contract,
            "owner_of",
            &OwnerOf { token_id: 43 }
        ),
        admin
    );
    assert_contract_nonce(&mut session, contract, admin, NFT_ADMIN_DOMAIN, 1);

    assert!(session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc721MintCall {
                to: admin,
                token_id: 43,
                authorization: Some(mint_auth),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(&mut session, contract, admin, NFT_ADMIN_DOMAIN, 1);

    let bad_mint_action = authorized_action(
        ContractId::from_bytes([78u8; 32]),
        admin,
        NFT_ADMIN_DOMAIN,
        MINT_ACTION,
        1,
        mint_payload_hash(admin, 44),
    );
    assert!(session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc721MintCall {
                to: admin,
                token_id: 44,
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(
                        &mut rng,
                        &admin_sk,
                        admin_pk,
                        bad_mint_action,
                    )
                )),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(&mut session, contract, admin, NFT_ADMIN_DOMAIN, 1);

    let approved = Principal::Contract(ContractId::from_bytes([55u8; 32]));
    let approve_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            NFT_SIGNED_APPROVE_DOMAIN,
            NFT_SIGNED_APPROVE_ACTION,
            0,
            approve_payload_hash(admin, approved, 43),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "approve_by_authorization",
            &SignedApproveCall {
                owner: admin,
                approved,
                token_id: 43,
                authorization: approve_auth.clone(),
            },
            GAS_LIMIT,
        )
        .expect("approve NFT by signed Phoenix owner");
    assert_eq!(
        query_principal(
            &mut session,
            contract,
            "get_approved",
            &GetApproved { token_id: 43 }
        ),
        approved
    );
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        NFT_SIGNED_APPROVE_DOMAIN,
        1,
    );

    assert!(session
        .call::<_, ()>(
            contract,
            "approve_by_authorization",
            &SignedApproveCall {
                owner: admin,
                approved,
                token_id: 43,
                authorization: approve_auth,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        NFT_SIGNED_APPROVE_DOMAIN,
        1,
    );

    let bad_approval_payload = authorized_action(
        contract,
        admin,
        NFT_SIGNED_APPROVE_DOMAIN,
        NFT_SIGNED_APPROVE_ACTION,
        1,
        approve_payload_hash(admin, approved, 44),
    );
    assert!(session
        .call::<_, ()>(
            contract,
            "approve_by_authorization",
            &SignedApproveCall {
                owner: admin,
                approved,
                token_id: 43,
                authorization: SignedAuthorization::Phoenix(phoenix_auth(
                    &mut rng,
                    &admin_sk,
                    admin_pk,
                    bad_approval_payload,
                )),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        NFT_SIGNED_APPROVE_DOMAIN,
        1,
    );

    let operator = Principal::Contract(ContractId::from_bytes([56u8; 32]));
    let operator_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            NFT_SIGNED_APPROVE_DOMAIN,
            NFT_SIGNED_APPROVAL_FOR_ALL_ACTION,
            1,
            approval_for_all_payload_hash(admin, operator, true),
        ),
    ));
    session
        .call::<_, ()>(
            contract,
            "set_approval_for_all_by_authorization",
            &SignedSetApprovalForAllCall {
                owner: admin,
                operator,
                approved: true,
                authorization: operator_auth.clone(),
            },
            GAS_LIMIT,
        )
        .expect("set NFT operator by signed Phoenix owner");
    assert!(query_bool(
        &mut session,
        contract,
        "is_approved_for_all",
        &IsApprovedForAll {
            owner: admin,
            operator,
        },
    ));
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        NFT_SIGNED_APPROVE_DOMAIN,
        2,
    );
    assert!(session
        .call::<_, ()>(
            contract,
            "set_approval_for_all_by_authorization",
            &SignedSetApprovalForAllCall {
                owner: admin,
                operator,
                approved: true,
                authorization: operator_auth,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        NFT_SIGNED_APPROVE_DOMAIN,
        2,
    );

    let invalid_royalty = RoyaltyInfo {
        receiver: admin,
        basis_points: 10_001,
    };
    let invalid_royalty_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            NFT_ADMIN_DOMAIN,
            SET_DEFAULT_ROYALTY_ACTION,
            1,
            royalty_payload_hash(None, invalid_royalty),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "set_default_royalty",
            &Drc721SetDefaultRoyaltyCall {
                info: invalid_royalty,
                authorization: Some(invalid_royalty_auth),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(&mut session, contract, admin, NFT_ADMIN_DOMAIN, 1);

    let valid_royalty = RoyaltyInfo {
        receiver: admin,
        basis_points: 500,
    };
    session
        .call::<_, ()>(
            contract,
            "set_default_royalty",
            &Drc721SetDefaultRoyaltyCall {
                info: valid_royalty,
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(
                        &mut rng,
                        &admin_sk,
                        admin_pk,
                        authorized_action(
                            contract,
                            admin,
                            NFT_ADMIN_DOMAIN,
                            SET_DEFAULT_ROYALTY_ACTION,
                            1,
                            royalty_payload_hash(None, valid_royalty),
                        ),
                    ),
                )),
            },
            GAS_LIMIT,
        )
        .expect("set valid default royalty by signed owner");
    assert_contract_nonce(&mut session, contract, admin, NFT_ADMIN_DOMAIN, 2);

    session
        .call::<_, ()>(
            contract,
            "pause",
            &Drc721AdminCall {
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(
                        &mut rng,
                        &admin_sk,
                        admin_pk,
                        authorized_action(
                            contract,
                            admin,
                            NFT_ADMIN_DOMAIN,
                            PAUSE_ACTION,
                            2,
                            empty_payload_hash(b"drc721.pause"),
                        ),
                    ),
                )),
            },
            GAS_LIMIT,
        )
        .expect("pause NFT by signed Phoenix owner");
    assert!(query_bool(&mut session, contract, "paused", &()));
    assert_contract_nonce(&mut session, contract, admin, NFT_ADMIN_DOMAIN, 3);

    assert!(session
        .call::<_, ()>(
            contract,
            "transfer_from",
            &TransferFromCall {
                from: admin,
                to: admin,
                token_id: 43,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert!(session
        .call::<_, ()>(contract, "burn", &43u64, GAS_LIMIT)
        .is_err());

    let paused_mint = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            NFT_ADMIN_DOMAIN,
            MINT_ACTION,
            3,
            mint_payload_hash(admin, 44),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc721MintCall {
                to: admin,
                token_id: 44,
                authorization: Some(paused_mint),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(&mut session, contract, admin, NFT_ADMIN_DOMAIN, 3);

    session
        .call::<_, ()>(
            contract,
            "set_approval_for_all_by_authorization",
            &SignedSetApprovalForAllCall {
                owner: admin,
                operator,
                approved: false,
                authorization: SignedAuthorization::Phoenix(phoenix_auth(
                    &mut rng,
                    &admin_sk,
                    admin_pk,
                    authorized_action(
                        contract,
                        admin,
                        NFT_SIGNED_APPROVE_DOMAIN,
                        NFT_SIGNED_APPROVAL_FOR_ALL_ACTION,
                        2,
                        approval_for_all_payload_hash(admin, operator, false),
                    ),
                )),
            },
            GAS_LIMIT,
        )
        .expect("operator approval remains available while paused");
    assert!(!query_bool(
        &mut session,
        contract,
        "is_approved_for_all",
        &IsApprovedForAll {
            owner: admin,
            operator,
        },
    ));
    assert_contract_nonce(
        &mut session,
        contract,
        admin,
        NFT_SIGNED_APPROVE_DOMAIN,
        3,
    );

    session
        .call::<_, ()>(
            contract,
            "unpause",
            &Drc721AdminCall {
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(
                        &mut rng,
                        &admin_sk,
                        admin_pk,
                        authorized_action(
                            contract,
                            admin,
                            NFT_ADMIN_DOMAIN,
                            UNPAUSE_ACTION,
                            3,
                            empty_payload_hash(b"drc721.unpause"),
                        ),
                    ),
                )),
            },
            GAS_LIMIT,
        )
        .expect("unpause NFT by signed Phoenix owner");
    assert!(!query_bool(&mut session, contract, "paused", &()));
    assert_contract_nonce(&mut session, contract, admin, NFT_ADMIN_DOMAIN, 4);
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

fn mint_payload_hash(to: Principal, token_id: u64) -> [u8; 32] {
    let mut bytes = Vec::from(&b"drc721.mint"[..]);
    push_principal(&mut bytes, to);
    bytes.extend_from_slice(&token_id.to_be_bytes());
    host_queries::keccak256(bytes)
}

fn approve_payload_hash(
    owner: Principal,
    approved: Principal,
    token_id: u64,
) -> [u8; 32] {
    let mut bytes = Vec::from(&b"drc721.approve"[..]);
    push_principal(&mut bytes, owner);
    push_principal(&mut bytes, approved);
    bytes.extend_from_slice(&token_id.to_be_bytes());
    host_queries::keccak256(bytes)
}

fn approval_for_all_payload_hash(
    owner: Principal,
    operator: Principal,
    approved: bool,
) -> [u8; 32] {
    let mut bytes = Vec::from(&b"drc721.approval_for_all"[..]);
    push_principal(&mut bytes, owner);
    push_principal(&mut bytes, operator);
    bytes.push(u8::from(approved));
    host_queries::keccak256(bytes)
}

fn royalty_payload_hash(token_id: Option<u64>, info: RoyaltyInfo) -> [u8; 32] {
    let mut bytes = Vec::from(&b"drc721.royalty"[..]);
    match token_id {
        Some(token_id) => {
            bytes.push(1);
            bytes.extend_from_slice(&token_id.to_be_bytes());
        }
        None => bytes.push(0),
    }
    push_principal(&mut bytes, info.receiver);
    bytes.extend_from_slice(&info.basis_points.to_be_bytes());
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

fn query_principal<A>(
    session: &mut Session,
    contract: ContractId,
    method: &str,
    args: &A,
) -> Principal
where
    A: for<'a> Serialize<StandardBufSerializer<'a>>,
    A::Archived: for<'a> CheckBytes<DefaultValidator<'a>>,
{
    query(session, contract, method, args)
}

fn query_royalty<A>(
    session: &mut Session,
    contract: ContractId,
    method: &str,
    args: &A,
) -> RoyaltyQuote
where
    A: for<'a> Serialize<StandardBufSerializer<'a>>,
    A::Archived: for<'a> CheckBytes<DefaultValidator<'a>>,
{
    query(session, contract, method, args)
}

fn query_string<A>(
    session: &mut Session,
    contract: ContractId,
    method: &str,
    args: &A,
) -> String
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
