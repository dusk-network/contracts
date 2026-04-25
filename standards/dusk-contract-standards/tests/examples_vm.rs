use std::fs;
use std::path::{Path, PathBuf};

use bytecheck::CheckBytes;
use dusk_contract_standards::auth::{
    AuthorizedAction, MoonlightAuthorization, PhoenixSignatureAuthorization,
    SignedAuthorization,
};
use dusk_contract_standards::core::{NonceDomain, Principal};
use dusk_contract_standards::token::drc20::{
    Allowance, BalanceOf as BalanceOf20, Init as Init20, InitBalance,
    SignedApproveCall,
};
use dusk_contract_standards::token::drc721::{
    Init as Init721, InitToken, OwnerOf, TokensOf,
};
use dusk_core::abi::{ContractId, Metadata};
use dusk_core::signatures::bls::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
};
use dusk_core::signatures::schnorr::{
    PublicKey as SchnorrPublicKey, SecretKey as SchnorrSecretKey,
};
use dusk_core::JubJubScalar;
use dusk_vm::host_queries;
use dusk_vm::{ContractData, Session, VM};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rkyv::{Archive, Deserialize, Serialize};

const CHAIN_ID: u8 = 0xD5;
const GAS_LIMIT: u64 = 1_000_000_000;
const OWNER_BYTES: [u8; 32] = [1u8; 32];
const SET_VALUE_DOMAIN: NonceDomain = [3u8; 32];
const SET_VALUE_ACTION: [u8; 32] = [4u8; 32];
const TOKEN_ADMIN_DOMAIN: NonceDomain = [11u8; 32];
const SIGNED_APPROVE_DOMAIN: NonceDomain = [12u8; 32];
const MINT_ACTION: [u8; 32] = [13u8; 32];
const PAUSE_ACTION: [u8; 32] = [14u8; 32];
const UNPAUSE_ACTION: [u8; 32] = [15u8; 32];
const SIGNED_APPROVE_ACTION: [u8; 32] = [18u8; 32];
const NFT_ADMIN_DOMAIN: NonceDomain = [21u8; 32];
const NFT_MINT_ACTION: [u8; 32] = [22u8; 32];
const NFT_PAUSE_ACTION: [u8; 32] = [23u8; 32];
const NFT_UNPAUSE_ACTION: [u8; 32] = [24u8; 32];
const PROXY_ADMIN_DOMAIN: NonceDomain = [31u8; 32];
const SET_PROXY_VALUE_ACTION: [u8; 32] = [32u8; 32];

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[archive_attr(derive(CheckBytes))]
struct SetValueByMoonlight {
    authorization: MoonlightAuthorization,
    amount: u64,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[archive_attr(derive(CheckBytes))]
struct SetValueByPhoenix {
    authorization: PhoenixSignatureAuthorization,
    amount: u64,
}

#[derive(
    Archive, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[archive_attr(derive(CheckBytes))]
struct NonceQuery {
    principal: Principal,
    domain: NonceDomain,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[archive_attr(derive(CheckBytes))]
struct Drc20ExampleInit {
    admin: Principal,
    token: Init20,
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

#[derive(Archive, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[archive_attr(derive(CheckBytes))]
struct Drc721ExampleInit {
    owner: Principal,
    token: Init721,
    default_royalty:
        Option<dusk_contract_standards::token::drc721::RoyaltyInfo>,
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

#[test]
#[ignore = "requires release Wasm examples; run after the wasm build"]
fn wasm_examples_deploy_and_answer_queries() {
    let _hard_fork_guard =
        host_queries::set_hard_fork(host_queries::HardFork::Aegis);
    let vm = VM::ephemeral().expect("create ephemeral VM");
    let mut session = vm.genesis_session(CHAIN_ID);

    let admin = phoenix_principal(7);
    let auth_counter =
        deploy(&mut session, "authorization_counter.wasm", [19u8; 32], &());
    let auth_value: u64 = session
        .call(auth_counter, "value", &(), GAS_LIMIT)
        .expect("query authorization counter value")
        .data;
    assert_eq!(auth_value, 0);
    exercise_authorization_counter_signed_calls(&mut session, auth_counter);

    let drc20 = deploy(
        &mut session,
        "drc20_roles_pausable.wasm",
        [20u8; 32],
        &Drc20ExampleInit {
            admin,
            token: Init20 {
                name: "VM Dusk Token".into(),
                symbol: "VDUSK".into(),
                decimals: 9,
                initial_balances: vec![InitBalance {
                    account: admin,
                    amount: 1_000,
                }],
            },
            cap: 10_000,
        },
    );
    let drc20_supply: u64 = session
        .call(drc20, "total_supply", &(), GAS_LIMIT)
        .expect("query drc20 total supply")
        .data;
    assert_eq!(drc20_supply, 1_000);
    let drc20_balance: u64 = session
        .call(
            drc20,
            "balance_of",
            &BalanceOf20 { account: admin },
            GAS_LIMIT,
        )
        .expect("query drc20 balance")
        .data;
    assert_eq!(drc20_balance, 1_000);
    assert!(session
        .call::<_, ()>(
            drc20,
            "mint",
            &Drc20MintCall {
                to: admin,
                amount: 1,
                authorization: None,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert!(session
        .call::<_, ()>(
            drc20,
            "pause",
            &Drc20AdminCall {
                authorization: None,
            },
            GAS_LIMIT,
        )
        .is_err());
    exercise_drc20_signed_calls(&mut session, drc20, admin);

    let drc721 = deploy(
        &mut session,
        "drc721_collection.wasm",
        [21u8; 32],
        &Drc721ExampleInit {
            owner: admin,
            token: Init721 {
                name: "VM Dusk Collection".into(),
                symbol: "VDNFT".into(),
                base_uri: "ipfs://vm/".into(),
                initial_tokens: vec![InitToken {
                    account: admin,
                    token_id: 42,
                }],
            },
            default_royalty: None,
        },
    );
    let drc721_supply: u64 = session
        .call(drc721, "total_supply", &(), GAS_LIMIT)
        .expect("query drc721 total supply")
        .data;
    assert_eq!(drc721_supply, 1);
    let owner: Principal = session
        .call(drc721, "owner_of", &OwnerOf { token_id: 42 }, GAS_LIMIT)
        .expect("query drc721 owner")
        .data;
    assert_eq!(owner, admin);
    let tokens: Vec<u64> = session
        .call(drc721, "tokens_of", &TokensOf { owner: admin }, GAS_LIMIT)
        .expect("query drc721 tokens")
        .data;
    assert_eq!(tokens, vec![42]);
    assert!(session
        .call::<_, ()>(
            drc721,
            "mint",
            &Drc721MintCall {
                to: admin,
                token_id: 43,
                authorization: None,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert!(session
        .call::<_, ()>(
            drc721,
            "pause",
            &Drc721AdminCall {
                authorization: None,
            },
            GAS_LIMIT,
        )
        .is_err());
    exercise_drc721_signed_calls(&mut session, drc721, admin);

    let proxy = deploy(
        &mut session,
        "proxy_counter.wasm",
        [22u8; 32],
        &ProxyCounterInit {
            admin,
            implementation: ContractId::from_bytes([99u8; 32]),
            upgrade_delay: 0,
            rollback_window: 10,
        },
    );
    let value: u64 = session
        .call(proxy, "value", &(), GAS_LIMIT)
        .expect("query proxy value")
        .data;
    assert_eq!(value, 0);
    let implementation: ContractId = session
        .call(proxy, "implementation", &(), GAS_LIMIT)
        .expect("query proxy implementation")
        .data;
    assert_eq!(implementation, ContractId::from_bytes([99u8; 32]));
    assert!(session
        .call::<_, ()>(
            proxy,
            "set_value",
            &ProxySetValue {
                value: 7,
                authorization: None,
            },
            GAS_LIMIT,
        )
        .is_err());
    exercise_proxy_signed_admin_call(&mut session, proxy, admin);
}

fn exercise_drc20_signed_calls(
    session: &mut Session,
    contract: ContractId,
    admin: Principal,
) {
    let mut rng = StdRng::seed_from_u64(2222);
    let admin_sk = SchnorrSecretKey::from(JubJubScalar::from(7u64));
    let admin_pk = SchnorrPublicKey::from(&admin_sk);
    assert_eq!(admin, Principal::phoenix_public_key(&admin_pk));

    let mint_action = authorized_action(
        contract,
        admin,
        TOKEN_ADMIN_DOMAIN,
        MINT_ACTION,
        0,
        0,
        mint_payload_hash(admin, 5),
    );
    let mint_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        mint_action,
    ));
    session
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
    let supply: u64 = session
        .call(contract, "total_supply", &(), GAS_LIMIT)
        .expect("query drc20 supply")
        .data;
    assert_eq!(supply, 1_005);
    assert_contract_nonce(session, contract, admin, TOKEN_ADMIN_DOMAIN, 1);
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

    let bad_mint_action = authorized_action(
        contract,
        admin,
        TOKEN_ADMIN_DOMAIN,
        MINT_ACTION,
        1,
        0,
        mint_payload_hash(admin, 9),
    );
    assert!(session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc20MintCall {
                to: admin,
                amount: 8,
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(
                        &mut rng,
                        &admin_sk,
                        admin_pk,
                        bad_mint_action,
                    ),
                )),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_contract_nonce(session, contract, admin, TOKEN_ADMIN_DOMAIN, 1);

    let spender_sk = moonlight_secret(30);
    let spender_pk = BlsPublicKey::from(&spender_sk);
    let spender = Principal::moonlight(&spender_pk);

    let approve_action = authorized_action(
        contract,
        admin,
        SIGNED_APPROVE_DOMAIN,
        SIGNED_APPROVE_ACTION,
        0,
        0,
        approve_payload_hash(admin, spender, 33),
    );
    let approve_auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        approve_action,
    ));
    session
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
        .expect("approve by Phoenix authorization");
    let allowance: u64 = session
        .call(
            contract,
            "allowance",
            &Allowance {
                owner: admin,
                spender,
            },
            GAS_LIMIT,
        )
        .expect("query signed allowance")
        .data;
    assert_eq!(allowance, 33);
    assert_contract_nonce(session, contract, admin, SIGNED_APPROVE_DOMAIN, 1);
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

    let moonlight_owner_sk = moonlight_secret(31);
    let moonlight_owner_pk = BlsPublicKey::from(&moonlight_owner_sk);
    let moonlight_owner = Principal::moonlight(&moonlight_owner_pk);
    let moonlight_action = authorized_action(
        contract,
        moonlight_owner,
        SIGNED_APPROVE_DOMAIN,
        SIGNED_APPROVE_ACTION,
        0,
        0,
        approve_payload_hash(moonlight_owner, admin, 44),
    );
    session
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
                    moonlight_action,
                )),
            },
            GAS_LIMIT,
        )
        .expect("approve by Moonlight authorization");
    assert_contract_nonce(
        session,
        contract,
        moonlight_owner,
        SIGNED_APPROVE_DOMAIN,
        1,
    );

    let pause_action = authorized_action(
        contract,
        admin,
        TOKEN_ADMIN_DOMAIN,
        PAUSE_ACTION,
        1,
        0,
        empty_payload_hash(b"drc20.pause"),
    );
    session
        .call::<_, ()>(
            contract,
            "pause",
            &Drc20AdminCall {
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(&mut rng, &admin_sk, admin_pk, pause_action),
                )),
            },
            GAS_LIMIT,
        )
        .expect("pause by signed Phoenix admin");
    let paused: bool = session
        .call(contract, "paused", &(), GAS_LIMIT)
        .expect("query drc20 paused")
        .data;
    assert!(paused);
    assert_contract_nonce(session, contract, admin, TOKEN_ADMIN_DOMAIN, 2);

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
            0,
            mint_payload_hash(admin, 6),
        ),
    ));
    assert!(session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc20MintCall {
                to: admin,
                amount: 6,
                authorization: Some(paused_mint),
            },
            GAS_LIMIT,
        )
        .is_err());
    assert!(session
        .call::<_, ()>(contract, "burn", &1u64, GAS_LIMIT)
        .is_err());
    assert_contract_nonce(session, contract, admin, TOKEN_ADMIN_DOMAIN, 2);

    let unpause_action = authorized_action(
        contract,
        admin,
        TOKEN_ADMIN_DOMAIN,
        UNPAUSE_ACTION,
        2,
        0,
        empty_payload_hash(b"drc20.unpause"),
    );
    session
        .call::<_, ()>(
            contract,
            "unpause",
            &Drc20AdminCall {
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(&mut rng, &admin_sk, admin_pk, unpause_action),
                )),
            },
            GAS_LIMIT,
        )
        .expect("unpause by signed Phoenix admin");
    let paused: bool = session
        .call(contract, "paused", &(), GAS_LIMIT)
        .expect("query drc20 unpaused")
        .data;
    assert!(!paused);
    assert_contract_nonce(session, contract, admin, TOKEN_ADMIN_DOMAIN, 3);
}

fn exercise_drc721_signed_calls(
    session: &mut Session,
    contract: ContractId,
    admin: Principal,
) {
    let mut rng = StdRng::seed_from_u64(4444);
    let admin_sk = SchnorrSecretKey::from(JubJubScalar::from(7u64));
    let admin_pk = SchnorrPublicKey::from(&admin_sk);
    assert_eq!(admin, Principal::phoenix_public_key(&admin_pk));

    let mint_action = authorized_action(
        contract,
        admin,
        NFT_ADMIN_DOMAIN,
        NFT_MINT_ACTION,
        0,
        0,
        nft_mint_payload_hash(admin, 43),
    );
    session
        .call::<_, ()>(
            contract,
            "mint",
            &Drc721MintCall {
                to: admin,
                token_id: 43,
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(&mut rng, &admin_sk, admin_pk, mint_action),
                )),
            },
            GAS_LIMIT,
        )
        .expect("mint NFT by signed Phoenix owner");
    let owner: Principal = session
        .call(contract, "owner_of", &OwnerOf { token_id: 43 }, GAS_LIMIT)
        .expect("query signed NFT mint owner")
        .data;
    assert_eq!(owner, admin);
    assert_contract_nonce(session, contract, admin, NFT_ADMIN_DOMAIN, 1);

    let pause_action = authorized_action(
        contract,
        admin,
        NFT_ADMIN_DOMAIN,
        NFT_PAUSE_ACTION,
        1,
        0,
        empty_payload_hash(b"drc721.pause"),
    );
    session
        .call::<_, ()>(
            contract,
            "pause",
            &Drc721AdminCall {
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(&mut rng, &admin_sk, admin_pk, pause_action),
                )),
            },
            GAS_LIMIT,
        )
        .expect("pause NFT by signed Phoenix owner");
    let paused: bool = session
        .call(contract, "paused", &(), GAS_LIMIT)
        .expect("query drc721 paused")
        .data;
    assert!(paused);
    assert_contract_nonce(session, contract, admin, NFT_ADMIN_DOMAIN, 2);

    let paused_mint = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng,
        &admin_sk,
        admin_pk,
        authorized_action(
            contract,
            admin,
            NFT_ADMIN_DOMAIN,
            NFT_MINT_ACTION,
            2,
            0,
            nft_mint_payload_hash(admin, 44),
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
    assert!(session
        .call::<_, ()>(contract, "burn", &43u64, GAS_LIMIT)
        .is_err());
    assert_contract_nonce(session, contract, admin, NFT_ADMIN_DOMAIN, 2);

    let unpause_action = authorized_action(
        contract,
        admin,
        NFT_ADMIN_DOMAIN,
        NFT_UNPAUSE_ACTION,
        2,
        0,
        empty_payload_hash(b"drc721.unpause"),
    );
    session
        .call::<_, ()>(
            contract,
            "unpause",
            &Drc721AdminCall {
                authorization: Some(SignedAuthorization::Phoenix(
                    phoenix_auth(&mut rng, &admin_sk, admin_pk, unpause_action),
                )),
            },
            GAS_LIMIT,
        )
        .expect("unpause NFT by signed Phoenix owner");
    let paused: bool = session
        .call(contract, "paused", &(), GAS_LIMIT)
        .expect("query drc721 unpaused")
        .data;
    assert!(!paused);
    assert_contract_nonce(session, contract, admin, NFT_ADMIN_DOMAIN, 3);
}

fn exercise_proxy_signed_admin_call(
    session: &mut Session,
    contract: ContractId,
    admin: Principal,
) {
    let mut rng = StdRng::seed_from_u64(3333);
    let admin_sk = SchnorrSecretKey::from(JubJubScalar::from(7u64));
    let admin_pk = SchnorrPublicKey::from(&admin_sk);
    let action = authorized_action(
        contract,
        admin,
        PROXY_ADMIN_DOMAIN,
        SET_PROXY_VALUE_ACTION,
        0,
        0,
        proxy_value_payload_hash(7),
    );
    let auth = SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng, &admin_sk, admin_pk, action,
    ));
    session
        .call::<_, ()>(
            contract,
            "set_value",
            &ProxySetValue {
                value: 7,
                authorization: Some(auth.clone()),
            },
            GAS_LIMIT,
        )
        .expect("set proxy value by signed admin");
    let value: u64 = session
        .call(contract, "value", &(), GAS_LIMIT)
        .expect("query proxy value after signed set")
        .data;
    assert_eq!(value, 7);
    assert_contract_nonce(session, contract, admin, PROXY_ADMIN_DOMAIN, 1);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value",
            &ProxySetValue {
                value: 7,
                authorization: Some(auth),
            },
            GAS_LIMIT,
        )
        .is_err());
}

fn exercise_authorization_counter_signed_calls(
    session: &mut Session,
    contract: ContractId,
) {
    let moonlight_sk = moonlight_secret(7);
    let moonlight_pk = BlsPublicKey::from(&moonlight_sk);
    let moonlight = Principal::moonlight(&moonlight_pk);

    let moonlight_action =
        counter_action(contract, moonlight, 0, 0, SET_VALUE_ACTION, 11);
    let moonlight_auth_0 =
        moonlight_auth(&moonlight_sk, moonlight_pk, moonlight_action);
    session
        .call::<_, ()>(
            contract,
            "set_value_by_moonlight",
            &SetValueByMoonlight {
                authorization: moonlight_auth_0.clone(),
                amount: 11,
            },
            GAS_LIMIT,
        )
        .expect("set counter by Moonlight signature");
    assert_counter(session, contract, 11, Some(moonlight), moonlight, 1);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_moonlight",
            &SetValueByMoonlight {
                authorization: moonlight_auth_0,
                amount: 11,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_counter(session, contract, 11, Some(moonlight), moonlight, 1);

    let bad_payload_action =
        counter_action(contract, moonlight, 1, 0, SET_VALUE_ACTION, 12);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_moonlight",
            &SetValueByMoonlight {
                authorization: moonlight_auth(
                    &moonlight_sk,
                    moonlight_pk,
                    bad_payload_action,
                ),
                amount: 13,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_nonce(session, contract, moonlight, 1);

    let valid_action =
        counter_action(contract, moonlight, 1, 0, SET_VALUE_ACTION, 12);
    let wrong_moonlight_sk = moonlight_secret(8);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_moonlight",
            &SetValueByMoonlight {
                authorization: MoonlightAuthorization {
                    action: valid_action,
                    public_key: moonlight_pk,
                    signature: wrong_moonlight_sk
                        .sign(&valid_action.message_bytes()),
                },
                amount: 12,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_nonce(session, contract, moonlight, 1);

    let wrong_contract_action = counter_action(
        ContractId::from_bytes([99u8; 32]),
        moonlight,
        1,
        0,
        SET_VALUE_ACTION,
        12,
    );
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_moonlight",
            &SetValueByMoonlight {
                authorization: moonlight_auth(
                    &moonlight_sk,
                    moonlight_pk,
                    wrong_contract_action,
                ),
                amount: 12,
            },
            GAS_LIMIT,
        )
        .is_err());

    let wrong_action = counter_action(contract, moonlight, 1, 0, [9u8; 32], 12);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_moonlight",
            &SetValueByMoonlight {
                authorization: moonlight_auth(
                    &moonlight_sk,
                    moonlight_pk,
                    wrong_action,
                ),
                amount: 12,
            },
            GAS_LIMIT,
        )
        .is_err());

    session
        .set_meta(Metadata::BLOCK_HEIGHT, 10u64)
        .expect("set VM block height");
    let expired_action =
        counter_action(contract, moonlight, 1, 9, SET_VALUE_ACTION, 12);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_moonlight",
            &SetValueByMoonlight {
                authorization: moonlight_auth(
                    &moonlight_sk,
                    moonlight_pk,
                    expired_action,
                ),
                amount: 12,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_nonce(session, contract, moonlight, 1);

    session
        .call::<_, ()>(
            contract,
            "set_value_by_moonlight",
            &SetValueByMoonlight {
                authorization: moonlight_auth(
                    &moonlight_sk,
                    moonlight_pk,
                    valid_action,
                ),
                amount: 12,
            },
            GAS_LIMIT,
        )
        .expect("set counter by second Moonlight signature");
    assert_counter(session, contract, 12, Some(moonlight), moonlight, 2);

    let mut rng = StdRng::seed_from_u64(1234);
    let phoenix_sk = SchnorrSecretKey::from(JubJubScalar::from(88u64));
    let phoenix_pk = SchnorrPublicKey::from(&phoenix_sk);
    let phoenix = Principal::phoenix_public_key(&phoenix_pk);

    let phoenix_action =
        counter_action(contract, phoenix, 0, 0, SET_VALUE_ACTION, 21);
    let phoenix_auth_0 =
        phoenix_auth(&mut rng, &phoenix_sk, phoenix_pk, phoenix_action);
    session
        .call::<_, ()>(
            contract,
            "set_value_by_phoenix",
            &SetValueByPhoenix {
                authorization: phoenix_auth_0.clone(),
                amount: 21,
            },
            GAS_LIMIT,
        )
        .expect("set counter by Phoenix signature");
    assert_counter(session, contract, 21, Some(phoenix), phoenix, 1);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_phoenix",
            &SetValueByPhoenix {
                authorization: phoenix_auth_0,
                amount: 21,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_counter(session, contract, 21, Some(phoenix), phoenix, 1);

    let bad_payload_action =
        counter_action(contract, phoenix, 1, 0, SET_VALUE_ACTION, 22);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_phoenix",
            &SetValueByPhoenix {
                authorization: phoenix_auth(
                    &mut rng,
                    &phoenix_sk,
                    phoenix_pk,
                    bad_payload_action,
                ),
                amount: 23,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_nonce(session, contract, phoenix, 1);

    let valid_phoenix_action =
        counter_action(contract, phoenix, 1, 0, SET_VALUE_ACTION, 22);
    let wrong_phoenix_sk = SchnorrSecretKey::from(JubJubScalar::from(89u64));
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_phoenix",
            &SetValueByPhoenix {
                authorization: PhoenixSignatureAuthorization {
                    action: valid_phoenix_action,
                    public_key: phoenix_pk,
                    signature: wrong_phoenix_sk
                        .sign(&mut rng, valid_phoenix_action.message_hash()),
                    replay_key: None,
                },
                amount: 22,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_nonce(session, contract, phoenix, 1);

    let wrong_phoenix_pk = SchnorrPublicKey::from(&wrong_phoenix_sk);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_phoenix",
            &SetValueByPhoenix {
                authorization: phoenix_auth(
                    &mut rng,
                    &wrong_phoenix_sk,
                    wrong_phoenix_pk,
                    valid_phoenix_action,
                ),
                amount: 22,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_nonce(session, contract, phoenix, 1);

    let wrong_contract_action = counter_action(
        ContractId::from_bytes([98u8; 32]),
        phoenix,
        1,
        0,
        SET_VALUE_ACTION,
        22,
    );
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_phoenix",
            &SetValueByPhoenix {
                authorization: phoenix_auth(
                    &mut rng,
                    &phoenix_sk,
                    phoenix_pk,
                    wrong_contract_action,
                ),
                amount: 22,
            },
            GAS_LIMIT,
        )
        .is_err());

    let wrong_action = counter_action(contract, phoenix, 1, 0, [8u8; 32], 22);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_phoenix",
            &SetValueByPhoenix {
                authorization: phoenix_auth(
                    &mut rng,
                    &phoenix_sk,
                    phoenix_pk,
                    wrong_action,
                ),
                amount: 22,
            },
            GAS_LIMIT,
        )
        .is_err());

    let expired_action =
        counter_action(contract, phoenix, 1, 9, SET_VALUE_ACTION, 22);
    assert!(session
        .call::<_, ()>(
            contract,
            "set_value_by_phoenix",
            &SetValueByPhoenix {
                authorization: phoenix_auth(
                    &mut rng,
                    &phoenix_sk,
                    phoenix_pk,
                    expired_action,
                ),
                amount: 22,
            },
            GAS_LIMIT,
        )
        .is_err());
    assert_nonce(session, contract, phoenix, 1);

    session
        .call::<_, ()>(
            contract,
            "set_value_by_phoenix",
            &SetValueByPhoenix {
                authorization: phoenix_auth(
                    &mut rng,
                    &phoenix_sk,
                    phoenix_pk,
                    valid_phoenix_action,
                ),
                amount: 22,
            },
            GAS_LIMIT,
        )
        .expect("set counter by second Phoenix signature");
    assert_counter(session, contract, 22, Some(phoenix), phoenix, 2);
}

fn counter_action(
    contract: ContractId,
    principal: Principal,
    nonce: u64,
    expires_at: u64,
    action_id: [u8; 32],
    amount: u64,
) -> AuthorizedAction {
    authorized_action(
        contract,
        principal,
        SET_VALUE_DOMAIN,
        action_id,
        nonce,
        expires_at,
        amount_hash(amount),
    )
}

fn authorized_action(
    contract: ContractId,
    principal: Principal,
    domain: NonceDomain,
    action_id: [u8; 32],
    nonce: u64,
    expires_at: u64,
    payload_hash: [u8; 32],
) -> AuthorizedAction {
    AuthorizedAction {
        contract,
        domain,
        action_id,
        nonce,
        expires_at,
        principal,
        payload_hash,
    }
}

fn moonlight_auth(
    secret_key: &BlsSecretKey,
    public_key: BlsPublicKey,
    action: AuthorizedAction,
) -> MoonlightAuthorization {
    let signature = secret_key.sign(&action.message_bytes());
    assert!(host_queries::verify_bls(
        action.message_bytes(),
        public_key,
        signature
    ));
    MoonlightAuthorization {
        action,
        public_key,
        signature,
    }
}

fn moonlight_secret(seed: u64) -> BlsSecretKey {
    let mut rng = StdRng::seed_from_u64(seed);
    BlsSecretKey::random(&mut rng)
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

fn assert_counter(
    session: &mut Session,
    contract: ContractId,
    value: u64,
    last_authorizer: Option<Principal>,
    principal: Principal,
    nonce: u64,
) {
    let actual_value: u64 = session
        .call(contract, "value", &(), GAS_LIMIT)
        .expect("query authorization counter value")
        .data;
    assert_eq!(actual_value, value);
    let actual_authorizer: Option<Principal> = session
        .call(contract, "last_authorizer", &(), GAS_LIMIT)
        .expect("query authorization counter last authorizer")
        .data;
    assert_eq!(actual_authorizer, last_authorizer);
    assert_nonce(session, contract, principal, nonce);
}

fn assert_nonce(
    session: &mut Session,
    contract: ContractId,
    principal: Principal,
    nonce: u64,
) {
    assert_contract_nonce(
        session,
        contract,
        principal,
        SET_VALUE_DOMAIN,
        nonce,
    );
}

fn assert_contract_nonce(
    session: &mut Session,
    contract: ContractId,
    principal: Principal,
    domain: NonceDomain,
    nonce: u64,
) {
    let actual_nonce: u64 = session
        .call(
            contract,
            "nonce",
            &NonceQuery { principal, domain },
            GAS_LIMIT,
        )
        .expect("query contract nonce")
        .data;
    assert_eq!(actual_nonce, nonce);
}

fn amount_hash(amount: u64) -> [u8; 32] {
    host_queries::keccak256(Vec::from(amount.to_be_bytes()))
}

fn mint_payload_hash(to: Principal, amount: u64) -> [u8; 32] {
    let mut bytes = Vec::from(&b"drc20.mint"[..]);
    push_principal(&mut bytes, to);
    bytes.extend_from_slice(&amount.to_be_bytes());
    host_queries::keccak256(bytes)
}

fn nft_mint_payload_hash(to: Principal, token_id: u64) -> [u8; 32] {
    let mut bytes = Vec::from(&b"drc721.mint"[..]);
    push_principal(&mut bytes, to);
    bytes.extend_from_slice(&token_id.to_be_bytes());
    host_queries::keccak256(bytes)
}

fn empty_payload_hash(tag: &[u8]) -> [u8; 32] {
    host_queries::keccak256(Vec::from(tag))
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

fn proxy_value_payload_hash(value: u64) -> [u8; 32] {
    let mut bytes = Vec::from(&b"proxy.value"[..]);
    bytes.extend_from_slice(&value.to_be_bytes());
    host_queries::keccak256(bytes)
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

fn deploy<A>(
    session: &mut Session,
    wasm_name: &str,
    contract_id: [u8; 32],
    init: &A,
) -> ContractId
where
    A: for<'a> Serialize<dusk_core::abi::StandardBufSerializer<'a>>,
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
