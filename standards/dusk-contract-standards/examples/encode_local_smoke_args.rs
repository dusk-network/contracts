use std::env;
use std::error::Error;
use std::string::String;
use std::vec::Vec;

use bytecheck::CheckBytes;
use dusk_contract_standards::auth::{
    AuthorizedAction, MoonlightAuthorization, PhoenixSignatureAuthorization,
    SignedAuthorization,
};
use dusk_contract_standards::core::Principal;
use dusk_contract_standards::governance::{
    MultisigControllerConfig, MultisigOperationId, MultisigTarget,
};
use dusk_contract_standards::token::drc20::{
    Init as Drc20TokenInit, InitBalance as Drc20InitBalance,
};
use dusk_contract_standards::token::drc721::{
    Init as Drc721TokenInit, InitToken as Drc721InitToken, IsApprovedForAll,
    SignedApproveCall as Drc721SignedApproveCall,
    SignedSetApprovalForAllCall as Drc721SignedSetApprovalForAllCall,
};
use dusk_core::abi::{ContractId, StandardBufSerializer, ARGBUF_LEN};
use dusk_core::signatures::bls::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey,
};
use dusk_core::signatures::schnorr::{
    PublicKey as SchnorrPublicKey, SecretKey as SchnorrSecretKey,
};
use dusk_core::transfer::data::ContractCall;
use dusk_core::JubJubScalar;
use dusk_vm::host_queries;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rkyv::ser::serializers::{
    BufferScratch, BufferSerializer, CompositeSerializer,
};
use rkyv::ser::Serializer;
use rkyv::{Archive, Deserialize, Infallible, Serialize};

const SCRATCH_BUF_BYTES: usize = 1024;
const SET_VALUE_DOMAIN: [u8; 32] = [3u8; 32];
const SET_VALUE_ACTION: [u8; 32] = [4u8; 32];
const TOKEN_ADMIN_DOMAIN: [u8; 32] = [11u8; 32];
const MINT_ACTION: [u8; 32] = [13u8; 32];
const PAUSE_ACTION: [u8; 32] = [14u8; 32];
const UNPAUSE_ACTION: [u8; 32] = [15u8; 32];
const NFT_ADMIN_DOMAIN: [u8; 32] = [21u8; 32];
const NFT_MINT_ACTION: [u8; 32] = [22u8; 32];
const NFT_PAUSE_ACTION: [u8; 32] = [23u8; 32];
const NFT_UNPAUSE_ACTION: [u8; 32] = [24u8; 32];
const NFT_SIGNED_APPROVE_DOMAIN: [u8; 32] = [29u8; 32];
const NFT_SIGNED_APPROVE_ACTION: [u8; 32] = [30u8; 32];
const NFT_SIGNED_APPROVAL_FOR_ALL_ACTION: [u8; 32] = [31u8; 32];
const PROXY_ADMIN_DOMAIN: [u8; 32] = [31u8; 32];
const SET_PROXY_VALUE_ACTION: [u8; 32] = [32u8; 32];
const MULTISIG_CONTROLLER_DOMAIN: [u8; 32] = [41u8; 32];
const MULTISIG_PROPOSE_ACTION: [u8; 32] = [42u8; 32];
const MULTISIG_CONFIRM_ACTION: [u8; 32] = [43u8; 32];

#[derive(Archive, Serialize, Deserialize)]
struct Drc20ExampleInit {
    admin: Principal,
    token: Drc20TokenInit,
    cap: u64,
}

#[derive(Archive, Serialize, Deserialize)]
struct Drc721ExampleInit {
    owner: Principal,
    token: Drc721TokenInit,
    default_royalty:
        Option<dusk_contract_standards::token::drc721::RoyaltyInfo>,
}

#[derive(Archive, Serialize, Deserialize)]
struct ProxyCounterInit {
    admin: Principal,
    implementation: ContractId,
    upgrade_delay: u64,
    rollback_window: u64,
}

#[derive(Archive, Serialize, Deserialize)]
struct MultisigInit {
    config: MultisigControllerConfig,
}

#[derive(Archive, Serialize, Deserialize)]
struct SetValueByMoonlight {
    authorization: MoonlightAuthorization,
    amount: u64,
}

#[derive(Archive, Serialize, Deserialize)]
struct SetValueByPhoenix {
    authorization: PhoenixSignatureAuthorization,
    amount: u64,
}

#[derive(Archive, Serialize, Deserialize)]
struct NonceQuery {
    principal: Principal,
    domain: [u8; 32],
}

#[derive(Archive, Serialize, Deserialize)]
struct Drc20MintCall {
    to: Principal,
    amount: u64,
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize)]
struct Drc20AdminCall {
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize)]
struct Drc721MintCall {
    to: Principal,
    token_id: u64,
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize)]
struct Drc721AdminCall {
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
struct ProxySetValue {
    value: u64,
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize)]
struct MultisigPropose {
    target: MultisigTarget,
    authorization: Option<SignedAuthorization>,
}

#[derive(Archive, Serialize, Deserialize)]
struct MultisigConfirm {
    id: MultisigOperationId,
    authorization: Option<SignedAuthorization>,
}

struct AdminPhoenixAction {
    contract: ContractId,
    admin: Principal,
    domain: [u8; 32],
    action_id: [u8; 32],
    nonce: u64,
    expires_at: u64,
    payload_hash: [u8; 32],
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    let Some(command) = args.get(1).map(String::as_str) else {
        eprintln!(
            "usage: encode_local_smoke_args <drc20-init|drc721-init|multisig-init|proxy-init|proxy-init-contract|unit|u64|nonce|auth-counter-phoenix|auth-counter-moonlight|drc20-mint|drc20-admin|drc721-mint|drc721-admin|drc721-approve|drc721-operator-approval|drc721-operator-query|proxy-set|proxy-set-no-auth|multisig-target|multisig-propose|multisig-confirm>"
        );
        std::process::exit(2);
    };

    let admin = phoenix_principal(1);
    let bytes = match command {
        "drc20-init" => encode(&Drc20ExampleInit {
            admin,
            token: Drc20TokenInit {
                name: String::from("Local Dusk Token"),
                symbol: String::from("LDUSK"),
                decimals: 9,
                initial_balances: vec![Drc20InitBalance {
                    account: admin,
                    amount: 1_000,
                }],
            },
            cap: 10_000_000,
        })?,
        "drc721-init" => encode(&Drc721ExampleInit {
            owner: admin,
            token: Drc721TokenInit {
                name: String::from("Local Dusk Collection"),
                symbol: String::from("LDNFT"),
                base_uri: String::from("ipfs://local/"),
                initial_tokens: vec![Drc721InitToken {
                    account: admin,
                    token_id: 1,
                }],
            },
            default_royalty: None,
        })?,
        "proxy-init" => encode(&ProxyCounterInit {
            admin,
            implementation: ContractId::from_bytes([9u8; 32]),
            upgrade_delay: 0,
            rollback_window: 10,
        })?,
        "multisig-init" => encode(&MultisigInit {
            config: MultisigControllerConfig {
                owners: vec![admin, phoenix_principal(2), phoenix_principal(3)],
                threshold: 2,
                proposal_ttl: 10,
                tombstone_ttl: 6,
            },
        })?,
        "proxy-init-contract" => encode(&ProxyCounterInit {
            admin: Principal::contract(contract_arg(&args, 2)?),
            implementation: ContractId::from_bytes([9u8; 32]),
            upgrade_delay: 0,
            rollback_window: 10,
        })?,
        "unit" => encode(&())?,
        "u64" => encode(&parse_u64_arg(&args, 2, "value")?)?,
        "nonce" => encode(&NonceQuery {
            principal: principal_arg(&args, 3)?,
            domain: domain_arg(&args, 2)?,
        })?,
        "auth-counter-phoenix" => encode(&counter_phoenix_call(&args)?)?,
        "auth-counter-moonlight" => encode(&counter_moonlight_call(&args)?)?,
        "drc20-mint" => encode(&drc20_mint_call(&args, admin)?)?,
        "drc20-admin" => encode(&drc20_admin_call(&args, admin)?)?,
        "drc721-mint" => encode(&drc721_mint_call(&args, admin)?)?,
        "drc721-admin" => encode(&drc721_admin_call(&args, admin)?)?,
        "drc721-approve" => encode(&drc721_approve_call(&args, admin)?)?,
        "drc721-operator-approval" => {
            encode(&drc721_operator_approval_call(&args, admin)?)?
        }
        "drc721-operator-query" => encode(&IsApprovedForAll {
            owner: admin,
            operator: drc721_operator_principal(),
        })?,
        "proxy-set" => encode(&proxy_set_call(&args, admin)?)?,
        "proxy-set-no-auth" => encode(&ProxySetValue {
            value: parse_u64_arg(&args, 2, "value")?,
            authorization: None,
        })?,
        "multisig-target" => encode(&multisig_target_arg(&args, 2, 3, 4)?)?,
        "multisig-propose" => encode(&multisig_propose_call(&args)?)?,
        "multisig-confirm" => encode(&multisig_confirm_call(&args)?)?,
        _ => {
            eprintln!("unknown command: {command}");
            std::process::exit(2);
        }
    };

    print_hex(&bytes);
    Ok(())
}

fn counter_phoenix_call(
    args: &[String],
) -> Result<SetValueByPhoenix, Box<dyn Error>> {
    let contract = contract_arg(args, 2)?;
    let nonce = parse_u64_arg(args, 3, "nonce")?;
    let expires_at = parse_u64_arg(args, 4, "expires_at")?;
    let amount = parse_u64_arg(args, 5, "amount")?;
    let variant = variant_arg(args);
    let secret = SchnorrSecretKey::from(JubJubScalar::from(88u64));
    let public = SchnorrPublicKey::from(&secret);
    let principal = Principal::phoenix_public_key(&public);
    let action = counter_action(
        contract_for_variant(contract, variant),
        principal,
        nonce,
        expires_at,
        action_for_variant(SET_VALUE_ACTION, variant),
        payload_amount_for_variant(amount, variant),
    );
    let mut rng = StdRng::seed_from_u64(12_345 + nonce);
    Ok(SetValueByPhoenix {
        authorization: phoenix_auth(&mut rng, &secret, public, action),
        amount,
    })
}

fn counter_moonlight_call(
    args: &[String],
) -> Result<SetValueByMoonlight, Box<dyn Error>> {
    let contract = contract_arg(args, 2)?;
    let nonce = parse_u64_arg(args, 3, "nonce")?;
    let expires_at = parse_u64_arg(args, 4, "expires_at")?;
    let amount = parse_u64_arg(args, 5, "amount")?;
    let variant = variant_arg(args);
    let secret = moonlight_secret(7);
    let public = BlsPublicKey::from(&secret);
    let principal = Principal::moonlight(&public);
    let action = counter_action(
        contract_for_variant(contract, variant),
        principal,
        nonce,
        expires_at,
        action_for_variant(SET_VALUE_ACTION, variant),
        payload_amount_for_variant(amount, variant),
    );
    Ok(SetValueByMoonlight {
        authorization: moonlight_auth(&secret, public, action),
        amount,
    })
}

fn drc20_mint_call(
    args: &[String],
    admin: Principal,
) -> Result<Drc20MintCall, Box<dyn Error>> {
    let contract = contract_arg(args, 2)?;
    let nonce = parse_u64_arg(args, 3, "nonce")?;
    let expires_at = parse_u64_arg(args, 4, "expires_at")?;
    let amount = parse_u64_arg(args, 5, "amount")?;
    let variant = variant_arg(args);
    let secret = SchnorrSecretKey::from(JubJubScalar::from(1u64));
    let public = SchnorrPublicKey::from(&secret);
    let payload_amount = payload_amount_for_variant(amount, variant);
    let action = authorized_action(
        contract_for_variant(contract, variant),
        admin,
        TOKEN_ADMIN_DOMAIN,
        action_for_variant(MINT_ACTION, variant),
        nonce,
        expires_at,
        mint_payload_hash(admin, payload_amount),
    );
    let mut rng = StdRng::seed_from_u64(22_222 + nonce);
    Ok(Drc20MintCall {
        to: admin,
        amount,
        authorization: Some(SignedAuthorization::Phoenix(phoenix_auth(
            &mut rng, &secret, public, action,
        ))),
    })
}

fn drc20_admin_call(
    args: &[String],
    admin: Principal,
) -> Result<Drc20AdminCall, Box<dyn Error>> {
    let action_name = arg(args, 2, "action")?;
    let contract = contract_arg(args, 3)?;
    let nonce = parse_u64_arg(args, 4, "nonce")?;
    let expires_at = parse_u64_arg(args, 5, "expires_at")?;
    let variant = variant_arg(args);
    let (action_id, tag) = match action_name {
        "pause" => (PAUSE_ACTION, b"drc20.pause".as_slice()),
        "unpause" => (UNPAUSE_ACTION, b"drc20.unpause".as_slice()),
        _ => {
            return Err(
                format!("unknown drc20 admin action: {action_name}").into()
            )
        }
    };
    Ok(Drc20AdminCall {
        authorization: Some(admin_phoenix_authorization(
            AdminPhoenixAction {
                contract,
                admin,
                domain: TOKEN_ADMIN_DOMAIN,
                action_id: action_for_variant(action_id, variant),
                nonce,
                expires_at,
                payload_hash: empty_payload_hash(tag),
            },
            variant,
        )),
    })
}

fn drc721_mint_call(
    args: &[String],
    admin: Principal,
) -> Result<Drc721MintCall, Box<dyn Error>> {
    let contract = contract_arg(args, 2)?;
    let nonce = parse_u64_arg(args, 3, "nonce")?;
    let expires_at = parse_u64_arg(args, 4, "expires_at")?;
    let token_id = parse_u64_arg(args, 5, "token_id")?;
    let variant = variant_arg(args);
    let payload_token_id = payload_amount_for_variant(token_id, variant);
    Ok(Drc721MintCall {
        to: admin,
        token_id,
        authorization: Some(admin_phoenix_authorization(
            AdminPhoenixAction {
                contract,
                admin,
                domain: NFT_ADMIN_DOMAIN,
                action_id: action_for_variant(NFT_MINT_ACTION, variant),
                nonce,
                expires_at,
                payload_hash: nft_mint_payload_hash(admin, payload_token_id),
            },
            variant,
        )),
    })
}

fn drc721_admin_call(
    args: &[String],
    admin: Principal,
) -> Result<Drc721AdminCall, Box<dyn Error>> {
    let action_name = arg(args, 2, "action")?;
    let contract = contract_arg(args, 3)?;
    let nonce = parse_u64_arg(args, 4, "nonce")?;
    let expires_at = parse_u64_arg(args, 5, "expires_at")?;
    let variant = variant_arg(args);
    let (action_id, tag) = match action_name {
        "pause" => (NFT_PAUSE_ACTION, b"drc721.pause".as_slice()),
        "unpause" => (NFT_UNPAUSE_ACTION, b"drc721.unpause".as_slice()),
        _ => {
            return Err(
                format!("unknown drc721 admin action: {action_name}").into()
            )
        }
    };
    Ok(Drc721AdminCall {
        authorization: Some(admin_phoenix_authorization(
            AdminPhoenixAction {
                contract,
                admin,
                domain: NFT_ADMIN_DOMAIN,
                action_id: action_for_variant(action_id, variant),
                nonce,
                expires_at,
                payload_hash: empty_payload_hash(tag),
            },
            variant,
        )),
    })
}

fn drc721_approve_call(
    args: &[String],
    admin: Principal,
) -> Result<Drc721SignedApproveCall, Box<dyn Error>> {
    let contract = contract_arg(args, 2)?;
    let nonce = parse_u64_arg(args, 3, "nonce")?;
    let expires_at = parse_u64_arg(args, 4, "expires_at")?;
    let token_id = parse_u64_arg(args, 5, "token_id")?;
    let variant = variant_arg(args);
    let approved = drc721_approved_principal();
    let payload_token_id = payload_amount_for_variant(token_id, variant);
    Ok(Drc721SignedApproveCall {
        owner: admin,
        approved,
        token_id,
        authorization: admin_phoenix_authorization(
            AdminPhoenixAction {
                contract,
                admin,
                domain: NFT_SIGNED_APPROVE_DOMAIN,
                action_id: action_for_variant(
                    NFT_SIGNED_APPROVE_ACTION,
                    variant,
                ),
                nonce,
                expires_at,
                payload_hash: nft_approve_payload_hash(
                    admin,
                    approved,
                    payload_token_id,
                ),
            },
            variant,
        ),
    })
}

fn drc721_operator_approval_call(
    args: &[String],
    admin: Principal,
) -> Result<Drc721SignedSetApprovalForAllCall, Box<dyn Error>> {
    let contract = contract_arg(args, 2)?;
    let nonce = parse_u64_arg(args, 3, "nonce")?;
    let expires_at = parse_u64_arg(args, 4, "expires_at")?;
    let approved = parse_bool_arg(args, 5, "approved")?;
    let variant = variant_arg(args);
    let operator = drc721_operator_principal();
    let payload_approved = payload_bool_for_variant(approved, variant);
    Ok(Drc721SignedSetApprovalForAllCall {
        owner: admin,
        operator,
        approved,
        authorization: admin_phoenix_authorization(
            AdminPhoenixAction {
                contract,
                admin,
                domain: NFT_SIGNED_APPROVE_DOMAIN,
                action_id: action_for_variant(
                    NFT_SIGNED_APPROVAL_FOR_ALL_ACTION,
                    variant,
                ),
                nonce,
                expires_at,
                payload_hash: nft_approval_for_all_payload_hash(
                    admin,
                    operator,
                    payload_approved,
                ),
            },
            variant,
        ),
    })
}

fn proxy_set_call(
    args: &[String],
    admin: Principal,
) -> Result<ProxySetValue, Box<dyn Error>> {
    let contract = contract_arg(args, 2)?;
    let nonce = parse_u64_arg(args, 3, "nonce")?;
    let expires_at = parse_u64_arg(args, 4, "expires_at")?;
    let value = parse_u64_arg(args, 5, "value")?;
    let variant = variant_arg(args);
    let payload_value = payload_amount_for_variant(value, variant);
    Ok(ProxySetValue {
        value,
        authorization: Some(admin_phoenix_authorization(
            AdminPhoenixAction {
                contract,
                admin,
                domain: PROXY_ADMIN_DOMAIN,
                action_id: action_for_variant(SET_PROXY_VALUE_ACTION, variant),
                nonce,
                expires_at,
                payload_hash: proxy_value_payload_hash(payload_value),
            },
            variant,
        )),
    })
}

fn multisig_propose_call(
    args: &[String],
) -> Result<MultisigPropose, Box<dyn Error>> {
    let multisig = contract_arg(args, 2)?;
    let owner_seed = parse_u64_arg(args, 4, "owner_seed")?;
    let nonce = parse_u64_arg(args, 5, "nonce")?;
    let expires_at = parse_u64_arg(args, 6, "expires_at")?;
    let id = parse_hex_32(arg(args, 9, "operation_id")?)?;
    let variant = args.get(10).map(String::as_str).unwrap_or("valid");
    let owner = phoenix_principal(owner_seed);
    let secret = SchnorrSecretKey::from(JubJubScalar::from(owner_seed));
    let public = SchnorrPublicKey::from(&secret);
    let action = authorized_action(
        multisig,
        owner,
        MULTISIG_CONTROLLER_DOMAIN,
        action_for_variant(MULTISIG_PROPOSE_ACTION, variant),
        nonce,
        expires_at,
        operation_id_for_variant(id, variant),
    );
    let mut rng = StdRng::seed_from_u64(44_444 + owner_seed + nonce);
    Ok(MultisigPropose {
        target: multisig_target_arg(args, 3, 7, 8)?,
        authorization: Some(SignedAuthorization::Phoenix(phoenix_auth(
            &mut rng, &secret, public, action,
        ))),
    })
}

fn multisig_confirm_call(
    args: &[String],
) -> Result<MultisigConfirm, Box<dyn Error>> {
    let multisig = contract_arg(args, 2)?;
    let owner_seed = parse_u64_arg(args, 3, "owner_seed")?;
    let nonce = parse_u64_arg(args, 4, "nonce")?;
    let expires_at = parse_u64_arg(args, 5, "expires_at")?;
    let id = parse_hex_32(arg(args, 6, "operation_id")?)?;
    let variant = args.get(7).map(String::as_str).unwrap_or("valid");
    let owner = phoenix_principal(owner_seed);
    let secret = SchnorrSecretKey::from(JubJubScalar::from(owner_seed));
    let public = SchnorrPublicKey::from(&secret);
    let action = authorized_action(
        multisig,
        owner,
        MULTISIG_CONTROLLER_DOMAIN,
        action_for_variant(MULTISIG_CONFIRM_ACTION, variant),
        nonce,
        expires_at,
        operation_id_for_variant(id, variant),
    );
    let mut rng = StdRng::seed_from_u64(55_555 + owner_seed + nonce);
    Ok(MultisigConfirm {
        id,
        authorization: Some(SignedAuthorization::Phoenix(phoenix_auth(
            &mut rng, &secret, public, action,
        ))),
    })
}

fn multisig_target_arg(
    args: &[String],
    proxy_index: usize,
    value_index: usize,
    salt_index: usize,
) -> Result<MultisigTarget, Box<dyn Error>> {
    let proxy = contract_arg(args, proxy_index)?;
    let value = parse_u64_arg(args, value_index, "value")?;
    let salt_seed = parse_u8_arg(args, salt_index, "salt_seed")?;
    proxy_set_value_target(proxy, value, [salt_seed; 32])
}

fn proxy_set_value_target(
    proxy: ContractId,
    value: u64,
    salt: [u8; 32],
) -> Result<MultisigTarget, Box<dyn Error>> {
    Ok(MultisigTarget {
        call: ContractCall::new(proxy, "set_value")
            .with_args(&ProxySetValue {
                value,
                authorization: None,
            })
            .map_err(|e| format!("serialize proxy set_value target: {e:?}"))?,
        salt,
    })
}

fn admin_phoenix_authorization(
    args: AdminPhoenixAction,
    variant: &str,
) -> SignedAuthorization {
    let secret = SchnorrSecretKey::from(JubJubScalar::from(1u64));
    let public = SchnorrPublicKey::from(&secret);
    let action = authorized_action(
        contract_for_variant(args.contract, variant),
        args.admin,
        args.domain,
        args.action_id,
        args.nonce,
        args.expires_at,
        args.payload_hash,
    );
    let mut rng = StdRng::seed_from_u64(33_333 + args.nonce);
    SignedAuthorization::Phoenix(phoenix_auth(
        &mut rng, &secret, public, action,
    ))
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
    domain: [u8; 32],
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

fn nft_approve_payload_hash(
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

fn nft_approval_for_all_payload_hash(
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

fn proxy_value_payload_hash(value: u64) -> [u8; 32] {
    let mut bytes = Vec::from(&b"proxy.value"[..]);
    bytes.extend_from_slice(&value.to_be_bytes());
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

fn moonlight_principal(seed: u64) -> Principal {
    let secret = moonlight_secret(seed);
    let public = BlsPublicKey::from(&secret);
    Principal::moonlight(&public)
}

fn moonlight_secret(seed: u64) -> BlsSecretKey {
    let mut rng = StdRng::seed_from_u64(seed);
    BlsSecretKey::random(&mut rng)
}

fn contract_for_variant(contract: ContractId, variant: &str) -> ContractId {
    if variant == "wrong-contract" {
        ContractId::from_bytes([0xee; 32])
    } else {
        contract
    }
}

fn action_for_variant(action_id: [u8; 32], variant: &str) -> [u8; 32] {
    if variant == "wrong-action" {
        [0xaa; 32]
    } else {
        action_id
    }
}

fn payload_amount_for_variant(amount: u64, variant: &str) -> u64 {
    if variant == "bad-payload" {
        amount.saturating_add(1)
    } else {
        amount
    }
}

fn payload_bool_for_variant(value: bool, variant: &str) -> bool {
    if variant == "bad-payload" {
        !value
    } else {
        value
    }
}

fn operation_id_for_variant(
    id: MultisigOperationId,
    variant: &str,
) -> MultisigOperationId {
    if variant == "bad-payload" {
        [0xee; 32]
    } else {
        id
    }
}

fn variant_arg(args: &[String]) -> &str {
    args.get(6).map(String::as_str).unwrap_or("valid")
}

fn arg<'a>(
    args: &'a [String],
    index: usize,
    name: &str,
) -> Result<&'a str, Box<dyn Error>> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}").into())
}

fn parse_u64_arg(
    args: &[String],
    index: usize,
    name: &str,
) -> Result<u64, Box<dyn Error>> {
    arg(args, index, name)?
        .parse::<u64>()
        .map_err(|e| format!("invalid {name}: {e}").into())
}

fn parse_u8_arg(
    args: &[String],
    index: usize,
    name: &str,
) -> Result<u8, Box<dyn Error>> {
    arg(args, index, name)?
        .parse::<u8>()
        .map_err(|e| format!("invalid {name}: {e}").into())
}

fn contract_arg(
    args: &[String],
    index: usize,
) -> Result<ContractId, Box<dyn Error>> {
    Ok(ContractId::from_bytes(parse_hex_32(arg(
        args, index, "contract",
    )?)?))
}

fn principal_arg(
    args: &[String],
    index: usize,
) -> Result<Principal, Box<dyn Error>> {
    let kind = arg(args, index, "principal kind")?;
    let seed = parse_u64_arg(args, index + 1, "principal seed")?;
    match kind {
        "phoenix" => Ok(phoenix_principal(seed)),
        "moonlight" => Ok(moonlight_principal(seed)),
        _ => Err(format!("unknown principal kind: {kind}").into()),
    }
}

fn parse_bool_arg(
    args: &[String],
    index: usize,
    name: &str,
) -> Result<bool, Box<dyn Error>> {
    match arg(args, index, name)? {
        "true" => Ok(true),
        "false" => Ok(false),
        value => Err(format!("invalid {name}: {value}").into()),
    }
}

fn domain_arg(
    args: &[String],
    index: usize,
) -> Result<[u8; 32], Box<dyn Error>> {
    match arg(args, index, "domain")? {
        "counter" => Ok(SET_VALUE_DOMAIN),
        "drc20-admin" => Ok(TOKEN_ADMIN_DOMAIN),
        "drc721-admin" => Ok(NFT_ADMIN_DOMAIN),
        "drc721-approval" => Ok(NFT_SIGNED_APPROVE_DOMAIN),
        "proxy-admin" => Ok(PROXY_ADMIN_DOMAIN),
        "multisig" => Ok(MULTISIG_CONTROLLER_DOMAIN),
        other => Err(format!("unknown domain: {other}").into()),
    }
}

fn drc721_approved_principal() -> Principal {
    Principal::Contract(ContractId::from_bytes([55u8; 32]))
}

fn drc721_operator_principal() -> Principal {
    Principal::Contract(ContractId::from_bytes([56u8; 32]))
}

fn parse_hex_32(hex: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()).into());
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid contract hex: {e}"))?;
    }
    Ok(bytes)
}

fn encode<A>(args: &A) -> Result<Vec<u8>, Box<dyn Error>>
where
    A: for<'a> Serialize<StandardBufSerializer<'a>>,
{
    let mut buf = vec![0u8; ARGBUF_LEN];
    let mut scratch = [0u8; SCRATCH_BUF_BYTES];
    let pos = {
        let ser = BufferSerializer::new(buf.as_mut_slice());
        let scratch = BufferScratch::new(&mut scratch);
        let mut serializer = CompositeSerializer::new(ser, scratch, Infallible);
        serializer
            .serialize_value(args)
            .map_err(|e| format!("serialize args failed: {e:?}"))?;
        serializer.pos()
    };
    buf.truncate(pos);
    Ok(buf)
}

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}
