use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use dusk_contract_standards::access::events as access_events;
use dusk_contract_standards::core::Principal;
use dusk_contract_standards::proxy::{
    RollbackFinalized, UpgradeActivated, UpgradeCancelled, UpgradePrepared,
    UpgradeRolledBack, ROLLBACK_FINALIZED_TOPIC, UPGRADE_ACTIVATED_TOPIC,
    UPGRADE_CANCELLED_TOPIC, UPGRADE_PREPARED_TOPIC, UPGRADE_ROLLED_BACK_TOPIC,
};
use dusk_contract_standards::token::drc20::events as drc20_events;
use dusk_contract_standards::token::drc721::{
    events as drc721_events, RoyaltyQuote,
};
use dusk_core::abi::ContractId;
use dusk_data_driver::reader::DriverReader;
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestRunner};
use rkyv::ser::serializers::AllocSerializer;
use serde_json::{json, Value};

const DRIVER_NAMES: [&str; 4] = [
    "authorization_counter",
    "drc20_roles_pausable",
    "drc721_collection",
    "proxy_counter",
];

#[derive(Clone, Copy, Debug)]
enum ReferenceContract {
    AuthorizationCounter,
    Drc20,
    Drc721,
    ProxyCounter,
}

#[derive(Clone, Debug)]
struct DriverCase {
    contract: ReferenceContract,
    selector: u8,
    a: u8,
    b: u8,
    amount: u64,
    flag: bool,
}

struct CallSpec {
    driver: &'static str,
    function: &'static str,
    input: Value,
}

#[test]
#[ignore = "requires `make standards-data-drivers` before running"]
fn data_driver_schemas_are_loadable() {
    for name in DRIVER_NAMES {
        let driver = load_driver(name);
        let version = driver.get_version().expect("driver version");
        assert!(!version.is_empty(), "{name} returned an empty version");

        let schema = driver.get_schema().expect("driver schema");
        let functions = schema
            .get("functions")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{name} schema has no functions array"));
        assert!(!functions.is_empty(), "{name} schema has no functions");
    }
}

#[test]
#[ignore = "requires `make standards-data-drivers` before running"]
fn data_driver_inputs_roundtrip_and_reject_bad_shapes() {
    let drivers = load_drivers();
    assert_rejects_bad_inputs(&drivers);

    let mut runner = TestRunner::new(ProptestConfig {
        cases: env_usize("STANDARDS_DATA_DRIVER_FUZZ_CASES")
            .or_else(|| env_usize("PROPTEST_CASES"))
            .unwrap_or(512) as u32,
        max_shrink_iters: env_usize("STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS")
            .or_else(|| env_usize("PROPTEST_MAX_SHRINK_ITERS"))
            .unwrap_or(2048) as u32,
        ..ProptestConfig::default()
    });

    runner
        .run(&driver_case_strategy(), |case| {
            let call = call_for(&case);
            let driver = drivers.get(call.driver).expect("loaded driver");
            assert_input_roundtrip(driver, &call)?;
            assert_mutated_inputs_are_handled(driver, &call)?;
            Ok(())
        })
        .expect("data-driver fuzz cases failed");
}

#[test]
#[ignore = "requires `make standards-data-drivers` before running"]
fn data_driver_outputs_and_events_decode() {
    let drivers = load_drivers();

    assert_output_decodes(
        drivers.get("authorization_counter").unwrap(),
        "value",
        &42u64,
    );
    assert_output_decodes(
        drivers.get("authorization_counter").unwrap(),
        "last_authorizer",
        &Some(principal_value(1)),
    );

    let drc20 = drivers.get("drc20_roles_pausable").unwrap();
    assert_output_decodes(drc20, "name", &"Audit Token".to_string());
    assert_output_decodes(drc20, "decimals", &9u8);
    assert_output_decodes(drc20, "total_supply", &1_000u64);
    assert_output_decodes(drc20, "has_role", &true);
    assert_output_decodes(drc20, "paused", &false);
    assert_event_decodes(
        drc20,
        drc20_events::TRANSFER_TOPIC,
        &drc20_events::Transfer {
            from: principal_value(1),
            to: principal_value(2),
            amount: 7,
        },
    );
    assert_event_decodes(
        drc20,
        drc20_events::APPROVAL_TOPIC,
        &drc20_events::Approval {
            owner: principal_value(1),
            spender: principal_value(2),
            amount: 7,
        },
    );
    assert_event_decodes(
        drc20,
        access_events::PAUSED_TOPIC,
        &access_events::Paused {
            account: principal_value(1),
        },
    );
    assert_event_decodes(
        drc20,
        access_events::ROLE_GRANTED_TOPIC,
        &access_events::RoleGranted {
            role: [3u8; 32],
            account: principal_value(1),
            sender: principal_value(2),
        },
    );

    let drc721 = drivers.get("drc721_collection").unwrap();
    assert_output_decodes(drc721, "base_uri", &"ipfs://audit/".to_string());
    assert_output_decodes(drc721, "tokens_of", &vec![1u64, 2, 3]);
    assert_output_decodes(drc721, "owner_of", &principal_value(1));
    assert_output_decodes(
        drc721,
        "royalty_info",
        &RoyaltyQuote {
            receiver: principal_value(2),
            amount: 50,
        },
    );
    assert_event_decodes(
        drc721,
        drc721_events::TRANSFER_TOPIC,
        &drc721_events::Transfer {
            from: principal_value(1),
            to: principal_value(2),
            token_id: 9,
        },
    );
    assert_event_decodes(
        drc721,
        drc721_events::APPROVAL_FOR_ALL_TOPIC,
        &drc721_events::ApprovalForAll {
            owner: principal_value(1),
            operator: principal_value(2),
            approved: true,
        },
    );
    assert_event_decodes(
        drc721,
        drc721_events::TOKEN_ROYALTY_SET_TOPIC,
        &drc721_events::TokenRoyaltySet {
            operator: principal_value(1),
            token_id: 9,
            receiver: principal_value(2),
            basis_points: 500,
        },
    );

    let proxy = drivers.get("proxy_counter").unwrap();
    assert_output_decodes(proxy, "implementation", &contract_id(4));
    assert_output_decodes(proxy, "rollback_deadline", &100u64);
    assert_output_decodes(proxy, "activate_upgrade", &vec![1u8, 2, 3]);
    assert_event_decodes(
        proxy,
        UPGRADE_PREPARED_TOPIC,
        &UpgradePrepared {
            implementation: contract_id(4),
            eta: 10,
        },
    );
    assert_event_decodes(
        proxy,
        UPGRADE_ACTIVATED_TOPIC,
        &UpgradeActivated {
            previous_implementation: contract_id(3),
            implementation: contract_id(4),
            rollback_deadline: 20,
        },
    );
    assert_event_decodes(
        proxy,
        UPGRADE_CANCELLED_TOPIC,
        &UpgradeCancelled {
            implementation: contract_id(4),
        },
    );
    assert_event_decodes(
        proxy,
        UPGRADE_ROLLED_BACK_TOPIC,
        &UpgradeRolledBack {
            from_implementation: contract_id(4),
            restored_implementation: contract_id(3),
        },
    );
    assert_event_decodes(
        proxy,
        ROLLBACK_FINALIZED_TOPIC,
        &RollbackFinalized {
            implementation: contract_id(4),
        },
    );

    for (name, driver) in &drivers {
        assert!(
            driver.decode_output_fn("definitely_missing", &[]).is_err(),
            "{name} accepted an unknown output function"
        );
        assert!(
            driver.decode_event("definitely_missing", &[]).is_err(),
            "{name} accepted an unknown event topic"
        );
    }
}

fn load_drivers() -> BTreeMap<&'static str, DriverReader> {
    DRIVER_NAMES
        .into_iter()
        .map(|name| (name, load_driver(name)))
        .collect()
}

fn load_driver(name: &str) -> DriverReader {
    let path = driver_path(name);
    let wasm = fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}; run `make standards-data-drivers`",
            path.display()
        )
    });
    DriverReader::new(&wasm)
        .unwrap_or_else(|error| panic!("failed to load {name}: {error}"))
}

fn driver_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/data-driver/wasm32-unknown-unknown/release")
        .join(format!("{name}.wasm"))
}

fn assert_rejects_bad_inputs(drivers: &BTreeMap<&'static str, DriverReader>) {
    for (name, driver) in drivers {
        assert!(
            driver
                .encode_input_fn("definitely_missing", "null")
                .is_err(),
            "{name} accepted an unknown function"
        );
        assert!(
            driver.encode_input_fn("value", "{").is_err(),
            "{name} accepted malformed JSON"
        );
    }

    let auth = drivers.get("authorization_counter").unwrap();
    assert!(
        auth.encode_input_fn(
            "nonce",
            &json!({
                "principal": {"kind": "Phoenix", "bytes": [1]},
                "domain": bytes32(0),
            })
            .to_string()
        )
        .is_err(),
        "authorization counter accepted a malformed Phoenix principal"
    );

    let drc20 = drivers.get("drc20_roles_pausable").unwrap();
    assert!(
        drc20
            .encode_input_fn(
                "balance_of",
                &json!({"account": {"kind": "Moonlight", "bytes": bytes32(1)}})
                    .to_string(),
            )
            .is_err(),
        "DRC20 accepted a short Moonlight principal"
    );
    assert!(
        drc20.encode_input_fn("burn", r#""not a number""#).is_err(),
        "DRC20 accepted a string u64"
    );

    let drc721 = drivers.get("drc721_collection").unwrap();
    assert!(
        drc721
            .encode_input_fn(
                "set_approval_for_all",
                &json!({"operator": principal(1), "approved": "yes"})
                    .to_string(),
            )
            .is_err(),
        "DRC721 accepted a string bool"
    );
}

fn assert_input_roundtrip(
    driver: &DriverReader,
    call: &CallSpec,
) -> Result<(), TestCaseError> {
    let input = call.input.to_string();
    let encoded =
        driver
            .encode_input_fn(call.function, &input)
            .map_err(|error| {
                TestCaseError::fail(format!("encode failed: {error}"))
            })?;
    prop_assert!(
        !encoded.is_empty() || call.input.is_null(),
        "{}:{} encoded to an empty non-unit payload",
        call.driver,
        call.function
    );

    let decoded =
        driver
            .decode_input_fn(call.function, &encoded)
            .map_err(|error| {
                TestCaseError::fail(format!("decode failed: {error}"))
            })?;
    let reencoded = driver
        .encode_input_fn(call.function, &decoded.to_string())
        .map_err(|error| {
            TestCaseError::fail(format!("re-encode failed: {error}"))
        })?;
    let decoded_again = driver
        .decode_input_fn(call.function, &reencoded)
        .map_err(|error| {
            TestCaseError::fail(format!(
                "decode-after-reencode failed: {error}"
            ))
        })?;

    prop_assert_eq!(decoded_again, decoded);
    Ok(())
}

fn assert_mutated_inputs_are_handled(
    driver: &DriverReader,
    call: &CallSpec,
) -> Result<(), TestCaseError> {
    let encoded = driver
        .encode_input_fn(call.function, &call.input.to_string())
        .map_err(|error| {
            TestCaseError::fail(format!("encode failed: {error}"))
        })?;

    for mutated in mutated_inputs(&encoded) {
        if let Ok(decoded) = driver.decode_input_fn(call.function, &mutated) {
            driver
                .encode_input_fn(call.function, &decoded.to_string())
                .map_err(|error| {
                    TestCaseError::fail(format!(
                        "mutated input decoded to unencodable JSON: {error}"
                    ))
                })?;
        }
    }

    Ok(())
}

fn assert_output_decodes<T>(driver: &DriverReader, function: &str, value: &T)
where
    T: rkyv::Serialize<AllocSerializer<4096>>,
{
    let encoded = rkyv_bytes(value);
    driver
        .decode_output_fn(function, &encoded)
        .unwrap_or_else(|error| {
            panic!("decode_output_fn({function}) failed: {error}")
        });
    assert_mutated_output_decode_is_handled(driver, function, &encoded);
}

fn assert_event_decodes<T>(driver: &DriverReader, topic: &str, value: &T)
where
    T: rkyv::Serialize<AllocSerializer<4096>>,
{
    let encoded = rkyv_bytes(value);
    driver
        .decode_event(topic, &encoded)
        .unwrap_or_else(|error| {
            panic!("decode_event({topic}) failed: {error}")
        });
    assert_mutated_event_decode_is_handled(driver, topic, &encoded);
}

fn assert_mutated_output_decode_is_handled(
    driver: &DriverReader,
    function: &str,
    encoded: &[u8],
) {
    for mutated in mutated_inputs(encoded) {
        let _ = driver.decode_output_fn(function, &mutated);
    }
}

fn assert_mutated_event_decode_is_handled(
    driver: &DriverReader,
    topic: &str,
    encoded: &[u8],
) {
    for mutated in mutated_inputs(encoded) {
        let _ = driver.decode_event(topic, &mutated);
    }
}

fn rkyv_bytes<T>(value: &T) -> Vec<u8>
where
    T: rkyv::Serialize<AllocSerializer<4096>>,
{
    rkyv::to_bytes::<_, 4096>(value)
        .expect("rkyv serialization")
        .to_vec()
}

fn mutated_inputs(encoded: &[u8]) -> Vec<Vec<u8>> {
    let mut mutations = Vec::new();
    mutations.push(Vec::new());

    if !encoded.is_empty() {
        let mut flipped = encoded.to_vec();
        flipped[0] ^= 0x80;
        mutations.push(flipped);

        let mut middle = encoded.to_vec();
        let index = middle.len() / 2;
        middle[index] ^= 0x55;
        mutations.push(middle);

        let mut truncated = encoded.to_vec();
        truncated.truncate(truncated.len() / 2);
        mutations.push(truncated);
    }

    let mut appended = encoded.to_vec();
    appended.extend_from_slice(&[0xaa, 0x55, 0x00, 0xff]);
    mutations.push(appended);

    mutations
}

fn driver_case_strategy() -> impl Strategy<Value = DriverCase> {
    (
        0u8..4,
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
        any::<u64>(),
        any::<bool>(),
    )
        .prop_map(|(contract, selector, a, b, amount, flag)| DriverCase {
            contract: match contract {
                0 => ReferenceContract::AuthorizationCounter,
                1 => ReferenceContract::Drc20,
                2 => ReferenceContract::Drc721,
                _ => ReferenceContract::ProxyCounter,
            },
            selector,
            a,
            b,
            amount,
            flag,
        })
}

fn call_for(case: &DriverCase) -> CallSpec {
    match case.contract {
        ReferenceContract::AuthorizationCounter => auth_counter_call(case),
        ReferenceContract::Drc20 => drc20_call(case),
        ReferenceContract::Drc721 => drc721_call(case),
        ReferenceContract::ProxyCounter => proxy_call(case),
    }
}

fn auth_counter_call(case: &DriverCase) -> CallSpec {
    match case.selector % 4 {
        0 => call("authorization_counter", "init", Value::Null),
        1 => call("authorization_counter", "value", Value::Null),
        2 => call("authorization_counter", "last_authorizer", Value::Null),
        _ => call("authorization_counter", "nonce", nonce_query(case.a)),
    }
}

#[allow(clippy::too_many_lines)]
fn drc20_call(case: &DriverCase) -> CallSpec {
    match case.selector % 27 {
        0 => call(
            "drc20_roles_pausable",
            "init",
            json!({
                "admin": principal(case.a),
                "token": {
                    "name": "Fuzz Token",
                    "symbol": "FUZZ",
                    "decimals": case.a % 19,
                    "initial_balances": [{
                        "account": principal(case.b),
                        "amount": bounded(case.amount),
                    }],
                },
                "cap": bounded(case.amount).saturating_add(1),
            }),
        ),
        1 => call("drc20_roles_pausable", "name", Value::Null),
        2 => call("drc20_roles_pausable", "symbol", Value::Null),
        3 => call("drc20_roles_pausable", "decimals", Value::Null),
        4 => call("drc20_roles_pausable", "total_supply", Value::Null),
        5 => call(
            "drc20_roles_pausable",
            "balance_of",
            json!({"account": principal(case.a)}),
        ),
        6 => call(
            "drc20_roles_pausable",
            "allowance",
            json!({"owner": principal(case.a), "spender": principal(case.b)}),
        ),
        7 => call("drc20_roles_pausable", "nonce", nonce_query(case.a)),
        8 => call("drc20_roles_pausable", "cap", Value::Null),
        9 => call("drc20_roles_pausable", "remaining_mintable", Value::Null),
        10 => call("drc20_roles_pausable", "latest_votes", principal(case.a)),
        11 => call(
            "drc20_roles_pausable",
            "past_votes",
            json!({"account": principal(case.a), "timepoint": case.amount}),
        ),
        12 => call("drc20_roles_pausable", "latest_total_votes", Value::Null),
        13 => call(
            "drc20_roles_pausable",
            "past_total_supply",
            json!(case.amount),
        ),
        14 => call(
            "drc20_roles_pausable",
            "has_role",
            json!({"role": bytes32(case.a), "account": principal(case.b)}),
        ),
        15 => call(
            "drc20_roles_pausable",
            "transfer",
            json!({"to": principal(case.a), "amount": case.amount}),
        ),
        16 => call(
            "drc20_roles_pausable",
            "approve",
            json!({"spender": principal(case.a), "amount": case.amount}),
        ),
        17 => call(
            "drc20_roles_pausable",
            "increase_allowance",
            json!({"spender": principal(case.a), "added_amount": case.amount}),
        ),
        18 => call(
            "drc20_roles_pausable",
            "decrease_allowance",
            json!({
                "spender": principal(case.a),
                "subtracted_amount": case.amount,
            }),
        ),
        19 => call(
            "drc20_roles_pausable",
            "transfer_from",
            json!({
                "owner": principal(case.a),
                "to": principal(case.b),
                "amount": case.amount,
            }),
        ),
        20 => call(
            "drc20_roles_pausable",
            "mint",
            json!({
                "to": principal(case.a),
                "amount": case.amount,
                "authorization": null,
            }),
        ),
        21 => call("drc20_roles_pausable", "burn", json!(case.amount)),
        22 => call(
            "drc20_roles_pausable",
            "pause",
            json!({"authorization": null}),
        ),
        23 => call(
            "drc20_roles_pausable",
            "unpause",
            json!({"authorization": null}),
        ),
        24 => call("drc20_roles_pausable", "paused", Value::Null),
        25 => call(
            "drc20_roles_pausable",
            "grant_role",
            json!({
                "role": bytes32(case.a),
                "account": principal(case.b),
                "authorization": null,
            }),
        ),
        _ => call(
            "drc20_roles_pausable",
            "revoke_role",
            json!({
                "role": bytes32(case.a),
                "account": principal(case.b),
                "authorization": null,
            }),
        ),
    }
}

#[allow(clippy::too_many_lines)]
fn drc721_call(case: &DriverCase) -> CallSpec {
    match case.selector % 27 {
        0 => call(
            "drc721_collection",
            "init",
            json!({
                "owner": principal(case.a),
                "token": {
                    "name": "Fuzz Collection",
                    "symbol": "FUZ",
                    "base_uri": "ipfs://fuzz/",
                    "initial_tokens": [{
                        "account": principal(case.b),
                        "token_id": bounded(case.amount),
                    }],
                },
                "default_royalty": royalty(case.a, case.amount),
            }),
        ),
        1 => call("drc721_collection", "name", Value::Null),
        2 => call("drc721_collection", "symbol", Value::Null),
        3 => call("drc721_collection", "base_uri", Value::Null),
        4 => call(
            "drc721_collection",
            "token_uri",
            json!({"token_id": case.amount}),
        ),
        5 => call(
            "drc721_collection",
            "token_by_index",
            json!({"index": bounded(case.amount)}),
        ),
        6 => call(
            "drc721_collection",
            "token_of_owner_by_index",
            json!({"owner": principal(case.a), "index": bounded(case.amount)}),
        ),
        7 => call(
            "drc721_collection",
            "tokens_of",
            json!({"owner": principal(case.a)}),
        ),
        8 => call("drc721_collection", "total_supply", Value::Null),
        9 => call(
            "drc721_collection",
            "balance_of",
            json!({"account": principal(case.a)}),
        ),
        10 => call(
            "drc721_collection",
            "owner_of",
            json!({"token_id": case.amount}),
        ),
        11 => call(
            "drc721_collection",
            "get_approved",
            json!({"token_id": case.amount}),
        ),
        12 => call(
            "drc721_collection",
            "is_approved_for_all",
            json!({"owner": principal(case.a), "operator": principal(case.b)}),
        ),
        13 => call("drc721_collection", "nonce", nonce_query(case.a)),
        14 => call(
            "drc721_collection",
            "royalty_info",
            json!({"token_id": case.amount, "sale_price": bounded(case.amount)}),
        ),
        15 => call(
            "drc721_collection",
            "approve",
            json!({"approved": principal(case.a), "token_id": case.amount}),
        ),
        16 => call(
            "drc721_collection",
            "set_approval_for_all",
            json!({"operator": principal(case.a), "approved": case.flag}),
        ),
        17 => call(
            "drc721_collection",
            "transfer_from",
            json!({
                "from": principal(case.a),
                "to": principal(case.b),
                "token_id": case.amount,
            }),
        ),
        18 => call(
            "drc721_collection",
            "mint",
            json!({
                "to": principal(case.a),
                "token_id": case.amount,
                "authorization": null,
            }),
        ),
        19 => call("drc721_collection", "burn", json!(case.amount)),
        20 => {
            call("drc721_collection", "pause", json!({"authorization": null}))
        }
        21 => call(
            "drc721_collection",
            "unpause",
            json!({"authorization": null}),
        ),
        22 => call("drc721_collection", "paused", Value::Null),
        23 => call(
            "drc721_collection",
            "set_default_royalty",
            json!({"info": royalty(case.a, case.amount), "authorization": null}),
        ),
        24 => call(
            "drc721_collection",
            "clear_default_royalty",
            json!({"authorization": null}),
        ),
        25 => call(
            "drc721_collection",
            "set_token_royalty",
            json!({
                "token_id": case.amount,
                "info": royalty(case.a, case.amount),
                "authorization": null,
            }),
        ),
        _ => call(
            "drc721_collection",
            "clear_token_royalty",
            json!({"token_id": case.amount, "authorization": null}),
        ),
    }
}

fn proxy_call(case: &DriverCase) -> CallSpec {
    match case.selector % 9 {
        0 => call("proxy_counter", "implementation", Value::Null),
        1 => call("proxy_counter", "rollback_deadline", Value::Null),
        2 => call("proxy_counter", "nonce", nonce_query(case.a)),
        3 => call("proxy_counter", "value", Value::Null),
        4 => call("proxy_counter", "increment", Value::Null),
        5 => call(
            "proxy_counter",
            "set_value",
            json!({"value": case.amount, "authorization": null}),
        ),
        6 => call(
            "proxy_counter",
            "activate_upgrade",
            json!({"authorization": null}),
        ),
        7 => call(
            "proxy_counter",
            "cancel_pending_upgrade",
            json!({"authorization": null}),
        ),
        _ => call(
            "proxy_counter",
            "finalize_rollback_window",
            json!({"authorization": null}),
        ),
    }
}

fn call(
    driver: &'static str,
    function: &'static str,
    input: Value,
) -> CallSpec {
    CallSpec {
        driver,
        function,
        input,
    }
}

fn nonce_query(seed: u8) -> Value {
    json!({"principal": principal(seed), "domain": bytes32(seed)})
}

fn principal(seed: u8) -> Value {
    match seed % 3 {
        0 => json!({"kind": "Phoenix", "bytes": bytes32(seed)}),
        1 => json!({"kind": "Contract", "bytes": bytes32(seed)}),
        _ => json!({"kind": "Moonlight", "bytes": bytes193(seed)}),
    }
}

fn royalty(seed: u8, amount: u64) -> Value {
    json!({
        "receiver": principal(seed),
        "basis_points": (amount % 10_001) as u16,
    })
}

fn principal_value(seed: u8) -> Principal {
    match seed % 3 {
        0 => Principal::Phoenix(bytes32_array(seed)),
        1 => Principal::Contract(contract_id(seed)),
        _ => Principal::Moonlight(bytes193_array(seed)),
    }
}

fn contract_id(seed: u8) -> ContractId {
    ContractId::from_bytes(bytes32_array(seed))
}

fn bytes32(seed: u8) -> Vec<u8> {
    (0..32).map(|index| seed.wrapping_add(index)).collect()
}

fn bytes32_array(seed: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    bytes
}

fn bytes193(seed: u8) -> Vec<u8> {
    (0..193).map(|index| seed.wrapping_add(index)).collect()
}

fn bytes193_array(seed: u8) -> [u8; 193] {
    let mut bytes = [0u8; 193];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    bytes
}

fn bounded(value: u64) -> u64 {
    value % 1_000_000
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse().ok()
}
