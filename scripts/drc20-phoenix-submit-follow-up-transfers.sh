#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STANDARDS_DIR="${ROOT_DIR}/standards"
CARGO_TOOLCHAIN="${CARGO_TOOLCHAIN:-nightly-2026-02-27}"
RUSK_STATE_URL="${RUSK_STATE_URL:-https://testnet.nodes.dusk.network}"
RUSK_PROVER_URL="${RUSK_PROVER_URL:-${RUSK_STATE_URL}}"
RUSK_WALLET_BIN="${RUSK_WALLET_BIN:-/home/hein_/projects/rusk-private/target/release/rusk-wallet}"
RUSK_WALLET_PWD="${RUSK_WALLET_PWD:-password}"
export RUSK_WALLET_PWD
WALLET_DIR="${DRC20_PHOENIX_WALLET_DIR:-${ROOT_DIR}/target/drc20-phoenix-testnet-extra-wallet}"
VERIFIER_DATA_DIR="${DRC20_PHOENIX_VERIFIER_DATA_DIR:-${STANDARDS_DIR}/drc20-phoenix-circuits/verifier-data}"
CHAIN_ID="${DRC20_PHOENIX_CHAIN_ID:-2}"
FLOW_ARGS_FILE="${DRC20_PHOENIX_FLOW_ARGS_FILE:-${ROOT_DIR}/target/drc20-phoenix-follow-up-flow.env}"
CONTRACT_ID="${DRC20_PHOENIX_CONTRACT_ID:-${1:-}}"
MAX_CALLS="${DRC20_PHOENIX_MAX_CALLS:-64}"
FOLLOW_UP_TRANSFERS="${DRC20_PHOENIX_FOLLOW_UP_TRANSFERS:-4}"
TARGET_NOTES="${DRC20_PHOENIX_TARGET_NOTES:-$((8 + FOLLOW_UP_TRANSFERS * 2))}"
export DRC20_PHOENIX_FOLLOW_UP_TRANSFERS="${FOLLOW_UP_TRANSFERS}"

if [ -z "${CONTRACT_ID}" ]; then
    echo "usage: DRC20_PHOENIX_CONTRACT_ID=<hex> $0" >&2
    echo "   or: $0 <contract-id-hex>" >&2
    exit 2
fi

if [ ! -x "${RUSK_WALLET_BIN}" ] && ! command -v "${RUSK_WALLET_BIN}" >/dev/null 2>&1; then
    echo "missing rusk-wallet at ${RUSK_WALLET_BIN}" >&2
    exit 2
fi

if [ ! -d "${WALLET_DIR}" ]; then
    echo "wallet dir does not exist: ${WALLET_DIR}" >&2
    echo "restore a funded wallet there or set DRC20_PHOENIX_WALLET_DIR" >&2
    exit 2
fi

cargo_cmd() {
    cargo +"${CARGO_TOOLCHAIN}" "$@"
}

query_hex() {
    local fn_name="$1"
    curl -fsS \
        -H 'Content-Type: application/octet-stream' \
        -H 'rusk-version: 1.0.0-rc.0' \
        --data-binary @/dev/null \
        "${RUSK_STATE_URL}/on/contracts:${CONTRACT_ID}/${fn_name}" \
        | xxd -p -c 256
}

decode_u64() {
    (
        cd "${STANDARDS_DIR}"
        cargo_cmd run -q -p drc20-phoenix-circuits \
            --example build_local_rusk_private_flow -- decode-u64 "$1"
    )
}

decode_u128() {
    (
        cd "${STANDARDS_DIR}"
        cargo_cmd run -q -p drc20-phoenix-circuits \
            --example build_local_rusk_private_flow -- decode-u128 "$1"
    )
}

num_notes() {
    decode_u64 "$(query_hex num_notes)"
}

show_supply() {
    echo "minted_supply=$(decode_u128 "$(query_hex minted_supply)")"
    echo "burned_supply=$(decode_u128 "$(query_hex burned_supply)")"
    echo "net_supply=$(decode_u128 "$(query_hex net_supply)")"
}

wallet_call() {
    local args="$1"
    "${RUSK_WALLET_BIN}" \
        --wallet-dir "${WALLET_DIR}" \
        --state "${RUSK_STATE_URL}" \
        --prover "${RUSK_PROVER_URL}" \
        --log-type plain \
        --log-level error \
        contract-call \
        --contract-id "${CONTRACT_ID}" \
        --fn-name transfer_private \
        --fn-args "${args}" \
        --gas-limit 3000000000
}

wait_num_notes() {
    local expected="$1"
    for _ in $(seq 1 90); do
        local current
        current="$(num_notes)"
        if [ "${current}" = "${expected}" ]; then
            echo "num_notes=${current}"
            return 0
        fi
        sleep 2
    done
    echo "expected num_notes == ${expected}" >&2
    return 1
}

current_notes="$(num_notes)"
echo "contract_id=${CONTRACT_ID}"
echo "current_num_notes=${current_notes}"
if [ "${current_notes}" -ge "${TARGET_NOTES}" ]; then
    echo "target_num_notes=${TARGET_NOTES}"
    show_supply
    echo "contract already reached deterministic flow capacity; no proof generation or transfer submitted"
    exit 0
fi

echo "==> Building deterministic DRC20Phoenix transfer flow for ${CONTRACT_ID}"
(
    cd "${STANDARDS_DIR}"
    cargo_cmd run -q -p drc20-phoenix-circuits \
        --example build_local_rusk_private_flow -- \
        build "${CONTRACT_ID}" "${VERIFIER_DATA_DIR}" "${CHAIN_ID}" \
        > "${FLOW_ARGS_FILE}"
)

# shellcheck disable=SC1090
. "${FLOW_ARGS_FILE}"

current_notes="$(num_notes)"
target_notes="${expected_num_notes_after_all_follow_up_transfers}"
echo "current_num_notes=${current_notes}"
echo "target_num_notes=${target_notes}"
show_supply

if [ "${current_notes}" -ge "${target_notes}" ]; then
    echo "contract already reached deterministic flow capacity; no transfer submitted"
    exit 0
fi

submitted=0

submit_if_needed() {
    local label="$1"
    local args="$2"
    local expected="$3"
    current_notes="$(num_notes)"
    if [ "${current_notes}" -lt "${expected}" ]; then
        if [ "${submitted}" -ge "${MAX_CALLS}" ]; then
            echo "reached DRC20_PHOENIX_MAX_CALLS=${MAX_CALLS}" >&2
            exit 2
        fi
        echo "==> Submitting ${label}; expecting num_notes=${expected}"
        wallet_call "${args}"
        wait_num_notes "${expected}"
        submitted=$((submitted + 1))
    fi
}

submit_if_needed extra_transfer "${extra_transfer_args}" "${expected_num_notes_after_extra_transfer}"
submit_if_needed second_extra_transfer "${second_extra_transfer_args}" "${expected_num_notes_after_second_extra_transfer}"

idx=1
while true; do
    args_var="follow_up_transfer_${idx}_args"
    expected_var="expected_num_notes_after_follow_up_transfer_${idx}"
    args="${!args_var:-}"
    expected="${!expected_var:-}"
    if [ -z "${args}" ] || [ -z "${expected}" ]; then
        break
    fi
    submit_if_needed "follow_up_transfer_${idx}" "${args}" "${expected}"
    idx=$((idx + 1))
done

echo "submitted=${submitted}"
echo "final_num_notes=$(num_notes)"
show_supply
