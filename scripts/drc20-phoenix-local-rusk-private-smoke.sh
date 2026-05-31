#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STANDARDS_DIR="${ROOT_DIR}/standards"
CARGO_TOOLCHAIN="${CARGO_TOOLCHAIN:-nightly-2026-02-27}"
VERIFIER_DATA_DIR="${DRC20_PHOENIX_VERIFIER_DATA_DIR:-${STANDARDS_DIR}/drc20-phoenix-circuits/verifier-data}"

RUSK_PRIVATE_BIN="${RUSK_PRIVATE_BIN:-}"
RUSK_WALLET_BIN="${RUSK_WALLET_BIN:-}"
RUSK_HTTP_LISTEN_ADDR="${RUSK_HTTP_LISTEN_ADDR:-127.0.0.1:8080}"
RUSK_STATE_URL="${RUSK_STATE_URL:-http://${RUSK_HTTP_LISTEN_ADDR}}"
RUSK_DB_PATH="${RUSK_DB_PATH:-${ROOT_DIR}/target/drc20-phoenix-rusk-db}"
RUSK_STATE_PATH="${RUSK_STATE_PATH:-${ROOT_DIR}/target/drc20-phoenix-example.state}"
RUSK_GENESIS_CONFIG="${RUSK_GENESIS_CONFIG:-/home/hein_/projects/rusk-private/examples/genesis.toml}"
RUSK_CONFIG="${RUSK_CONFIG:-}"
RUSK_KADCAST_PUBLIC_ADDRESS="${RUSK_KADCAST_PUBLIC_ADDRESS:-127.0.0.1:19000}"
RUSK_KADCAST_LISTEN_ADDRESS="${RUSK_KADCAST_LISTEN_ADDRESS:-${RUSK_KADCAST_PUBLIC_ADDRESS}}"
DUSK_CONSENSUS_KEYS_PASS="${DUSK_CONSENSUS_KEYS_PASS:-password}"
export DUSK_CONSENSUS_KEYS_PASS
RUSK_MINIMUM_BLOCK_TIME="${RUSK_MINIMUM_BLOCK_TIME:-1}"
export RUSK_MINIMUM_BLOCK_TIME
RUSK_WALLET_PWD="${RUSK_WALLET_PWD:-password}"
export RUSK_WALLET_PWD
DEPLOY_NONCE="${DRC20_PHOENIX_DEPLOY_NONCE:-4242}"
FAUCET_MNEMONIC="${DRC20_PHOENIX_FAUCET_MNEMONIC:-auction tribe type torch domain caution lyrics mouse alert fabric snake ticket}"
WALLET_DIR="${DRC20_PHOENIX_WALLET_DIR:-${ROOT_DIR}/target/drc20-phoenix-wallet}"
FLOW_ARGS_FILE="${ROOT_DIR}/target/drc20-phoenix-local-flow.env"
RUSK_LOG_FILE="${DRC20_PHOENIX_RUSK_LOG_FILE:-${ROOT_DIR}/target/drc20-phoenix-rusk.log}"
RUSK_NODE_PID=""

cleanup() {
    if [ -n "${RUSK_NODE_PID}" ] && kill -0 "${RUSK_NODE_PID}" 2>/dev/null; then
        kill "${RUSK_NODE_PID}" 2>/dev/null || true
        wait "${RUSK_NODE_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

find_rusk() {
    if [ -n "${RUSK_PRIVATE_BIN}" ]; then
        printf '%s\n' "${RUSK_PRIVATE_BIN}"
        return
    fi
    for candidate in \
        /home/hein_/projects/rusk-private/target/release/rusk \
        /home/hein_/projects/rusk-private/target/debug/rusk \
        /home/hein_/projects/rusk-1.6.1-linux-x64-prover/rusk \
        rusk
    do
        if command -v "${candidate}" >/dev/null 2>&1; then
            command -v "${candidate}"
            return
        fi
        if [ -x "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return
        fi
    done
}

find_rusk_wallet() {
    if [ -n "${RUSK_WALLET_BIN}" ]; then
        printf '%s\n' "${RUSK_WALLET_BIN}"
        return
    fi
    for candidate in \
        /home/hein_/projects/rusk-private/target/release/rusk-wallet \
        /home/hein_/projects/rusk-private/target/debug/rusk-wallet \
        /home/hein_/projects/rusk-wallet \
        rusk-wallet
    do
        if command -v "${candidate}" >/dev/null 2>&1; then
            command -v "${candidate}"
            return
        fi
        if [ -x "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return
        fi
    done
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1 && [ ! -x "$1" ]; then
        echo "missing required executable: $1" >&2
        exit 2
    fi
}

remove_target_path() {
    local path="$1"
    case "${path}" in
        "${ROOT_DIR}"/target/*) rm -rf "${path}" ;;
        *) echo "refusing to remove non-target path: ${path}" >&2; exit 2 ;;
    esac
}

cargo_cmd() {
    cargo +"${CARGO_TOOLCHAIN}" "$@"
}

hex_contract_id_from_wallet_output() {
    awk -F'[][]' '/Contract ID:/ {print $2}' \
        | tr ',' '\n' \
        | awk '{gsub(/ /, "", $0); if ($0 != "") printf "%02x", $0}'
}

restore_faucet_wallet() {
    rm -rf "${WALLET_DIR}"
    mkdir -p "${WALLET_DIR}"
    local restore_args="restore"
    if "${RUSK_WALLET_BIN}" restore --help 2>/dev/null | grep -q -- '--legacy'; then
        restore_args="restore --legacy"
    fi
    script -q -e -c "${RUSK_WALLET_BIN} --wallet-dir '${WALLET_DIR}' --log-type plain --log-level error ${restore_args}" /dev/null <<EOF >/dev/null
${FAUCET_MNEMONIC}
${RUSK_WALLET_PWD}
${RUSK_WALLET_PWD}
EOF
}

query_hex() {
    local contract_id="$1"
    local fn_name="$2"
    local fn_args="${3:-}"
    if [ -n "${fn_args}" ]; then
        curl -fsS \
            -H 'Content-Type: application/octet-stream' \
            -H 'rusk-version: 1.0.0-rc.0' \
            --data-binary @<(printf '%s' "${fn_args}" | xxd -r -p) \
            "${RUSK_STATE_URL}/on/contracts:${contract_id}/${fn_name}" \
            | xxd -p -c 256
    else
        curl -fsS \
            -H 'Content-Type: application/octet-stream' \
            -H 'rusk-version: 1.0.0-rc.0' \
            --data-binary @/dev/null \
            "${RUSK_STATE_URL}/on/contracts:${contract_id}/${fn_name}" \
            | xxd -p -c 256
    fi
}

decode_u64() {
    (
        cd "${STANDARDS_DIR}"
        cargo_cmd run -q -p drc20-phoenix-circuits \
            --example build_local_rusk_private_flow -- decode-u64 "$1"
    )
}

decode_u32() {
    (
        cd "${STANDARDS_DIR}"
        cargo_cmd run -q -p drc20-phoenix-circuits \
            --example build_local_rusk_private_flow -- decode-u32 "$1"
    )
}

decode_u128() {
    (
        cd "${STANDARDS_DIR}"
        cargo_cmd run -q -p drc20-phoenix-circuits \
            --example build_local_rusk_private_flow -- decode-u128 "$1"
    )
}

decode_bool() {
    (
        cd "${STANDARDS_DIR}"
        cargo_cmd run -q -p drc20-phoenix-circuits \
            --example build_local_rusk_private_flow -- decode-bool "$1"
    )
}

wait_u64() {
    local contract_id="$1"
    local fn_name="$2"
    local expected="$3"
    for _ in $(seq 1 60); do
        local hex
        if hex="$(query_hex "${contract_id}" "${fn_name}" 2>/dev/null)"; then
            local value
            value="$(decode_u64 "${hex}")"
            if [ "${value}" = "${expected}" ]; then
                return 0
            fi
        fi
        sleep 1
    done
    echo "expected ${fn_name} == ${expected}" >&2
    return 1
}

wait_u32() {
    local contract_id="$1"
    local fn_name="$2"
    local expected="$3"
    for _ in $(seq 1 60); do
        local hex
        if hex="$(query_hex "${contract_id}" "${fn_name}" 2>/dev/null)"; then
            local value
            value="$(decode_u32 "${hex}")"
            if [ "${value}" = "${expected}" ]; then
                return 0
            fi
        fi
        sleep 1
    done
    echo "expected ${fn_name} == ${expected}" >&2
    return 1
}

wait_u128() {
    local contract_id="$1"
    local fn_name="$2"
    local expected="$3"
    for _ in $(seq 1 60); do
        local hex
        if hex="$(query_hex "${contract_id}" "${fn_name}" 2>/dev/null)"; then
            local value
            value="$(decode_u128 "${hex}")"
            if [ "${value}" = "${expected}" ]; then
                return 0
            fi
        fi
        sleep 1
    done
    echo "expected ${fn_name} == ${expected}" >&2
    return 1
}

wait_bool() {
    local contract_id="$1"
    local fn_name="$2"
    local expected="$3"
    for _ in $(seq 1 60); do
        local hex
        if hex="$(query_hex "${contract_id}" "${fn_name}" 2>/dev/null)"; then
            local value
            value="$(decode_bool "${hex}")"
            if [ "${value}" = "${expected}" ]; then
                return 0
            fi
        fi
        sleep 1
    done
    echo "expected ${fn_name} == ${expected}" >&2
    return 1
}

wallet_call() {
    local contract_id="$1"
    local fn_name="$2"
    local fn_args="$3"
    "${RUSK_WALLET_BIN}" \
        --wallet-dir "${WALLET_DIR}" \
        --state "${RUSK_STATE_URL}" \
        --prover "${RUSK_STATE_URL}" \
        --log-type plain \
        --log-level error \
        contract-call \
        --contract-id "${contract_id}" \
        --fn-name "${fn_name}" \
        --fn-args "${fn_args}" \
        --gas-limit 3000000000
}

echo "==> Building DRC20Phoenix standards, Forge contract, data-driver, and client flow"
if [ "${DRC20_PHOENIX_SKIP_BUILD:-0}" != "1" ]; then
    (
        cd "${STANDARDS_DIR}"
        cargo_cmd test -p dusk-contract-standards
        cargo_cmd test -p dusk-contract-standards --features serde
        cargo_cmd test -p drc20-phoenix-circuits
        cargo_cmd run -p drc20-phoenix-circuits --example generate_verifier_data -- "${VERIFIER_DATA_DIR}"
        cargo_cmd run -p dusk-contract-standards --example build_drc20_phoenix_flow
        cargo_cmd build -p drc20-phoenix-reference --target wasm32-unknown-unknown --release --features contract
        cp target/wasm32-unknown-unknown/release/drc20_phoenix_reference.wasm \
            target/wasm32-unknown-unknown/release/drc20_phoenix_reference.contract.wasm
        cargo_cmd build -p drc20-phoenix-reference --target wasm32-unknown-unknown --release --features data-driver
        cp target/wasm32-unknown-unknown/release/drc20_phoenix_reference.wasm \
            target/wasm32-unknown-unknown/release/drc20_phoenix_reference.data-driver.wasm
    )
else
    echo "==> Skipping build preflight because DRC20_PHOENIX_SKIP_BUILD=1"
fi

if [ "${DRC20_PHOENIX_REAL_CIRCUIT:-0}" != "1" ]; then
    cat >&2 <<'EOF'
DRC20Phoenix local-node validation is blocked before RPC submission:
  DRC20_PHOENIX_REAL_CIRCUIT=1 is not set. This branch generates a development
  verifier-data manifest for the dedicated private-asset circuits, but the
  local RPC flow is still fail-closed until wallet transaction builders submit
  real mint/transfer/burn proofs end to end.

The circuits, contract, and data-driver were built successfully. Re-run this script with:
  DRC20_PHOENIX_REAL_CIRCUIT=1
  DRC20_PHOENIX_VERIFIER_DATA_DIR=/path/to/verifier-data
  RUSK_PRIVATE_BIN=/path/to/rusk
  RUSK_WALLET_BIN=/path/to/rusk-wallet
once RPC transaction builders are available.
EOF
    exit 2
fi

RUSK_PRIVATE_BIN="$(find_rusk || true)"
if [ -z "${RUSK_PRIVATE_BIN}" ]; then
    echo "rusk-private/rusk binary not found. Set RUSK_PRIVATE_BIN=/path/to/rusk." >&2
    exit 2
fi
RUSK_WALLET_BIN="$(find_rusk_wallet || true)"
if [ -z "${RUSK_WALLET_BIN}" ]; then
    echo "rusk-wallet binary not found. Set RUSK_WALLET_BIN=/path/to/rusk-wallet." >&2
    exit 2
fi
require_cmd "${RUSK_PRIVATE_BIN}"
require_cmd "${RUSK_WALLET_BIN}"
require_cmd script
require_cmd curl
require_cmd xxd

if [ ! -f "${VERIFIER_DATA_DIR}/manifest.json" ]; then
    echo "missing verifier manifest at ${VERIFIER_DATA_DIR}/manifest.json" >&2
    exit 2
fi

if [ "${DRC20_PHOENIX_GENERATE_STATE:-1}" = "1" ]; then
    echo "==> Generating local genesis state"
    remove_target_path "${RUSK_STATE_PATH}"
    remove_target_path "${RUSK_DB_PATH}"
    STATE_TMP="${ROOT_DIR}/target/drc20-phoenix-state-${RANDOM}-${RANDOM}.tmp"
    remove_target_path "${STATE_TMP}"
    "${RUSK_PRIVATE_BIN}" recovery state \
        --force \
        --init "${RUSK_GENESIS_CONFIG}" \
        -o "${STATE_TMP}" >/dev/null
    remove_target_path "${RUSK_STATE_PATH}"
    mv "${STATE_TMP}" "${RUSK_STATE_PATH}"
fi

echo "==> Starting local rusk-private node"
mkdir -p "${RUSK_DB_PATH}"
rm -f "${RUSK_LOG_FILE}"
RUSK_ARGS=(
    -s "${RUSK_STATE_PATH}"
    --http-listen-addr "${RUSK_HTTP_LISTEN_ADDR}"
    --db-path "${RUSK_DB_PATH}"
    --kadcast-public-address "${RUSK_KADCAST_PUBLIC_ADDRESS}"
    --kadcast-listen-address "${RUSK_KADCAST_LISTEN_ADDRESS}"
    --log-level info
)
if [ -n "${RUSK_CONFIG}" ]; then
    RUSK_ARGS+=(--config "${RUSK_CONFIG}")
fi
"${RUSK_PRIVATE_BIN}" "${RUSK_ARGS[@]}" >"${RUSK_LOG_FILE}" 2>&1 &
RUSK_NODE_PID="$!"

echo "==> Waiting for ${RUSK_STATE_URL}"
for _ in $(seq 1 60); do
    if curl -sS "${RUSK_STATE_URL}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! curl -sS "${RUSK_STATE_URL}" >/dev/null 2>&1; then
    echo "local rusk-private endpoint did not become reachable at ${RUSK_STATE_URL}" >&2
    exit 2
fi

cat >&2 <<'EOF'
==> Restoring local funded faucet wallet
EOF
restore_faucet_wallet

CONTRACT_WASM="${STANDARDS_DIR}/target/wasm32-unknown-unknown/release/drc20_phoenix_reference.contract.wasm"
if [ ! -f "${CONTRACT_WASM}" ]; then
    CONTRACT_WASM="${STANDARDS_DIR}/target/wasm32-unknown-unknown/release/drc20_phoenix_reference.wasm"
fi

echo "==> Calculating contract id"
CONTRACT_ID="$(
    "${RUSK_WALLET_BIN}" \
        --wallet-dir "${WALLET_DIR}" \
        --log-type plain \
        --log-level error \
        calculate-contract-id \
        --code "${CONTRACT_WASM}" \
        --deploy-nonce "${DEPLOY_NONCE}" \
        | hex_contract_id_from_wallet_output
)"
if [ -z "${CONTRACT_ID}" ]; then
    echo "failed to calculate contract id" >&2
    exit 2
fi
echo "contract_id=${CONTRACT_ID}"

echo "==> Building real DRC20Phoenix proof call arguments"
(
    cd "${STANDARDS_DIR}"
    cargo_cmd run -q -p drc20-phoenix-circuits \
        --example build_local_rusk_private_flow -- \
        build "${CONTRACT_ID}" "${VERIFIER_DATA_DIR}" > "${FLOW_ARGS_FILE}"
)
# shellcheck disable=SC1090
. "${FLOW_ARGS_FILE}"

echo "==> Deploying DRC20Phoenix reference"
"${RUSK_WALLET_BIN}" \
    --wallet-dir "${WALLET_DIR}" \
    --state "${RUSK_STATE_URL}" \
    --prover "${RUSK_STATE_URL}" \
    --log-type plain \
    --log-level error \
    contract-deploy \
    --code "${CONTRACT_WASM}" \
    --init-args "${init_args}" \
    --deploy-nonce "${DEPLOY_NONCE}" \
    --gas-limit 3000000000
wait_u32 "${CONTRACT_ID}" version 1

echo "==> Minting private notes"
wallet_call "${CONTRACT_ID}" mint_private "${mint_args}"
wait_u64 "${CONTRACT_ID}" num_notes "${expected_num_notes_after_mint}"
wait_u128 "${CONTRACT_ID}" minted_supply "${expected_minted_supply}"

echo "==> Submitting mutated transfer proof and checking state is unchanged"
wallet_call "${CONTRACT_ID}" transfer_private "${bad_transfer_args}" || true
sleep 3
wait_u64 "${CONTRACT_ID}" num_notes "${expected_num_notes_after_mint}"

echo "==> Transferring privately"
wallet_call "${CONTRACT_ID}" transfer_private "${transfer_args}"
wait_u64 "${CONTRACT_ID}" num_notes "${expected_num_notes_after_transfer}"

echo "==> Replaying transfer and checking state is unchanged"
wallet_call "${CONTRACT_ID}" transfer_private "${transfer_args}" || true
sleep 3
wait_u64 "${CONTRACT_ID}" num_notes "${expected_num_notes_after_transfer}"

echo "==> Burning privately"
wallet_call "${CONTRACT_ID}" burn_private "${burn_args}"
wait_u128 "${CONTRACT_ID}" burned_supply "${expected_burned_supply}"
wait_u128 "${CONTRACT_ID}" net_supply "${expected_net_supply}"
wait_u64 "${CONTRACT_ID}" num_notes "${expected_num_notes_after_burn}"

echo "==> Checking pause/unpause"
wallet_call "${CONTRACT_ID}" pause "${pause_args}"
wait_bool "${CONTRACT_ID}" paused true
wallet_call "${CONTRACT_ID}" mint_private "${mint_args}" || true
sleep 3
wait_u64 "${CONTRACT_ID}" num_notes "${expected_num_notes_after_burn}"
wallet_call "${CONTRACT_ID}" unpause "${unpause_args}"
wait_bool "${CONTRACT_ID}" paused false

echo "DRC20Phoenix local rusk-private smoke passed"
