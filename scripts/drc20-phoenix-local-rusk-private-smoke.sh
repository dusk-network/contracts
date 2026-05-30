#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STANDARDS_DIR="${ROOT_DIR}/standards"
CARGO_TOOLCHAIN="${CARGO_TOOLCHAIN:-nightly-2026-02-27}"
VERIFIER_DATA_DIR="${DRC20_PHOENIX_VERIFIER_DATA_DIR:-${STANDARDS_DIR}/drc20-phoenix-circuits/verifier-data}"

RUSK_PRIVATE_BIN="${RUSK_PRIVATE_BIN:-}"
RUSK_WALLET_BIN="${RUSK_WALLET_BIN:-/home/hein_/projects/rusk-wallet}"
RUSK_HTTP_LISTEN_ADDR="${RUSK_HTTP_LISTEN_ADDR:-127.0.0.1:8080}"
RUSK_STATE_URL="${RUSK_STATE_URL:-http://${RUSK_HTTP_LISTEN_ADDR}}"
RUSK_DB_PATH="${RUSK_DB_PATH:-${ROOT_DIR}/target/drc20-phoenix-rusk-db}"
RUSK_CONFIG="${RUSK_CONFIG:-}"
RUSK_KADCAST_PUBLIC_ADDRESS="${RUSK_KADCAST_PUBLIC_ADDRESS:-127.0.0.1:19000}"
RUSK_KADCAST_LISTEN_ADDRESS="${RUSK_KADCAST_LISTEN_ADDRESS:-${RUSK_KADCAST_PUBLIC_ADDRESS}}"
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

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1 && [ ! -x "$1" ]; then
        echo "missing required executable: $1" >&2
        exit 2
    fi
}

cargo_cmd() {
    cargo +"${CARGO_TOOLCHAIN}" "$@"
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
require_cmd "${RUSK_PRIVATE_BIN}"
require_cmd "${RUSK_WALLET_BIN}"

if [ ! -f "${VERIFIER_DATA_DIR}/manifest.json" ]; then
    echo "missing verifier manifest at ${VERIFIER_DATA_DIR}/manifest.json" >&2
    exit 2
fi

echo "==> Starting local rusk-private node"
mkdir -p "${RUSK_DB_PATH}"
RUSK_ARGS=(
    --http-listen-addr "${RUSK_HTTP_LISTEN_ADDR}"
    --db-path "${RUSK_DB_PATH}"
    --kadcast-public-address "${RUSK_KADCAST_PUBLIC_ADDRESS}"
    --kadcast-listen-address "${RUSK_KADCAST_LISTEN_ADDRESS}"
    --log-level info
)
if [ -n "${RUSK_CONFIG}" ]; then
    RUSK_ARGS+=(--config "${RUSK_CONFIG}")
fi
"${RUSK_PRIVATE_BIN}" "${RUSK_ARGS[@]}" &
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
The node is reachable, but the transaction-submission portion is intentionally
not scripted until wallet RPC builders submit the generated DRC20Phoenix
private-asset proofs to the Forge contract. This avoids shipping an RPC smoke
that uses a permissive or native-DUSK Phoenix proof by accident.
EOF
exit 2
