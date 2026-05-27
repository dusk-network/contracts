#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

STANDARDS_PROPTEST_CASES="${STANDARDS_PROPTEST_CASES:-8192}"
STANDARDS_PROPTEST_MAX_SHRINK_ITERS="${STANDARDS_PROPTEST_MAX_SHRINK_ITERS:-16384}"
STANDARDS_DATA_DRIVER_FUZZ_CASES="${STANDARDS_DATA_DRIVER_FUZZ_CASES:-4096}"
STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS="${STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS:-8192}"
RUN_LOCAL_NODE_SMOKE="${RUN_LOCAL_NODE_SMOKE:-0}"
RUN_CARGO_AUDIT="${RUN_CARGO_AUDIT:-0}"

cd "$ROOT_DIR"

echo "Checking formatting"
cargo fmt --check
cargo fmt --manifest-path standards/Cargo.toml --all --check

echo "Running standards clippy"
cargo clippy --manifest-path standards/Cargo.toml -p dusk-contract-standards --all-targets -- -D warnings

echo "Running native standards tests"
cargo test --manifest-path standards/Cargo.toml -p dusk-contract-standards

echo "Building reference contract Wasm"
cargo build --manifest-path standards/Cargo.toml --release -Z build-std=core,alloc --target wasm32-unknown-unknown \
  -p authorization-counter \
  -p drc20-roles-pausable \
  -p drc721-collection \
  -p moonlight-call-router \
  -p multisig-controller \
  -p proxy-counter \
  --features authorization-counter/contract,drc20-roles-pausable/contract,drc721-collection/contract,moonlight-call-router/contract,multisig-controller/contract,proxy-counter/contract

echo "Running VM reference deployment tests"
cargo test --manifest-path standards/Cargo.toml -p dusk-contract-standards --test examples_vm -- --ignored

echo "Running long property and data-driver hardening"
STANDARDS_PROPTEST_CASES="$STANDARDS_PROPTEST_CASES" \
STANDARDS_PROPTEST_MAX_SHRINK_ITERS="$STANDARDS_PROPTEST_MAX_SHRINK_ITERS" \
STANDARDS_DATA_DRIVER_FUZZ_CASES="$STANDARDS_DATA_DRIVER_FUZZ_CASES" \
STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS="$STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS" \
make standards-hardening

if [[ "$RUN_CARGO_AUDIT" == "1" ]]; then
  echo "Running cargo audit"
  cargo audit
else
  echo "Skipping cargo audit; set RUN_CARGO_AUDIT=1 when cargo-audit is installed"
fi

if [[ "$RUN_LOCAL_NODE_SMOKE" == "1" ]]; then
  echo "Running funded local-node smoke"
  ./scripts/dusk-contract-standards-local-smoke.sh
else
  echo "Skipping funded local-node smoke; set RUN_LOCAL_NODE_SMOKE=1 with RUSK_URL/RUSK_WALLET_BIN/WALLET_DIR"
fi

echo "Audit-grade standards validation completed"
