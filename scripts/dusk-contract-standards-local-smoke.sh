#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUSK_URL="${RUSK_URL:-http://localhost:8080}"
RUSK_WALLET_BIN="${RUSK_WALLET_BIN:-$(command -v rusk-wallet || true)}"
WALLET_DIR="${WALLET_DIR:-${ROOT_DIR}/target/dusk-contract-standards-wallet}"
WALLET_PASSWORD="${WALLET_PASSWORD:-password}"
WALLET_RESTORE_FILE="${WALLET_RESTORE_FILE:-}"
DEPLOY_NONCE_BASE="${DEPLOY_NONCE_BASE:-100}"

cd "$ROOT_DIR"

echo "Running standards unit tests"
cargo test --manifest-path standards/Cargo.toml -p dusk-contract-standards

echo "Building example contracts"
cargo build --manifest-path standards/Cargo.toml --release -Z build-std=core,alloc --target wasm32-unknown-unknown \
  -p authorization-counter \
  -p drc20-roles-pausable \
  -p drc721-collection \
  -p multisig-controller \
  -p proxy-counter \
  --features authorization-counter/contract,drc20-roles-pausable/contract,drc721-collection/contract,multisig-controller/contract,proxy-counter/contract

echo "Building Forge data-drivers"
CARGO_TARGET_DIR="${ROOT_DIR}/target/data-driver" \
cargo build --manifest-path standards/Cargo.toml --release --target wasm32-unknown-unknown \
  -p authorization-counter \
  -p drc20-roles-pausable \
  -p drc721-collection \
  -p multisig-controller \
  -p proxy-counter \
  --features authorization-counter/data-driver-js,drc20-roles-pausable/data-driver-js,drc721-collection/data-driver-js,multisig-controller/data-driver-js,proxy-counter/data-driver-js

echo "Running VM example deployment tests"
cargo test --manifest-path standards/Cargo.toml -p dusk-contract-standards --test examples_vm -- --ignored

if [[ -z "$RUSK_WALLET_BIN" ]]; then
  cat >&2 <<'MSG'
rusk-wallet was not found.

Set RUSK_WALLET_BIN=/path/to/rusk-wallet and RUSK_URL=http://host:port for a running local node,
then rerun this script to deploy the standards examples.
MSG
  exit 2
fi

if ! curl -fsS \
  -H 'Content-Type: text/plain' \
  --data '{ block(height: -1) { header { height } } }' \
  "${RUSK_URL}/on/graphql/query" >/dev/null; then
  cat >&2 <<MSG
Rusk node is not reachable at ${RUSK_URL}.

Start a local node or set RUSK_URL to an existing local endpoint, then rerun this script.
MSG
  exit 2
fi

if ! command -v xxd >/dev/null 2>&1; then
  echo "xxd was not found; it is required to submit binary query arguments." >&2
  exit 2
fi

if [[ -z "${DUSK_CHAIN_ID:-}" ]]; then
  chain_info="$(curl -fsS "${RUSK_URL}/on/node/info" 2>/dev/null || true)"
  DUSK_CHAIN_ID="$(
    printf '%s' "$chain_info" |
      sed -n 's/.*"chain_id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' |
      head -n1
  )"
  if [[ -z "$DUSK_CHAIN_ID" ]]; then
    DUSK_CHAIN_ID=250
    echo "Could not read chain id from ${RUSK_URL}; defaulting DUSK_CHAIN_ID=${DUSK_CHAIN_ID}" >&2
  fi
fi
export DUSK_CHAIN_ID
echo "Using DUSK_CHAIN_ID=${DUSK_CHAIN_ID}"

mkdir -p "$WALLET_DIR"

if [[ -n "$WALLET_RESTORE_FILE" && ! -f "$WALLET_DIR/wallet.keystore.json" ]]; then
  if [[ ! -f "$WALLET_RESTORE_FILE" ]]; then
    echo "WALLET_RESTORE_FILE does not exist: ${WALLET_RESTORE_FILE}" >&2
    exit 2
  fi

  echo "Restoring local smoke wallet from ${WALLET_RESTORE_FILE}"
  RUSK_WALLET_PWD="$WALLET_PASSWORD" "$RUSK_WALLET_BIN" \
    --wallet-dir "$WALLET_DIR" \
    --state "$RUSK_URL" \
    --prover "$RUSK_URL" \
    --password "$WALLET_PASSWORD" \
    restore -f "$WALLET_RESTORE_FILE"
fi

encode_args() {
  cargo run -q --manifest-path standards/Cargo.toml -p dusk-contract-standards --example encode_local_smoke_args -- "$@"
}

deploy_contract() {
  local name="$1"
  local wasm="$2"
  local nonce="$3"
  local init_args="$4"
  local output
  local contract_id
  local status

  echo "Deploying ${name}" >&2
  set +e
  output="$(RUSK_WALLET_PWD="$WALLET_PASSWORD" "$RUSK_WALLET_BIN" \
    --wallet-dir "$WALLET_DIR" \
    --state "$RUSK_URL" \
    --prover "$RUSK_URL" \
    --password "$WALLET_PASSWORD" \
    contract-deploy \
    --code "$wasm" \
    --deploy-nonce "$nonce" \
    --init-args "$init_args" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output" >&2
  if [[ "$status" -ne 0 ]]; then
    echo "Deployment failed for ${name}" >&2
    exit "$status"
  fi

  contract_id="$(
    printf '%s\n' "$output" |
      awk '
        /Deploying/ {
          for (i = 1; i <= NF; i++) {
            token = $i
            gsub(/[^0-9a-fA-F]/, "", token)
            if (length(token) == 64) {
              print tolower(token)
              exit
            }
          }
        }
      '
  )"

  if [[ -z "$contract_id" ]]; then
    echo "Unable to parse deployed contract id for ${name}" >&2
    exit 1
  fi

  echo "$contract_id"
}

query_contract() {
  local name="$1"
  local contract_id="$2"
  local fn_name="$3"
  local args_hex="$4"
  local tmp_dir
  local bytes

  tmp_dir="$(mktemp -d)"
  printf '%s' "$args_hex" | xxd -r -p >"${tmp_dir}/args.bin"
  curl -fsS \
    -H 'Content-Type: application/octet-stream' \
    --data-binary @"${tmp_dir}/args.bin" \
    "${RUSK_URL}/on/contracts:${contract_id}/${fn_name}" \
    -o "${tmp_dir}/response.bin"
  bytes="$(wc -c <"${tmp_dir}/response.bin")"
  rm -rf "$tmp_dir"

  if [[ "$bytes" -eq 0 ]]; then
    echo "${name}.${fn_name} returned an empty response" >&2
    exit 1
  fi

  echo "Queried ${name}.${fn_name} (${bytes} bytes)"
}

query_hex() {
  local contract_id="$1"
  local fn_name="$2"
  local args_hex="$3"
  local tmp_dir

  tmp_dir="$(mktemp -d)"
  printf '%s' "$args_hex" | xxd -r -p >"${tmp_dir}/args.bin"
  curl -fsS \
    -H 'Content-Type: application/octet-stream' \
    --data-binary @"${tmp_dir}/args.bin" \
    "${RUSK_URL}/on/contracts:${contract_id}/${fn_name}" \
    -o "${tmp_dir}/response.bin"
  xxd -p -c 256 "${tmp_dir}/response.bin"
  rm -rf "$tmp_dir"
}

query_u64() {
  local contract_id="$1"
  local fn_name="$2"
  local args_hex="$3"

  printf '%s' "$(query_hex "$contract_id" "$fn_name" "$args_hex")" |
    xxd -r -p |
    od -An -t u8 |
    tr -d ' \n'
}

query_bool() {
  local contract_id="$1"
  local fn_name="$2"
  local args_hex="$3"
  local value

  value="$(query_hex "$contract_id" "$fn_name" "$args_hex")"
  case "$value" in
    00) echo "false" ;;
    01) echo "true" ;;
    *)
      echo "${contract_id}.${fn_name} returned invalid bool hex: ${value}" >&2
      exit 1
      ;;
  esac
}

assert_eq() {
  local label="$1"
  local actual="$2"
  local expected="$3"

  if [[ "$actual" != "$expected" ]]; then
    echo "Assertion failed for ${label}: got ${actual}, expected ${expected}" >&2
    exit 1
  fi

  echo "Asserted ${label} = ${expected}"
}

call_contract() {
  local contract_id="$1"
  local fn_name="$2"
  local args_hex="$3"
  local output_file="$4"
  local status

  set +e
  RUSK_WALLET_PWD="$WALLET_PASSWORD" "$RUSK_WALLET_BIN" \
    --wallet-dir "$WALLET_DIR" \
    --state "$RUSK_URL" \
    --prover "$RUSK_URL" \
    --password "$WALLET_PASSWORD" \
    contract-call \
    --contract-id "$contract_id" \
    --fn-name "$fn_name" \
    --fn-args "$args_hex" >"$output_file" 2>&1
  status=$?
  set -e

  return "$status"
}

expect_call_ok() {
  local label="$1"
  local contract_id="$2"
  local fn_name="$3"
  local args_hex="$4"
  local output_file

  output_file="$(mktemp)"
  if ! call_contract "$contract_id" "$fn_name" "$args_hex" "$output_file"; then
    echo "Expected ${label} to succeed, but wallet command failed" >&2
    cat "$output_file" >&2
    rm -f "$output_file"
    exit 1
  fi
  if grep -q 'Transaction error:' "$output_file"; then
    echo "Expected ${label} to succeed, but transaction reverted" >&2
    cat "$output_file" >&2
    rm -f "$output_file"
    exit 1
  fi
  rm -f "$output_file"
  echo "Accepted ${label}"
}

expect_call_rejected() {
  local label="$1"
  local contract_id="$2"
  local fn_name="$3"
  local args_hex="$4"
  local output_file

  output_file="$(mktemp)"
  if call_contract "$contract_id" "$fn_name" "$args_hex" "$output_file"; then
    if ! grep -q 'Transaction error:' "$output_file"; then
      echo "Expected ${label} to be rejected, but it succeeded" >&2
      cat "$output_file" >&2
      rm -f "$output_file"
      exit 1
    fi
  fi
  rm -f "$output_file"
  echo "Rejected ${label}"
}

run_signed_invariants() {
  local auth_id="$1"
  local drc20_id="$2"
  local drc721_id="$3"
  local proxy_id="$4"
  local expires_at="${SIGNED_EXPIRES_AT:-100000}"
  local unit_args
  local phoenix_call
  local moonlight_call
  local proxy_call

  unit_args="$(encode_args unit)"

  assert_eq "authorization counter initial value" \
    "$(query_u64 "$auth_id" value "$unit_args")" 0
  assert_eq "DRC20 initial supply" \
    "$(query_u64 "$drc20_id" total_supply "$unit_args")" 1000
  assert_eq "DRC721 initial supply" \
    "$(query_u64 "$drc721_id" total_supply "$unit_args")" 1
  assert_eq "proxy initial value" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 0

  phoenix_call="$(encode_args auth-counter-phoenix "$auth_id" 0 "$expires_at" 21)"
  expect_call_ok "Phoenix counter set" "$auth_id" set_value_by_phoenix "$phoenix_call"
  assert_eq "Phoenix counter value" \
    "$(query_u64 "$auth_id" value "$unit_args")" 21
  assert_eq "Phoenix counter nonce after success" \
    "$(query_u64 "$auth_id" nonce "$(encode_args nonce counter phoenix 88)")" 1
  expect_call_rejected "Phoenix counter replay" "$auth_id" set_value_by_phoenix "$phoenix_call"
  assert_eq "Phoenix counter nonce after replay" \
    "$(query_u64 "$auth_id" nonce "$(encode_args nonce counter phoenix 88)")" 1
  expect_call_rejected "Phoenix counter bad payload" \
    "$auth_id" set_value_by_phoenix \
    "$(encode_args auth-counter-phoenix "$auth_id" 1 "$expires_at" 22 bad-payload)"
  assert_eq "Phoenix counter nonce after bad payload" \
    "$(query_u64 "$auth_id" nonce "$(encode_args nonce counter phoenix 88)")" 1
  expect_call_rejected "Phoenix counter expired action" \
    "$auth_id" set_value_by_phoenix \
    "$(encode_args auth-counter-phoenix "$auth_id" 1 1 22)"
  assert_eq "Phoenix counter nonce after expired action" \
    "$(query_u64 "$auth_id" nonce "$(encode_args nonce counter phoenix 88)")" 1
  expect_call_ok "Phoenix counter second set" \
    "$auth_id" set_value_by_phoenix \
    "$(encode_args auth-counter-phoenix "$auth_id" 1 "$expires_at" 22)"
  assert_eq "Phoenix counter nonce after second success" \
    "$(query_u64 "$auth_id" nonce "$(encode_args nonce counter phoenix 88)")" 2

  moonlight_call="$(encode_args auth-counter-moonlight "$auth_id" 0 "$expires_at" 31)"
  expect_call_ok "Moonlight counter set" "$auth_id" set_value_by_moonlight "$moonlight_call"
  assert_eq "Moonlight counter value" \
    "$(query_u64 "$auth_id" value "$unit_args")" 31
  assert_eq "Moonlight counter nonce after success" \
    "$(query_u64 "$auth_id" nonce "$(encode_args nonce counter moonlight 7)")" 1
  expect_call_rejected "Moonlight counter replay" "$auth_id" set_value_by_moonlight "$moonlight_call"
  assert_eq "Moonlight counter nonce after replay" \
    "$(query_u64 "$auth_id" nonce "$(encode_args nonce counter moonlight 7)")" 1
  expect_call_rejected "Moonlight counter wrong action" \
    "$auth_id" set_value_by_moonlight \
    "$(encode_args auth-counter-moonlight "$auth_id" 1 "$expires_at" 32 wrong-action)"
  assert_eq "Moonlight counter nonce after wrong action" \
    "$(query_u64 "$auth_id" nonce "$(encode_args nonce counter moonlight 7)")" 1
  expect_call_ok "Moonlight counter second set" \
    "$auth_id" set_value_by_moonlight \
    "$(encode_args auth-counter-moonlight "$auth_id" 1 "$expires_at" 32)"
  assert_eq "Moonlight counter nonce after second success" \
    "$(query_u64 "$auth_id" nonce "$(encode_args nonce counter moonlight 7)")" 2

  expect_call_ok "DRC20 signed mint" \
    "$drc20_id" mint "$(encode_args drc20-mint "$drc20_id" 0 "$expires_at" 5)"
  assert_eq "DRC20 supply after mint" \
    "$(query_u64 "$drc20_id" total_supply "$unit_args")" 1005
  assert_eq "DRC20 admin nonce after mint" \
    "$(query_u64 "$drc20_id" nonce "$(encode_args nonce drc20-admin phoenix 1)")" 1
  expect_call_ok "DRC20 signed pause" \
    "$drc20_id" pause "$(encode_args drc20-admin pause "$drc20_id" 1 "$expires_at")"
  assert_eq "DRC20 paused" \
    "$(query_bool "$drc20_id" paused "$unit_args")" true
  assert_eq "DRC20 admin nonce after pause" \
    "$(query_u64 "$drc20_id" nonce "$(encode_args nonce drc20-admin phoenix 1)")" 2
  expect_call_rejected "DRC20 paused mint" \
    "$drc20_id" mint "$(encode_args drc20-mint "$drc20_id" 2 "$expires_at" 6)"
  assert_eq "DRC20 supply after paused mint" \
    "$(query_u64 "$drc20_id" total_supply "$unit_args")" 1005
  assert_eq "DRC20 admin nonce after paused mint" \
    "$(query_u64 "$drc20_id" nonce "$(encode_args nonce drc20-admin phoenix 1)")" 2
  expect_call_rejected "DRC20 paused burn" \
    "$drc20_id" burn "$(encode_args u64 1)"
  expect_call_ok "DRC20 signed unpause" \
    "$drc20_id" unpause "$(encode_args drc20-admin unpause "$drc20_id" 2 "$expires_at")"
  assert_eq "DRC20 unpaused" \
    "$(query_bool "$drc20_id" paused "$unit_args")" false
  assert_eq "DRC20 admin nonce after unpause" \
    "$(query_u64 "$drc20_id" nonce "$(encode_args nonce drc20-admin phoenix 1)")" 3

  expect_call_ok "DRC721 signed mint" \
    "$drc721_id" mint "$(encode_args drc721-mint "$drc721_id" 0 "$expires_at" 2)"
  assert_eq "DRC721 supply after mint" \
    "$(query_u64 "$drc721_id" total_supply "$unit_args")" 2
  assert_eq "DRC721 admin nonce after mint" \
    "$(query_u64 "$drc721_id" nonce "$(encode_args nonce drc721-admin phoenix 1)")" 1
  expect_call_ok "DRC721 signed token approval" \
    "$drc721_id" approve_by_authorization \
    "$(encode_args drc721-approve "$drc721_id" 0 "$expires_at" 2)"
  assert_eq "DRC721 approval nonce after token approval" \
    "$(query_u64 "$drc721_id" nonce "$(encode_args nonce drc721-approval phoenix 1)")" 1
  expect_call_rejected "DRC721 signed token approval replay" \
    "$drc721_id" approve_by_authorization \
    "$(encode_args drc721-approve "$drc721_id" 0 "$expires_at" 2)"
  assert_eq "DRC721 approval nonce after token approval replay" \
    "$(query_u64 "$drc721_id" nonce "$(encode_args nonce drc721-approval phoenix 1)")" 1
  expect_call_rejected "DRC721 signed token approval bad payload" \
    "$drc721_id" approve_by_authorization \
    "$(encode_args drc721-approve "$drc721_id" 1 "$expires_at" 2 bad-payload)"
  assert_eq "DRC721 approval nonce after bad payload" \
    "$(query_u64 "$drc721_id" nonce "$(encode_args nonce drc721-approval phoenix 1)")" 1
  expect_call_ok "DRC721 signed operator approval" \
    "$drc721_id" set_approval_for_all_by_authorization \
    "$(encode_args drc721-operator-approval "$drc721_id" 1 "$expires_at" true)"
  assert_eq "DRC721 signed operator approval state" \
    "$(query_bool "$drc721_id" is_approved_for_all "$(encode_args drc721-operator-query)")" true
  assert_eq "DRC721 approval nonce after operator approval" \
    "$(query_u64 "$drc721_id" nonce "$(encode_args nonce drc721-approval phoenix 1)")" 2
  expect_call_ok "DRC721 signed pause" \
    "$drc721_id" pause "$(encode_args drc721-admin pause "$drc721_id" 1 "$expires_at")"
  assert_eq "DRC721 paused" \
    "$(query_bool "$drc721_id" paused "$unit_args")" true
  assert_eq "DRC721 admin nonce after pause" \
    "$(query_u64 "$drc721_id" nonce "$(encode_args nonce drc721-admin phoenix 1)")" 2
  expect_call_ok "DRC721 signed operator approval while paused" \
    "$drc721_id" set_approval_for_all_by_authorization \
    "$(encode_args drc721-operator-approval "$drc721_id" 2 "$expires_at" false)"
  assert_eq "DRC721 signed operator approval state while paused" \
    "$(query_bool "$drc721_id" is_approved_for_all "$(encode_args drc721-operator-query)")" false
  assert_eq "DRC721 approval nonce after paused operator approval" \
    "$(query_u64 "$drc721_id" nonce "$(encode_args nonce drc721-approval phoenix 1)")" 3
  expect_call_rejected "DRC721 paused mint" \
    "$drc721_id" mint "$(encode_args drc721-mint "$drc721_id" 2 "$expires_at" 3)"
  assert_eq "DRC721 supply after paused mint" \
    "$(query_u64 "$drc721_id" total_supply "$unit_args")" 2
  assert_eq "DRC721 admin nonce after paused mint" \
    "$(query_u64 "$drc721_id" nonce "$(encode_args nonce drc721-admin phoenix 1)")" 2
  expect_call_rejected "DRC721 paused burn" \
    "$drc721_id" burn "$(encode_args u64 2)"
  expect_call_ok "DRC721 signed unpause" \
    "$drc721_id" unpause "$(encode_args drc721-admin unpause "$drc721_id" 2 "$expires_at")"
  assert_eq "DRC721 unpaused" \
    "$(query_bool "$drc721_id" paused "$unit_args")" false
  assert_eq "DRC721 admin nonce after unpause" \
    "$(query_u64 "$drc721_id" nonce "$(encode_args nonce drc721-admin phoenix 1)")" 3

  proxy_call="$(encode_args proxy-set "$proxy_id" 0 "$expires_at" 7)"
  expect_call_ok "proxy signed set value" "$proxy_id" set_value "$proxy_call"
  assert_eq "proxy value after signed set" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 7
  assert_eq "proxy admin nonce after signed set" \
    "$(query_u64 "$proxy_id" nonce "$(encode_args nonce proxy-admin phoenix 1)")" 1
  expect_call_rejected "proxy replay" "$proxy_id" set_value "$proxy_call"
  assert_eq "proxy value after replay" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 7
  assert_eq "proxy admin nonce after replay" \
    "$(query_u64 "$proxy_id" nonce "$(encode_args nonce proxy-admin phoenix 1)")" 1

  echo "Local signed invariant checks completed"
}

run_multisig_invariants() {
  local multisig_id="$1"
  local proxy_id="$2"
  local expires_at="${SIGNED_EXPIRES_AT:-100000}"
  local unit_args
  local target_args
  local op_id
  local second_target_args
  local second_op_id

  unit_args="$(encode_args unit)"

  assert_eq "multisig-governed proxy initial value" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 0

  expect_call_rejected "multisig-governed proxy direct set without auth" \
    "$proxy_id" set_value "$(encode_args proxy-set-no-auth 55)"
  assert_eq "multisig-governed proxy value after direct no-auth set" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 0

  expect_call_rejected "multisig-governed proxy direct owner signature" \
    "$proxy_id" set_value "$(encode_args proxy-set "$proxy_id" 0 "$expires_at" 66)"
  assert_eq "multisig-governed proxy owner nonce after direct signature" \
    "$(query_u64 "$proxy_id" nonce "$(encode_args nonce proxy-admin phoenix 1)")" 0
  assert_eq "multisig-governed proxy value after direct owner signature" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 0

  target_args="$(encode_args multisig-target "$proxy_id" 77 1)"
  op_id="$(query_hex "$multisig_id" operation_id "$target_args")"

  expect_call_rejected "multisig non-owner propose" \
    "$multisig_id" propose \
    "$(encode_args multisig-propose "$multisig_id" "$proxy_id" 4 0 "$expires_at" 77 1 "$op_id")"
  assert_eq "multisig non-owner nonce after rejected propose" \
    "$(query_u64 "$multisig_id" nonce "$(encode_args nonce multisig phoenix 4)")" 0

  expect_call_ok "multisig owner one propose" \
    "$multisig_id" propose \
    "$(encode_args multisig-propose "$multisig_id" "$proxy_id" 1 0 "$expires_at" 77 1 "$op_id")"
  assert_eq "multisig owner one nonce after propose" \
    "$(query_u64 "$multisig_id" nonce "$(encode_args nonce multisig phoenix 1)")" 1
  assert_eq "multisig-governed proxy value after one of three" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 0

  expect_call_rejected "multisig duplicate confirmation" \
    "$multisig_id" confirm \
    "$(encode_args multisig-confirm "$multisig_id" 1 1 "$expires_at" "$op_id")"
  assert_eq "multisig owner one nonce after duplicate confirmation" \
    "$(query_u64 "$multisig_id" nonce "$(encode_args nonce multisig phoenix 1)")" 1

  expect_call_rejected "multisig wrong payload confirmation" \
    "$multisig_id" confirm \
    "$(encode_args multisig-confirm "$multisig_id" 2 0 "$expires_at" "$op_id" bad-payload)"
  assert_eq "multisig owner two nonce after wrong payload" \
    "$(query_u64 "$multisig_id" nonce "$(encode_args nonce multisig phoenix 2)")" 0

  expect_call_ok "multisig owner two confirmation executes proxy" \
    "$multisig_id" confirm \
    "$(encode_args multisig-confirm "$multisig_id" 2 0 "$expires_at" "$op_id")"
  assert_eq "multisig-governed proxy value after two of three" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 77
  assert_eq "multisig owner two nonce after confirmation" \
    "$(query_u64 "$multisig_id" nonce "$(encode_args nonce multisig phoenix 2)")" 1

  expect_call_rejected "multisig confirmation replay" \
    "$multisig_id" confirm \
    "$(encode_args multisig-confirm "$multisig_id" 2 0 "$expires_at" "$op_id")"
  assert_eq "multisig owner two nonce after replay" \
    "$(query_u64 "$multisig_id" nonce "$(encode_args nonce multisig phoenix 2)")" 1

  second_target_args="$(encode_args multisig-target "$proxy_id" 88 2)"
  second_op_id="$(query_hex "$multisig_id" operation_id "$second_target_args")"
  expect_call_ok "multisig second operation owner one propose" \
    "$multisig_id" propose \
    "$(encode_args multisig-propose "$multisig_id" "$proxy_id" 1 1 "$expires_at" 88 2 "$second_op_id")"
  assert_eq "multisig-governed proxy value after second one of three" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 77
  assert_eq "multisig owner one nonce after second propose" \
    "$(query_u64 "$multisig_id" nonce "$(encode_args nonce multisig phoenix 1)")" 2

  expect_call_ok "multisig owner three confirmation executes proxy" \
    "$multisig_id" confirm \
    "$(encode_args multisig-confirm "$multisig_id" 3 0 "$expires_at" "$second_op_id")"
  assert_eq "multisig-governed proxy value after owner one plus three" \
    "$(query_u64 "$proxy_id" value "$unit_args")" 88
  assert_eq "multisig owner three nonce after confirmation" \
    "$(query_u64 "$multisig_id" nonce "$(encode_args nonce multisig phoenix 3)")" 1

  echo "Local multisig invariant checks completed"
}

unit_args="$(encode_args unit)"

auth_id="$(deploy_contract \
  "authorization counter" \
  "${ROOT_DIR}/target/wasm32-unknown-unknown/release/authorization_counter.wasm" \
  "$((DEPLOY_NONCE_BASE + 0))" \
  "$unit_args")"
query_contract "authorization counter" "$auth_id" "value" "$unit_args"

drc20_id="$(deploy_contract \
  "DRC20 roles/pausable" \
  "${ROOT_DIR}/target/wasm32-unknown-unknown/release/drc20_roles_pausable.wasm" \
  "$((DEPLOY_NONCE_BASE + 1))" \
  "$(encode_args drc20-init)")"
query_contract "DRC20 roles/pausable" "$drc20_id" "total_supply" "$unit_args"

drc721_id="$(deploy_contract \
  "DRC721 collection" \
  "${ROOT_DIR}/target/wasm32-unknown-unknown/release/drc721_collection.wasm" \
  "$((DEPLOY_NONCE_BASE + 2))" \
  "$(encode_args drc721-init)")"
query_contract "DRC721 collection" "$drc721_id" "total_supply" "$unit_args"

multisig_id="$(deploy_contract \
  "multisig controller" \
  "${ROOT_DIR}/target/wasm32-unknown-unknown/release/multisig_controller.wasm" \
  "$((DEPLOY_NONCE_BASE + 3))" \
  "$(encode_args multisig-init)")"
query_contract "multisig controller" "$multisig_id" "threshold" "$unit_args"

proxy_id="$(deploy_contract \
  "proxy counter" \
  "${ROOT_DIR}/target/wasm32-unknown-unknown/release/proxy_counter.wasm" \
  "$((DEPLOY_NONCE_BASE + 4))" \
  "$(encode_args proxy-init)")"
query_contract "proxy counter" "$proxy_id" "value" "$unit_args"

multisig_proxy_id="$(deploy_contract \
  "multisig-owned proxy counter" \
  "${ROOT_DIR}/target/wasm32-unknown-unknown/release/proxy_counter.wasm" \
  "$((DEPLOY_NONCE_BASE + 5))" \
  "$(encode_args proxy-init-contract "$multisig_id")")"
query_contract "multisig-owned proxy counter" "$multisig_proxy_id" "value" "$unit_args"

run_signed_invariants "$auth_id" "$drc20_id" "$drc721_id" "$proxy_id"
run_multisig_invariants "$multisig_id" "$multisig_proxy_id"

echo "Local standards smoke completed"
