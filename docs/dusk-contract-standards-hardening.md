# Dusk Contract Standards Hardening Track

This branch is a separate hardening track for the Dusk-native standards layer.
It keeps implementation work close to the contracts, but treats security
validation as a first-class deliverable rather than a final smoke test.

## Current Scope

The first hardening pass focuses on invariants that should hold regardless of
the composing contract:

- signed authorization must bind contract, domain, action id, payload hash,
  nonce, principal, and expiry before nonce/replay state is consumed;
- Phoenix signed authorization must preserve nonce and replay-key state across
  all rejected envelope, signature, expiry, policy, and replay-key cases;
- owner, role, and upgrade-admin checks must not consume a valid signer nonce
  when the signer is not authorized for the policy being checked;
- mixed owner-set checks must follow the same no-consume-on-unauthorized rule;
- failed token operations must not leave partial native state behind;
- DRC20 total supply must equal the modeled sum of balances for all touched
  accounts;
- DRC20 allowance movement must match the reference model exactly;
- DRC721 total supply must equal the modeled number of live token ids;
- DRC721 owner, approval, operator, balance, and enumerable views must remain
  internally consistent after arbitrary operation sequences;
- nonce import/export and replay-key import/export must be monotonic,
  idempotent, and atomic on rejected nonce consumption;
- voting checkpoints must reject non-monotonic writes without partially
  updating account or total-supply checkpoints;
- royalty registry mutations and overflow-prone royalty quotes must leave
  registry state unchanged on rejection;
- supply-cap changes must reject cap reductions below current supply and
  overflow-prone mints without moving the configured cap;
- owner-set initialization and timelock-controller maintenance operations must
  validate before mutating durable state;
- the reserved zero principal must not be accepted as an actor, recipient,
  spender, minter, burner, or operator where that would create ownership or
  authorization state.

## Added Validation

`standards/dusk-contract-standards/tests/properties.rs` adds property-based
state-machine tests for:

- action-bound authorization rejection cases;
- Phoenix action-bound authorization rejection and replay-key preservation
  cases;
- mixed owner sets;
- access-control role/admin mutation;
- timelock scheduling, execution, cancellation, and delay mutation;
- timelock-controller self-governed delay changes and malformed maintenance
  payload rejection;
- upgrade-admin prepare, activate, cancel, rollback, and finalization flows;
- nonce/replay state import, consumption, and rejection;
- two-step ownership;
- DRC20 supply caps and voting-unit checkpoints;
- DRC20 accounting and allowance flows;
- DRC721 ownership, approval, operator, balance, and enumerable views;
- DRC721 royalty registry mutation and quote behavior.

The tests generate random operation sequences, run them against the real
primitive and an independent model, and assert after each operation that:

- success/failure matches the model;
- successful calls produce the exact expected state;
- failing calls leave the pre-call state unchanged.

The saved proptest regression file keeps the self-transfer case that caught a
DRC20 accounting bug during this pass.

The extended invariant pass also found and fixed:

- a `VotingUnits::move_units` atomicity bug where an account checkpoint could
  be written before a later total-supply checkpoint rejected the operation;
- an `OwnerSet::init` atomicity bug where a later invalid owner could leave
  earlier owners in the set;
- a `TimelockController::execute_min_delay_change` atomicity bug where a
  malformed payload could mark an operation done before being rejected.

## Commands

Run the hardening tests with:

```sh
cargo test -p dusk-contract-standards
cargo test -p dusk-contract-standards --test properties
```

Run the long randomized hardening loop with:

```sh
start=$(date +%s)
end=$((start + 14400))
while [ "$(date +%s)" -lt "$end" ]; do
  PROPTEST_CASES=2048 PROPTEST_MAX_SHRINK_ITERS=8192 \
    cargo test -p dusk-contract-standards --test properties
done
```

On April 26, 2026, this loop ran for 14,404 seconds and completed 367 full
property-suite iterations without a failure.

On April 26, 2026, the extended 16-test property suite also passed a
4,096-case focused run:

```sh
PROPTEST_CASES=4096 PROPTEST_MAX_SHRINK_ITERS=8192 \
  cargo test -p dusk-contract-standards --test properties
```

The property suite now also honors `STANDARDS_PROPTEST_CASES` and
`STANDARDS_PROPTEST_MAX_SHRINK_ITERS`, which lets CI run longer without
editing the test source:

```sh
STANDARDS_PROPTEST_CASES=8192 STANDARDS_PROPTEST_MAX_SHRINK_ITERS=16384 \
  cargo test -p dusk-contract-standards --test properties
```

Forge data-driver ABI fuzzing covers JSON-to-rkyv input encoding, input
decoding, roundtrips, malformed JSON, bad shapes, unknown functions, and
mutated encoded payloads for the four standards reference contracts:

```sh
make standards-data-drivers
STANDARDS_DATA_DRIVER_FUZZ_CASES=2048 \
  cargo test -p dusk-contract-standards --test data_driver_fuzz -- --ignored
```

The `standards-hardening` workflow runs these longer property and data-driver
fuzz jobs on demand and nightly.

Run the full standards validation pass with:

```sh
cargo fmt
cargo test -p dusk-contract-standards
cargo build --release -Z build-std=core,alloc --target wasm32-unknown-unknown \
  -p authorization-counter \
  -p drc20-roles-pausable \
  -p drc721-collection \
  -p proxy-counter \
  --features authorization-counter/contract,drc20-roles-pausable/contract,drc721-collection/contract,proxy-counter/contract
cargo test -p dusk-contract-standards --test examples_vm -- --ignored
make standards-data-drivers
cargo test -p dusk-contract-standards --test data_driver_fuzz -- --ignored
cargo clippy -p dusk-contract-standards --all-targets -- -D warnings
```

## Next Research Items

The next hardening layer should add mutation testing for authorization and
pause paths, differential tests against independent client encoders, and
local-node scenario tests that intentionally mix successful transactions with
rejected transactions across block boundaries.
