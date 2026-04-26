# Dusk Contract Standards Hardening Track

This branch is a separate hardening track for the Dusk-native standards layer.
It keeps implementation work close to the contracts, but treats security
validation as a first-class deliverable rather than a final smoke test.

## Current Scope

The first hardening pass focuses on invariants that should hold regardless of
the composing contract:

- signed authorization must bind contract, domain, action id, payload hash,
  nonce, principal, and expiry before nonce/replay state is consumed;
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
- the reserved zero principal must not be accepted as an actor, recipient,
  spender, minter, burner, or operator where that would create ownership or
  authorization state.

## Added Validation

`standards/dusk-contract-standards/tests/properties.rs` adds property-based
state-machine tests for:

- action-bound authorization rejection cases;
- mixed owner sets;
- access-control role/admin mutation;
- timelock scheduling, execution, cancellation, and delay mutation;
- upgrade-admin prepare, activate, cancel, rollback, and finalization flows;
- DRC20 accounting and allowance flows;
- DRC721 ownership, approval, operator, balance, and enumerable views.

The tests generate random operation sequences, run them against the real
primitive and an independent model, and assert after each operation that:

- success/failure matches the model;
- successful calls produce the exact expected state;
- failing calls leave the pre-call state unchanged.

The saved proptest regression file keeps the self-transfer case that caught a
DRC20 accounting bug during this pass.

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
cargo clippy -p dusk-contract-standards --all-targets -- -D warnings
```

## Next Research Items

The next hardening layer should add ABI-level fuzzing of Forge call payloads,
longer-running property tests in CI, mutation testing for authorization and
pause paths, and local-node scenario tests that intentionally mix successful
transactions with rejected transactions across block boundaries.
