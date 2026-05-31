# DRC20Phoenix

`DRC20Phoenix` is a Dusk-native private fungible token primitive. It is not a
public-balance DRC20 variant. It models ownership as private notes, spends as
nullifiers, and balances as wallet-local state reconstructed by scanning note
and nullifier streams.

The implementation lives in:

```text
standards/dusk-contract-standards/src/token/drc20_phoenix
```

The Forge reference contract lives in:

```text
standards/examples/drc20_phoenix
```

The first dedicated circuit package lives in:

```text
standards/drc20-phoenix-circuits
```

## Non-Goals

`DRC20Phoenix` deliberately does not provide:

- `balance_of`
- `allowance`
- `approve`
- `transfer_from`
- public `Transfer(from, to, amount)` events
- native DUSK gas/refund/deposit semantics
- `spend_and_execute`
- Moonlight account balances
- native transfer-contract balances

Those concepts are public-balance or native-transfer concepts. A private token
would lose its privacy guarantees if it exposed them directly.

## State Model

The token stores:

- metadata: name, symbol, decimals
- immutable `asset_id`
- chain id and contract id domain
- append-only private note tree
- note leaves for wallet scanning
- nullifier membership set for double-spend checks
- append-ordered nullifier log for stable wallet sync
- retained historical roots
- public minted and burned supply counters
- optional public mint cap
- admin id
- pause state
- verifier data

Private balances are not stored on chain. A wallet computes a balance by
scanning notes it can decrypt and subtracting notes whose nullifiers have been
spent.

## Asset Domain

The `asset_id` is derived from:

```text
DRC20Phoenix.asset.v1
chain_id
contract_id
metadata
deployment_salt
```

Every note, intent, and proof input is bound to:

```text
DRC20Phoenix
version
chain_id
contract_id
asset_id
mode
```

This prevents replay across contracts, assets, chains, and modes.

## Notes

`PrivateAssetNote` contains public encrypted-note data:

```rust
asset_id
owner_commitment
value_commitment
nonce
encrypted_payload
commitment
```

The note value is not public. Wallets use their viewing material to detect and
decrypt notes from the public note stream.

The contract checks that each note:

- belongs to the token `asset_id`
- has a commitment matching the note fields
- is bound by the proof public inputs

## Proof Inputs

The contract reconstructs the expected `PrivateAssetPublicInputs` and compares
them to the supplied proof inputs before verifier dispatch.

Public inputs include:

```text
version
chain_id
contract_id
asset_id
mode
root
nullifiers
output commitments
public mint amount
public burn amount
intent hash
```

The `intent_hash` binds the proof to the exact call and mode.

## Verifier Status

The production verifier path calls:

```rust
abi::verify_plonk(verifier_data, proof, public_inputs)
```

in contract builds.

Native non-contract builds reject proofs by default. This is intentional: a
permissive verifier must not accidentally ship. Unit tests use a private
`#[cfg(test)]` verifier that accepts only deterministic test proofs derived from
the exact public inputs.

The current branch includes a first fixed-arity custom private-asset circuit
package. It proves:

- input note inclusion under the supplied root
- note ownership through a private spend secret and owner commitment
- nullifier correctness
- output note correctness
- asset/domain correctness
- value conservation:

```text
sum(inputs) + public_mint = sum(outputs) + public_burn
```

The circuit uses Poseidon-compatible note commitments, nullifiers, Merkle
nodes, range checks, and standards public-input ordering. It is deliberately a
custom DRC20Phoenix circuit and not the native DUSK Phoenix `TxCircuit`.

The available upstream `phoenix-circuits` package was reviewed and remains the
native DUSK `TxCircuit` family. It binds gas/deposit/refund semantics and does
not expose a custom-asset proof statement with `asset_id` and token contract
domain. It is therefore intentionally not wired as the DRC20Phoenix production
circuit.

The current implementation provides the strict contract-side verifier boundary,
the public-input builder, the Forge reference wrapper, fixed-arity proof tests,
and verifier dispatch by version/mode/input/output arity. The branch also
contains generated Dusk-CRS verifier-data artifacts and a manifest under:

```text
standards/drc20-phoenix-circuits/verifier-data/
```

These artifacts are pinned by hash and generated from the official Dusk CRS
`devnet-piecrust.crs`, whose SHA-256 is:

```text
6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059
```

They still require circuit and artifact audit before mainnet use. There is no
permissive production fallback.

The v1 artifact tree height is `23`, giving `8,388,608` note slots. That target
is chosen to keep the append-only note/nullifier state in the right order of
magnitude for a 3 GB storage budget with the current note representation.

## Proving Performance

Use the dedicated benchmark to measure proving rather than the deployment
smoke scripts:

```bash
cargo +nightly-2026-02-27 run --release \
  -p drc20-phoenix-circuits \
  --example benchmark_drc20_phoenix_proving
```

The benchmark measures CRS loading, circuit compilation, witness and public
input construction, raw proving, verifier self-check, proof serialization,
proof size, verifier-data size, constraints, and process high-water memory.

Observed release-mode results on May 31, 2026 using the official Dusk CRS
`~/.dusk/rusk/devnet-piecrust.crs`:

```text
CRS load: 9.8s
Process peak RSS for full matrix: 1,328,556 KB
```

| height | proof | arity | constraints | compile | prove | verify | proof bytes |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 17 | mint | 0x2 | 7,963 | 1.5s | 0.6s | 0.005s | 1,008 |
| 17 | transfer | 1x2 | 31,921 | 6.0s | 2.0s | 0.004s | 1,008 |
| 17 | burn | 1x0 | 23,979 | 5.8s | 2.0s | 0.006s | 1,008 |
| 17 | transfer | 4x2 | 103,795 | 24.3s | 8.3s | 0.004s | 1,008 |
| 20 | mint | 0x2 | 7,963 | 1.5s | 0.5s | 0.008s | 1,008 |
| 20 | transfer | 1x2 | 34,924 | 11.8s | 4.0s | 0.004s | 1,008 |
| 20 | burn | 1x0 | 26,982 | 5.8s | 2.0s | 0.006s | 1,008 |
| 20 | transfer | 4x2 | 115,807 | 24.4s | 8.5s | 0.004s | 1,008 |
| 23 | mint | 0x2 | 7,963 | 1.5s | 0.5s | 0.007s | 1,008 |
| 23 | transfer | 1x2 | 37,927 | 11.8s | 4.1s | 0.004s | 1,008 |
| 23 | burn | 1x0 | 29,985 | 5.8s | 2.0s | 0.006s | 1,008 |
| 23 | transfer | 4x2 | 127,819 | 24.1s | 8.7s | 0.009s | 1,008 |

The most important result is that optimized raw proving is much faster than
the earlier end-to-end debug measurements. Height 23 adds about 6,006
constraints over height 17 for 1-input transfers and about 24,024 constraints
for 4-input transfers. That is meaningful but not enough to explain the prior
25-35 second per-transfer estimate by itself.

The local and testnet smoke scripts now run the proof-building helper in
release mode by default. Override with:

```bash
DRC20_PHOENIX_CARGO_RUN_PROFILE= ./scripts/drc20-phoenix-submit-follow-up-transfers.sh
```

only when intentionally debugging helper code.

### Persistent Proving Context And Cache

Wallet/client code should use `Drc20PhoenixProvingContext` from:

```rust
drc20_phoenix_circuits::proving
```

The context owns the CRS public parameters, lazily loads each mode/arity once,
and reuses the compiled or cached `Prover`/`Verifier` handles for repeated
mint, transfer, and burn proofs. This is the expected wallet integration shape:

1. load the Dusk CRS once at wallet startup or first private-token use
2. create a `Drc20PhoenixProvingContext`
3. load the needed arity once, typically transfer `1x2`
4. generate many proofs through the same context
5. keep the context alive while the wallet is building a batch

The context supports a local prover cache through `ProverCacheConfig`. Cached
entries are validated against:

- DRC20Phoenix cache format version
- circuit version/mode/input/output arity
- tree height
- CRS SHA-256
- transcript label
- prover artifact SHA-256
- verifier artifact SHA-256

The cache is intentionally local. Prover artifacts are large; the observed
height-23 transfer `1x2` prover artifact is about `323 MB`, while the verifier
artifact is about `1.4 KB`. Committing the full v1 prover set would be
impractical. Wallets should generate or download audited prover artifacts into
a user cache and fail closed on any manifest/hash mismatch.

Generate a cache entry with:

```bash
cargo +nightly-2026-02-27 run --release \
  -p drc20-phoenix-circuits \
  --example generate_prover_cache -- \
  --cache-dir target/drc20-phoenix-prover-cache \
  --only transfer-1x2
```

Generate the full v1 cache by omitting `--only`, but expect this to take
substantially longer and use significant disk space.

The smoke and testnet helper scripts default to:

```text
DRC20_PHOENIX_PROVER_CACHE_DIR=target/drc20-phoenix-prover-cache
DRC20_PHOENIX_PROVING_TIMINGS=1
```

Set `DRC20_PHOENIX_FORCE_PROVER_CACHE_REBUILD=1` to overwrite local artifacts.

### Repeated Transfer Benchmark

Run:

```bash
cargo +nightly-2026-02-27 run --release \
  -p drc20-phoenix-circuits \
  --example benchmark_drc20_phoenix_repeated_transfers -- \
  --transfers 50
```

With `DRC20_PHOENIX_PROVER_CACHE_DIR` pointing at a warm transfer `1x2` cache,
the observed May 31, 2026 result was:

```text
transfers=50
tree_height=23
crs_load_ms=9553
context_setup_ms=3964
artifact source=Cache
artifact load_ms=3873
prover_bytes=323031736
first_proof_ms=3920
median_proof_ms=4017
p95_proof_ms=4333
total_proof_ms=205332
total_wall_ms=218989
notes_generated=100
hwm_kb=715172
```

This is the current wallet-grade baseline: repeated private transfers amortize
setup and settle at roughly `4.0s` median proving time for height-23 transfer
`1x2`, with about `715 MB` peak RSS when using the cached prover path.

### Native Phoenix Comparison

Native Phoenix currently uses tree depth `17`. The available `rusk-prover`
fixture is a native 4-input/2-output transfer proof and uses cached prover keys.
A warm release-mode run of:

```bash
cargo test --release -p rusk-prover test_prove_tx_circuit -- --nocapture
```

completed in `43.05s` wall clock with peak RSS around `1.41 GB`. This includes
loading cached native prover data and running the test harness; it is not a raw
`prove()` timing and is not apples-to-apples with the DRC20Phoenix benchmark.

The closest DRC20Phoenix arity row is height-17 transfer `4x2`, which compiled
in `24.3s` and proved in `8.3s`, with peak process RSS for the full benchmark
matrix around `1.33 GB`. The circuit statements differ: native Phoenix includes
native DUSK fee/deposit/refund semantics, while DRC20Phoenix includes custom
asset id, contract id, mode, public mint/burn, and token-domain separation.

### Tree-Size Direction

Height 23 remains a reasonable v1 default for the current storage target. If
wallet-grade proving needs to go lower than roughly 4 seconds for 1-input
transfers or 9 seconds for 4-input transfers, the next work should focus on
prover-key caching/distribution, wallet-side persistent proving contexts, and
circuit shape review before reducing the tree height.

Longer-term alternatives remain open:

- epoch trees with migration between epochs
- append-only forests with multiple retained roots
- token-instance sharding
- rolling note trees with explicit migration notes

Those designs trade simpler wallet scanning and proof statements for lower
per-proof Merkle depth. They should be handled as a separate design change, not
as an unreviewed tweak to the current circuit.

## V1 Arity Matrix

The v1 verifier set is deliberately small and fixed:

```text
mint:     0 inputs / 1 output
mint:     0 inputs / 2 outputs
transfer: 1 input  / 2 outputs
transfer: 2 inputs / 2 outputs
transfer: 3 inputs / 2 outputs
transfer: 4 inputs / 2 outputs
burn:     1..4 inputs / 0..2 outputs
```

Transfers always use two outputs in v1 so wallets can naturally represent a
recipient note plus a change note. Burns allow zero change outputs for full
burns and one or two change outputs for partial burns. Unsupported arities are
rejected before any state mutation.

Verifier entries are keyed by:

```text
version
mode
input_count
output_count
```

`Init` requires a complete v1 verifier set with no duplicate keys. Each entry
stores its verifier data and a pinned hash. Query APIs expose
`verifier_manifest_hash` and `verifier_manifest`.

## Forge Reference Contract

The Forge reference exposes:

```text
metadata
name
symbol
decimals
version
asset_id
root
root_exists
opening
num_notes
existing_nullifiers
sync
sync_nullifiers
minted_supply
burned_supply
net_supply
cap
paused
verifier_data_hash
verifier_manifest_hash
verifier_manifest
build_public_inputs
mint_private
transfer_private
burn_private
pause
unpause
```

Build commands:

```bash
cd standards
cargo build -p drc20-phoenix-reference --target wasm32-unknown-unknown --release --features contract
cargo build -p drc20-phoenix-reference --target wasm32-unknown-unknown --release --features data-driver
```

The data-driver build is intended for client JSON encoding/decoding of contract
calls, query outputs, and events.

## Client Flow Example

The example:

```bash
cd standards
cargo run -p dusk-contract-standards --example build_drc20_phoenix_flow
```

constructs mint, transfer, and burn call payloads with domain-bound public
inputs. It still uses placeholder proof bytes for the generic call example;
proof generation is covered in the dedicated `drc20-phoenix-circuits` crate.

Development verifier artifacts can be regenerated with:

```bash
cd standards
cargo +nightly-2026-02-27 run -p drc20-phoenix-circuits \
  --example generate_verifier_data -- \
  drc20-phoenix-circuits/verifier-data
```

## Mint Flow

`mint_private`:

1. requires the configured admin id
2. requires the token to be unpaused
3. checks chain id, contract id, and asset id
4. checks output notes are well formed
5. checks cap and supply arithmetic
6. reconstructs proof public inputs
7. verifies proof
8. appends output notes
9. updates `minted_supply`
10. checkpoints the new root

The mint amount is public. Recipient balances are private.

## Transfer Flow

`transfer_private`:

1. requires the token to be unpaused
2. checks chain id, contract id, and asset id
3. checks the supplied root is retained
4. rejects duplicate or spent nullifiers
5. checks output notes are well formed
6. reconstructs proof public inputs
7. verifies proof
8. appends nullifiers to the membership set and append log
9. appends output notes
10. checkpoints the new root

The transfer amount, sender, and recipient are not public.

## Burn Flow

`burn_private`:

1. requires the token to be unpaused
2. checks chain id, contract id, and asset id
3. checks the supplied root is retained
4. rejects duplicate or spent nullifiers
5. checks change notes are well formed, if any
6. checks burn supply arithmetic
7. reconstructs proof public inputs
8. verifies proof
9. appends nullifiers and change notes
10. updates `burned_supply`
11. checkpoints the new root

The burn amount is public. Input values and change values are private.

## Wallet Scanning

Wallets should:

1. call `sync(from, count_limit)` to fetch note leaves
2. test ownership locally with viewing material
3. decrypt owned note values locally
4. compute candidate nullifiers locally
5. call `sync_nullifiers(from, count_limit)` to update spent state
6. compute balance as the sum of owned unspent notes

`existing_nullifiers` is useful for targeted checks, but it may leak interest in
specific nullifiers to infrastructure. Prefer append-log sync when privacy
against the queried node matters.

## Events

Private events expose only public proof outputs:

- `PrivateMintEvent`: asset id, public amount, output notes, new root
- `PrivateTransferEvent`: asset id, nullifiers, output notes, new root
- `PrivateBurnEvent`: asset id, public amount, nullifiers, change notes, new root
- pause/unpause events

No event exposes sender, recipient, or private transfer amount.

## Security Notes

The implementation checks:

- initialized state
- admin authorization for mint/pause/unpause
- pause on mint/transfer/burn
- chain/contract/asset domain
- retained roots
- duplicate nullifiers in the same transaction
- already-spent nullifiers
- output note commitments
- proof public input equality
- proof verification result
- checked supply arithmetic
- cap enforcement
- failed-operation atomicity in tests

Remaining production requirements:

- external audit of the circuit and generated verifier-data manifest
- production artifact review for the Dusk-CRS-generated verifier set
- wallet SDK and scanning database
- broader wallet SDK/indexer RPC tests beyond the reference smoke
- external audit of cryptographic constraints and public-input ordering

## Local `rusk-private` Smoke

The smoke preflight is:

```bash
./scripts/drc20-phoenix-local-rusk-private-smoke.sh
```

It builds the standards crate, Forge reference contract, data-driver, circuit
tests, Dusk-CRS verifier manifest, and client payload example. Proof-building
helpers run in release mode by default. By default,
the script refuses to submit RPC transactions unless explicitly forced:

```bash
DRC20_PHOENIX_REAL_CIRCUIT=1 \
DRC20_PHOENIX_VERIFIER_DATA_DIR=/path/to/verifier-data \
RUSK_PRIVATE_BIN=/path/to/rusk \
RUSK_WALLET_BIN=/path/to/rusk-wallet \
./scripts/drc20-phoenix-local-rusk-private-smoke.sh
```

This fail-closed behavior is intentional. A local-node mint/transfer/burn smoke
must not be made green by using a test verifier or the native DUSK Phoenix
transaction circuit.

Observed local status on this branch:

- the standards tests, Forge contract build, data-driver build, verifier-data
  generation, and client payload builder run successfully inside the smoke
  script
- the dedicated DRC20Phoenix circuit proof tests run successfully inside the
  smoke script
- local `rusk-private` starts with `DUSK_CONSENSUS_KEYS_PASS=password` against
  the example genesis state
- the matching `rusk-wallet` 0.3.0 binary restores the local funded faucet
  mnemonic in legacy mode
- the Forge reference deploys over RPC with the generated verifier manifest
- real private-asset proofs are submitted for mint, transfer, and burn
- negative RPC calls reject a mutated transfer proof, replayed transfer
  nullifiers, and mint while paused without changing the checked state
- the smoke verifies note counts, minted supply, burned supply, net supply, and
  pause state through contract queries

Latest local attempt after adding the prover cache:

```text
DRC20_PHOENIX_SKIP_BUILD=1 DRC20_PHOENIX_REAL_CIRCUIT=1 \
  ./scripts/drc20-phoenix-local-rusk-private-smoke.sh
```

The helper generated real proof call arguments with the cached proving context
active, but the local deployment did not land:

```text
Rusk error occurred: Unsupported operation
expected version == 1
```

That is the current local-node blocker for this branch. The proof-generation
side of the local flow is working; the failing step is the local
`rusk-wallet`/node contract deployment path.

Latest testnet follow-up against the height-23 contract:

```text
contract_id=396a1db75c1cc797b53b9be1964dfb552d373e9290587337e4e4c3b34bc59125
tx=c69b9513525550e8b9f42699744855f30940d54e211bf1084ed9768c77903237
num_notes: 48 -> 50
minted_supply=100
burned_supply=25
net_supply=75
submitted=1
```
