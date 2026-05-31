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
tests, Dusk-CRS verifier manifest, and client payload example. By default,
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
