# DRC20Phoenix

`DRC20Phoenix` is a Dusk-native private fungible token primitive. It is not a
public-balance DRC20 variant. It models ownership as private notes, spends as
nullifiers, and balances as wallet-local state reconstructed by scanning note
and nullifier streams.

The implementation lives in:

```text
standards/dusk-contract-standards/src/token/drc20_phoenix
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

The current branch does not include the final custom private-asset circuit or
prover keys. A production deployment requires verifier data for a circuit that
proves:

- input note inclusion under the supplied root
- note ownership/spend authorization
- nullifier correctness
- output note correctness
- asset/domain correctness
- value conservation:

```text
sum(inputs) + public_mint = sum(outputs) + public_burn
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

- final private-asset circuit
- audited prover/verifier data
- verifier-data packaging policy
- wallet SDK and scanning database
- local-node/RPC wallet-flow tests
- external audit of cryptographic constraints and public-input ordering
