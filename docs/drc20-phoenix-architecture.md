# DRC20Phoenix Private Fungible Token Standard

## Executive Conclusion

A Dusk-native private fungible token standard is feasible, but it should not be
modeled as DRC20 balances with Phoenix signatures. Phoenix signatures authorize
actions, but they do not hide balances or transfers. A private fungible token
must instead be modeled as a private note system: append-only note tree, note
commitments, nullifiers, historical roots, proof verification, and wallet-side
scanning.

Recommended standard name: `DRC20Phoenix`.

Use `DRC20Shielded` only as a broader umbrella if future standards support
non-Phoenix shielded schemes. For a standard based on Dusk's existing Phoenix
flow, `DRC20Phoenix` is more precise.

The native Phoenix transfer stack is the right architectural reference for the
state machine and wallet model. The existing `PhoenixTransaction` and
`TxCircuit` types, however, are native-DUSK transfer types rather than a
complete custom-asset abstraction. They include gas, deposit, refund, fixed
native transfer semantics, and verifier data for the genesis transfer contract.
The current public inputs also do not provide a custom asset id or token
contract domain, so they are not sufficient as the canonical proof statement
for arbitrary private assets.

The practical conclusion is:

- Pure contract feasibility: feasible for the contract state machine and
  verifier-call pattern, assuming contracts can bundle verifier data and call
  `abi::verify_plonk`.
- Not feasible using native `PhoenixTransaction` unchanged: a production
  private-token standard needs a custom private asset transaction type, custom
  note commitment domain, and custom circuit/prover/verifier data.
- Protocol or host support is only required if the token should behave like a
  native asset: paying gas in the private token, participating in the native
  transaction entrypoint, or reusing transfer-contract refund/deposit machinery.
  For a normal smart-contract token whose gas is paid in native DUSK, this can
  remain an application-level contract plus circuit/prover/client standard.

Implementation status on this branch:

- `standards/dusk-contract-standards/src/token/drc20_phoenix` implements the
  first standards-layer state machine, type model, verifier boundary,
  append-only note tree, root retention, nullifier set/log, mint, transfer,
  burn, pause, and tests.
- The production path is intentionally strict: it calls the host PLONK verifier
  in contract builds and rejects proofs in native non-contract builds. Native
  tests use a `#[cfg(test)]` verifier that cannot be imported by downstream
  contracts.
- This branch includes a first custom fixed-arity private-asset circuit package
  and development-generated verifier-data artifacts. The circuit and artifacts
  are not yet externally audited and are not mainnet-production CRS artifacts.
- `standards/examples/drc20_phoenix` adds a Forge reference wrapper and
  data-driver build target around the standards primitive.
- `standards/drc20-phoenix-circuits` adds the first dedicated fixed-arity
  private-asset circuit package. It proves Poseidon note commitments,
  nullifiers, Merkle inclusion, range checks, and value conservation using the
  same public-input ordering as the standards primitive.
- The standards primitive now dispatches verifier data by
  `(version, mode, input_count, output_count)` and requires a complete pinned v1
  verifier manifest at initialization.
- `scripts/drc20-phoenix-local-rusk-private-smoke.sh` adds a fail-closed local
  `rusk-private` preflight. It builds the standards crate, Forge reference, and
  client flow, regenerates development verifier data, and runs the circuit
  proof tests, but refuses RPC submission until wallet RPC transaction builders
  submit real DRC20Phoenix proofs end to end.

## Relationship To `genesis/transfer`

The genesis transfer contract can be viewed as three layers:

1. Reusable Phoenix state mechanics.
2. Native DUSK transaction execution.
3. Host/protocol-only management hooks.

`DRC20Phoenix` should reuse the first layer and avoid copying the second and
third layers.

## Reusable Transfer-Contract Concepts

### Append-Only Note Tree

`genesis/transfer/src/tree.rs` stores a Merkle tree of note hashes plus a
separate `Vec<NoteLeaf>` containing full notes and block heights. Spent notes
remain in the tree; spending is represented by adding nullifiers to a nullifier
set.

The reusable shape is:

```rust
struct PrivateNoteTree {
    merkle_tree: NotesTree,
    leaves: Vec<PrivateNoteLeaf>,
}
```

The key behaviors should be preserved:

```rust
push(note_leaf) -> Option<note>
extend_notes(block_height, notes) -> Vec<note>
root() -> BlsScalar
opening(pos) -> Option<NoteOpening>
leaves_pos(from) -> Iterator<PrivateNoteLeaf>
leaves_len() -> u64
```

For `DRC20Phoenix`, this should operate over a `PrivateAssetNote` type rather
than native `phoenix::Note`.

### Wallet Query And Sync APIs

The transfer contract exposes the query shape a wallet needs:

```rust
root()
opening(pos)
existing_nullifiers(nullifiers)
num_notes()
sync(from, count_limit)
sync_nullifiers(from, count_limit)
```

`DRC20Phoenix` should retain these APIs almost exactly.

One important improvement: the transfer contract stores nullifiers in a
`BTreeSet` and syncs by skipping into that sorted set. That is fine for
membership, but it is not a stable append-order cursor because newly inserted
nullifiers may sort before a previously synced cursor. A token standard should
store both:

```rust
nullifier_set: BTreeSet<Nullifier>, // membership checks
nullifier_log: Vec<Nullifier>,      // stable sync order
```

Then `sync_nullifiers(from, count_limit)` streams from `nullifier_log[from..]`.

### Nullifier Set

The transfer contract rejects double spends by inserting each nullifier into a
set and rejecting duplicates. The same model applies:

```rust
if !nullifier_set.insert(nullifier) {
    panic!("DRC20Phoenix: nullifier already spent");
}
```

For a reusable standard, prefer verifying all transaction invariants before
mutation. If mutation-before-proof is used, rollback semantics must be explicit
and tested.

Also reject duplicate nullifiers inside a single transaction before mutating
state.

### Historical Roots

The transfer contract keeps a fixed-size root ring buffer and rejects spends
whose root is not retained. `DRC20Phoenix` should retain a historical root
window as well.

Recommended storage:

```rust
root_ring: RingBuffer<BlsScalar, MAX_ROOTS>
root_set: BTreeSet<BlsScalar>
```

The ring provides bounded retention. The set provides efficient membership.
When evicting a root from the ring, also remove it from `root_set`.

Unlike the genesis transfer contract, a normal token contract should checkpoint
roots automatically after successful `mint_private`, `transfer_private`, and
`burn_private`, and should insert the initial empty root at deployment.

### Proof Verification Pattern

The transfer contract verifies Phoenix proofs with `abi::verify_plonk` and
selects verifier data by circuit arity. This call pattern is reusable:

```rust
let verifier = verifier_set.lookup(mode, num_inputs, num_outputs);
if !abi::verify_plonk(verifier.data, tx.proof, tx.public_inputs()) {
    panic!("DRC20Phoenix: invalid proof");
}
```

The verifier data and public inputs must correspond to a new private asset
circuit, not the native DUSK `TxCircuit`.

### Wallet Scanning Model

The native tests show the right client model:

1. Fetch leaves.
2. Filter notes locally with a Phoenix view key.
3. Decrypt owned values locally.
4. Fetch openings by note position.
5. Generate nullifiers locally.
6. Query or sync spent nullifiers.

`DRC20Phoenix` should standardize this model. The contract does not provide
`balance_of`; wallets reconstruct balances from owned unspent notes.

## Native Transfer Semantics Not To Copy

### `spend_and_execute`

`spend_and_execute` is the native top-level transaction path. It validates gas,
sets transitory transaction state, dispatches to Phoenix or Moonlight spending,
and executes an optional contract call.

A custom private token should not expose this. Users submit normal Dusk
transactions that call token methods such as:

```rust
transfer_private(private_asset_tx)
```

The transaction pays gas in native DUSK. The token contract only verifies and
mutates private token state.

### Gas And Refund Notes

Native Phoenix transactions include gas limit, gas price, max fee, and refund
mechanics. `DRC20Phoenix` should not create token refund notes for unused DUSK
gas. Gas accounting is outside private token accounting.

### Deposit, Withdraw, And Convert

`deposit`, `withdraw`, and `convert` implement native value movement between
Phoenix, Moonlight, and contract balances. They depend on transitory transaction
state and `TRANSFER_CONTRACT` assumptions.

Do not inherit these semantics. Bridge APIs should be separate later work:

```rust
shield_from_drc20(...)
unshield_to_drc20(...)
```

### Protocol Contract Identities

The transfer contract is reserved protocol infrastructure and uses identities
such as `TRANSFER_CONTRACT` and `STAKE_CONTRACT`. A private token must use its
own contract id, asset id, and admin model.

### Moonlight Accounts And Contract Balances

`accounts` and `contract_balances` exist because the genesis transfer contract
manages native public balances. `DRC20Phoenix` should not store per-owner public
balances. It may store public supply counters and admin state; private balances
are wallet-local.

### Native DUSK Value Conservation

Native Phoenix transactions conserve DUSK value across transfer amount, gas,
deposit, and refund. A custom token needs asset-local conservation:

```text
sum(input_token_values) + public_mint_amount
=
sum(output_token_values) + public_burn_amount
```

There is no token gas or native deposit term in this equation.

## Why Native `PhoenixTransaction` Is Not Enough

The existing native Phoenix transaction types can inspire the implementation,
but should not be the production standard for custom assets.

Reasons:

1. Native note construction in the inspected flow does not expose an asset id.
2. Native transaction construction is built around transfer value, deposit, gas
   limit, gas price, chain id, and optional native transaction data.
3. The public inputs bind native transaction payload fields, but not a custom
   token contract id or asset id.
4. Existing verifier data targets native `TxCircuit` variants.
5. The native spend path appends outputs to the native DUSK Phoenix tree and
   emits native Phoenix transaction events.

A narrow experiment could try existing native circuits with zero fee and zero
deposit, but that would be fragile and should not be standardized. A proper
standard needs asset-domain separation.

## Custom Private Asset Proof Statement

`DRC20Phoenix` needs a private asset circuit whose public inputs are explicitly
bound to the asset and contract.

Recommended public inputs:

```text
domain_separator
version
chain_id
contract_id
asset_id
mode
root
nullifiers[N]
output_note_commitments[M]
public_mint_amount
public_burn_amount
intent_hash
```

`intent_hash` should bind the proof to the intended contract call:

```text
H(
  "DRC20Phoenix.intent",
  chain_id,
  contract_id,
  asset_id,
  mode,
  root,
  nullifiers,
  output_commitments,
  public_mint_amount,
  public_burn_amount,
  memo_hash
)
```

Recommended witness data:

```text
input notes
input note values
input value blinders
input spend secrets
input Merkle openings
output note values
output value blinders
output recipient keys / stealth randomness
output encryption randomness
```

The circuit should prove:

1. Every input and output note is for the same `asset_id`.
2. Note commitments are computed in the `DRC20Phoenix` domain.
3. Every input note is included under the supplied historical root.
4. The prover controls the input notes' spend secrets.
5. Nullifiers are derived correctly from note secrets and asset domain.
6. Output notes are well-formed and match the public commitments.
7. Values are conserved:

   ```text
   sum(inputs) + public_mint_amount
   =
   sum(outputs) + public_burn_amount
   ```

8. Values are range-checked.
9. The proof is bound to chain id, contract id, asset id, entrypoint, and mode.

Recommended modes:

```rust
enum PrivateAssetCircuitMode {
    Transfer,
    Mint,
    Burn,
}
```

If practical, use a common circuit equation for all modes:

```text
sum(inputs) + mint = sum(outputs) + burn
```

Then enforce mode-specific policy in the contract.

## Recommended Contract State

```rust
pub struct Drc20PhoenixState {
    metadata: TokenMetadata,
    asset_id: BlsScalar,
    version: u32,

    tree: PrivateNoteTree,
    nullifier_set: BTreeSet<BlsScalar>,
    nullifier_log: Vec<BlsScalar>,
    root_ring: RootRingBuffer,
    root_set: BTreeSet<BlsScalar>,

    minted_supply: u128,
    burned_supply: u128,
    cap: Option<u128>,

    admin: AdminConfig,
    paused: bool,

    verifier_set: VerifierSet,
}
```

Metadata can follow DRC20 naming:

```rust
struct TokenMetadata {
    name: String,
    symbol: String,
    decimals: u8,
}
```

Do not reuse DRC20 balances, allowances, or `transfer_from`.

Derive `asset_id` immutably:

```text
asset_id = H(
  "DRC20Phoenix.asset",
  chain_id,
  contract_id,
  metadata_hash,
  deployment_salt
)
```

Even if each contract is single-asset, include `asset_id` in the note and proof
domain to prevent replay or note confusion across contracts, assets, chains, or
future multi-asset extensions.

Use public supply accounting in v1:

```rust
net_supply = minted_supply - burned_supply
```

This reveals total mint and burn amounts, but not balances or transfers. Hidden
total supply is a separate research problem and should not block v1.

## Recommended API

### Metadata

```rust
metadata() -> TokenMetadata
name() -> String
symbol() -> String
decimals() -> u8
asset_id() -> BlsScalar
version() -> u32
```

### Shielded Queries

```rust
root() -> BlsScalar
root_exists(root: BlsScalar) -> bool
opening(pos: u64) -> Option<PrivateNoteOpening>
num_notes() -> u64
existing_nullifiers(nullifiers: Vec<BlsScalar>) -> Vec<BlsScalar>
```

### Sync

```rust
sync(from: u64, count_limit: u64)
sync_nullifiers(from: u64, count_limit: u64)
```

`sync` streams `PrivateNoteLeaf`.

`sync_nullifiers` streams `nullifier_log`, not sorted set order.

### Supply

```rust
minted_supply() -> u128
burned_supply() -> u128
net_supply() -> u128
cap() -> Option<u128>
```

### State-Changing Calls

#### `mint_private`

```rust
mint_private(mint: PrivateMint)
```

Contract checks:

```text
not paused
admin authorized
asset_id matches
amount > 0
minted_supply + amount <= cap, if cap exists
proof verifies output well-formedness and sum(outputs) == amount
append outputs
minted_supply += amount
checkpoint root
emit PrivateMintEvent
```

#### `transfer_private`

```rust
transfer_private(tx: PrivateTransfer)
```

Contract checks:

```text
not paused
asset_id matches
root is retained
nullifiers are unique and unspent
proof verifies inclusion, ownership, nullifiers, outputs, and conservation
append nullifiers
append outputs
checkpoint root
emit PrivateTransferEvent
```

#### `burn_private`

```rust
burn_private(burn: PrivateBurn)
```

Contract checks:

```text
not paused
asset_id matches
amount > 0
root is retained
nullifiers are unique and unspent
proof verifies sum(inputs) == sum(outputs) + amount
append nullifiers
append change outputs
burned_supply += amount
checkpoint root
emit PrivateBurnEvent
```

### Later Bridge APIs

```rust
shield_from_drc20(...)
unshield_to_drc20(...)
```

Do not include these in v1 unless public DRC20 bridge semantics are already
stable.

## Events

Private transfers cannot emit `from`, `to`, or `amount` without destroying
privacy. Events should expose public proof outputs only:

```rust
struct PrivateTransferEvent {
    asset_id: BlsScalar,
    nullifiers: Vec<BlsScalar>,
    notes: Vec<PrivateAssetNote>,
    memo: Option<Vec<u8>>,
}
```

Mint and burn events may include public amounts:

```rust
struct PrivateMintEvent {
    asset_id: BlsScalar,
    amount: u64,
    notes: Vec<PrivateAssetNote>,
}

struct PrivateBurnEvent {
    asset_id: BlsScalar,
    amount: u64,
    nullifiers: Vec<BlsScalar>,
    change_notes: Vec<PrivateAssetNote>,
}
```

## Wallet And Client Flow

A `DRC20Phoenix` wallet reconstructs balances locally.

Per asset, the wallet stores:

```text
contract_id
asset_id
metadata
view key
spend key
last_note_pos
last_nullifier_pos
owned note database
```

Scanning:

1. Call `sync(from, count_limit)`.
2. For each `PrivateNoteLeaf`, test ownership locally with the view key.
3. If owned, decrypt value and store note position, commitment, value, and
   candidate nullifier.
4. Call `sync_nullifiers(from, count_limit)` and mark owned notes spent when
   their nullifier appears.
5. Compute balance as the sum of owned unspent notes.

`existing_nullifiers(my_candidates)` is useful but can leak wallet interest in
specific nullifiers to infrastructure. Prefer full nullifier sync when privacy
against the queried node matters.

Transfer construction:

1. Select input notes.
2. Fetch `opening(pos)` for each input.
3. Select a recent retained root.
4. Construct recipient and change output notes.
5. Build `intent_hash`.
6. Generate proof locally or through an explicitly trusted prover.
7. Submit a normal Dusk transaction calling `transfer_private`.
8. Rescan notes and nullifiers after confirmation.

## Relationship To DRC20

`DRC20Phoenix` should be a sibling standard:

```text
token/drc20          // public balances and allowances
token/drc20_phoenix  // private note/nullifier fungible asset
```

Shared concepts:

```text
metadata
ownable/access control
mint authority
pausable policy
multisig/timelock administration
```

Not shared:

```text
balance_of
allowance
approve
transfer_from
Transfer(from, to, amount)
```

## Security Considerations

### Double Spend Prevention

Reject:

```text
nullifier already in set
duplicate nullifier inside one transaction
nullifier not proven to derive from an input note
```

Invalid proofs must not insert nullifiers or append notes.

### Root Window

Roots should be retained long enough for wallet UX and short enough to bound
state. Expose:

```rust
root_exists(root)
```

Checkpoint automatically after accepted state transitions.

### Asset Domain Separation

Every note commitment, nullifier, and proof intent must bind:

```text
standard version
chain_id
contract_id
asset_id
mode / entrypoint
```

This is the most important difference from native Phoenix.

### Supply Inflation

Minting requires:

```text
admin authorization
public mint amount
proof binding outputs to mint amount
cap check
checked arithmetic
event emission
```

Use `u128` for cumulative public supply even if note values are `u64`.

### Burn Accounting

Burn proof must bind:

```text
sum(inputs) = sum(change_outputs) + public_burn_amount
```

The contract must not trust a user-supplied burn amount without proof binding.

### Verifier Misuse

Risks:

```text
wrong verifier data for arity
wrong circuit mode
public input ordering mismatch
proof generated for old version
silent verifier upgrade
```

Mitigations:

```text
versioned verifier ids
verifier hash query
shared public input builder
immutable verifier data for v1, or timelocked/multisig upgrades
```

### Client Privacy Leaks

Risks:

```text
querying openings one-by-one only for owned notes
calling existing_nullifiers only with owned candidates
remote prover observing witnesses
unique sync ranges
```

Mitigations:

```text
batch sync
full nullifier stream where practical
local proving by default
explicit remote-prover threat model
```

### Storage And DoS

Every note and nullifier is permanent. Define:

```text
tree depth
max inputs
max outputs
max proof size
max memo size
sync pagination limits
```

Confirm whether the native Phoenix tree depth is appropriate for custom
fungible tokens; popular tokens may need a larger tree.

## Testing Plan

### Positive Tests

- Deploy and query metadata, asset id, initial root, and note count.
- Authorized private mint creates notes and increases public minted supply.
- Valid private transfer with one input and two outputs.
- Valid private transfer with max supported inputs.
- Receiver wallet discovers received notes by scanning.
- Sender wallet discovers change notes by scanning.
- Valid private burn updates burned supply and leaves change notes.
- `sync`, `opening`, `num_notes`, and `sync_nullifiers` return consistent
  append-order data.

### Negative Tests

- Submit the same transaction twice.
- Spend the same note in two different transactions.
- Include duplicate nullifiers in one transaction.
- Use unknown, stale, or wrong-contract roots.
- Use wrong chain id, contract id, asset id, or mode.
- Mutate proof bytes, public inputs, outputs, or nullifiers after proving.
- Attempt unauthorized mint.
- Exceed cap or overflow supply counters.
- Burn amount does not match proof.
- Invalid proof leaves nullifier, note, and supply state unchanged.

### Property Tests

For arbitrary accepted mint/transfer/burn sequences in a test harness that knows
all note values:

```text
minted_supply - burned_supply = sum(unspent private notes)
```

Also assert:

```text
no duplicate accepted nullifiers
every opening verifies
paginated sync has no gaps or duplicates
boundary values are handled correctly
```

### VM And Local-Node Tests

VM tests should cover proof verification, rollback on panic, event emission,
and integration with access/multisig administration.

Local-node tests should cover wallet scanning over RPC/indexer paths, mempool
double-spend races, root windows across blocks, remote prover integration, and
data-driver encoding.

## Implementation Phases

### Phase 0: ADR And Proof Specification

Deliver:

```text
note format
asset id derivation
public input ordering
circuit mode definitions
event schema
wallet sync requirements
verifier-data manifest and hash-pinning policy
```

### Phase 1: Generic Contract Utilities

Extract or reimplement from `genesis/transfer`:

```text
append-only note tree
root ring/set
nullifier set/log
sync/opening helpers
verifier dispatch helper
```

Do not import native `TransferState`.

### Phase 2: Private Asset Types

Define:

```rust
PrivateAssetNote
PrivateAssetLeaf
PrivateTransfer
PrivateMint
PrivateBurn
PrivateAssetProofPublicInputs
```

All types should be versioned and domain-separated.

### Phase 3: Circuit And Prover

Implement circuits for:

```text
transfer: 1..N inputs, M outputs
mint: 0 inputs, M outputs, public mint
burn: 1..N inputs, M outputs, public burn
```

The branch now starts with a conservative fixed v1 matrix:

```text
mint: 0 inputs / 1..2 outputs
transfer: 1..4 inputs / 2 outputs
burn: 1..4 inputs / 0..2 outputs
```

Expand only when needed.

### Phase 4: Minimal Contract

Implement:

```rust
metadata
asset_id
root
opening
num_notes
sync
sync_nullifiers
existing_nullifiers
mint_private
transfer_private
```

### Phase 5: Burn, Cap, Admin, And Events

Add:

```rust
burn_private
cap
pause
role-based mint authority
multisig integration
event schema
```

### Phase 6: Wallet SDK And Data Driver

Deliver:

```text
scanner
note database
balance reconstruction
transaction builder
proof generation adapter
RPC/data-driver support
test vectors
```

### Phase 7: Bridges

Only after the base standard is audited:

```text
shield_from_drc20
unshield_to_drc20
indexer conventions
explorer display
audit/viewing-key support
```

## Open Questions

1. Which production CRS/public parameters should be pinned for audited verifier
   data?
2. Should Phoenix core note primitives be extended with asset ids, or should
   `DRC20Phoenix` define `PrivateAssetNote` independently?
3. What tree depth is required for popular custom fungible tokens?
4. Should v1 transfer remain two-output only after wallet UX testing?
5. Is public total minted/burned supply acceptable for v1?
6. Should roots be retained by block window, note count, or fixed ring size?
7. Should wallets derive per-asset viewing keys to reduce cross-asset
   correlation?
8. What bridge semantics should be used for transparent DRC20 integration?
9. Should verifier data stay immutable forever, or can a timelocked/multisig
   migration flow replace it after audit?

## Final Recommendation

Build `DRC20Phoenix` as a sibling to DRC20, sharing only metadata and
administration traits.

Reuse the genesis transfer contract's architecture for:

```text
append-only note tree
note leaves
openings
historical roots
nullifier set
sync APIs
wallet scanning model
PLONK verifier call pattern
```

Do not copy:

```text
spend_and_execute
refund
gas accounting
deposit/withdraw/convert
Moonlight accounts
contract balances
TRANSFER_CONTRACT assumptions
STAKE_CONTRACT mint semantics
native PhoenixTransaction as the token transaction type
```

The central deliverable is not a contract wrapper around native Phoenix
transactions. The central deliverable is a custom private asset note format and
circuit whose proof statement binds value conservation to `asset_id`,
`contract_id`, and `chain_id`.
