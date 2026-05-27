# Dusk Contract Standards

This branch adds Dusk-native reusable contract standards rather than a semantic
copy of an EVM library. The goal is to provide secure building blocks that fit
the Dusk execution model, storage model, and client model.

## Layout

- `standards/dusk-contract-standards`: reusable primitives, native tests, and
  ignored VM tests for the Wasm examples.
- `standards/examples/authorization_counter`: a Forge counter controlled by
  replay-protected Moonlight BLS or Phoenix Schnorr signatures.
- `standards/examples/drc20_roles_pausable`: a Forge fungible-token
  reference with roles, pause control, cap policy, vote checkpoints, signed
  approvals, events, and reentrancy protection.
- `standards/examples/drc721_collection`: a Forge collection composition with
  owner control, pause control, approvals, royalties, events, and token
  metadata.
- `standards/examples/multisig_controller`: a Forge standalone multisig
  controller that can own/administer other contracts through a contract
  principal, with proposals, confirmations, tombstones, typed events, and
  Dusk-native signed owner approvals.
- `standards/examples/proxy_counter`: a Forge upgrade-admin and state-store
  example showing how proxy-like upgrade policy can be modeled without
  pretending Dusk has EVM delegatecall semantics.

## Design Notes

Dusk identity is not a single address type. The shared `Principal` abstraction
distinguishes Moonlight public accounts, Phoenix authorization identities, and
contracts. `OwnerSet` lets a composing contract accept a mixed ownership policy
instead of forcing everything into an Ethereum-style address. Contracts can use
`CallContext::current()` for runtime Moonlight and inter-contract calls, while
Phoenix flows should pass an explicit authorization identity plus a nonce or
replay key when the application needs that model.
For Moonlight transactions routed through the transfer contract, the standards
layer treats the root transfer-contract call into the target as the transaction
entrypoint and resolves it to the runtime `public_sender`. Nested calls remain
bound to the immediate caller contract.

`NonceManager` is intentionally domain-separated by `(principal, domain)`. This
lets one contract keep independent monotonic streams for permits, Phoenix
signature authorizations, voting, role delegation, or upgrade approvals.

`AuthorizationManager` builds on those nonces. Moonlight authorization verifies
BLS signatures over stable action bytes and consumes the matching
principal/domain nonce. Phoenix authorization verifies a Schnorr signature from
the Phoenix public key represented by the principal, then consumes the nonce and
optional replay key. This proves control of the Phoenix signing key without
pretending that Phoenix exposes an address-like runtime caller.

`SignedAuthorization` is the ABI-facing wrapper for explicit authorizations,
`ActionEnvelope` is the expected contract/domain/action/payload binding, and
`Authorizer` is the reusable per-call adapter. `Ownable`, `OwnerSet`,
`AccessControl`, and `UpgradeAdmin` expose action-bound helper methods that
accept runtime Moonlight/contract callers when available and otherwise verify
the exact signed envelope before consuming nonce/replay state. This keeps
Phoenix out of the `msg.sender` model while still giving contracts one ergonomic
admin path.

The token modules keep core accounting in reusable Rust state machines. Access
control, pausing, and event emission live in the composing contracts, which is a
better fit for Dusk because call context, host functions, and exposed ABI shape
are contract-specific.

The examples are Forge contracts. Their ABI argument structs live at crate scope
for schema generation, while the state and exported methods live inside a
`#[dusk_forge::contract]` module. Forge generates the schema, contract `STATE`,
and exported wrappers; the examples do not hand-roll `#[no_mangle]` ABI
functions.

DRC20 includes optional supply-cap, burnable, pausable, signed approval, and
voting-unit checkpoint patterns. DRC721 includes enumerable queries, burnable,
pausable, signed token/operator approvals, and default/token-specific royalty
patterns. The reference pausable tokens pause all balance-changing operations:
transfers, minting, and burning. Approvals remain available while paused. These
remain composing contract choices rather than mandatory behavior baked into
every token. Reference contracts emit typed pause/unpause, role grant/revoke,
royalty change, transfer, approval, and proxy value/upgrade events instead of
leaving policy mutations silent.

Proxy support is expressed as an upgrade admin state machine and a namespaced
state store. The example records the active implementation id, delay, migration
payload, rollback window, and emits upgrade lifecycle events. It deliberately
does not expose an EVM-compatible proxy ABI.

`Timelock` is a standalone scheduling primitive for upgrade/governance flows,
and `TimelockController` composes it with Dusk-native roles for proposer,
executor, canceller, and admin policies. Controller maintenance that changes
the minimum delay is self-governed: it must be scheduled and executed through
the timelock path rather than performed directly by an administrator.

`ThresholdMultisig` is the Dusk-native answer to single-owner admin risk. It
counts distinct Moonlight, Phoenix, and contract principals toward a threshold:
Moonlight and contract owners may be observed through call context, while
Phoenix owners must approve with signed actions. The primitive verifies every
approval against the exact `ActionEnvelope` and checks distinct owner quorum
before consuming any nonce or replay state. This lets proxy admins, token
admins, pausers, and future governance flows require M-of-N approval instead of
trusting one hot wallet.

`MultisigController` is the standalone counterpart for DuskEVM/OZ-style ports
where a contract expects one owner/admin principal. The multisig contract is
assigned as that owner, owners propose and confirm a target `ContractCall`, and
the controller performs the call after threshold. Operation ids are bound to
chain id, controller id, target call bytes, and salt; executed operations are
tombstoned to avoid accidental replay. Failed target execution emits a typed
execution event and consumes the proposal, so clients should use a new salt for
an intentional retry.

## Client Signing Flow

Clients sign an `AuthorizedAction` for the exact contract action they want to
execute. The action includes:

- `contract`: the target `ContractId`;
- `domain`: a 32-byte nonce stream chosen by the contract;
- `action_id`: a 32-byte id for the exported operation;
- `nonce`: the current nonce for `(principal, domain)`;
- `expires_at`: a contract-defined block/time deadline, or zero for an explicit
  permanent unused signature;
- `principal`: the Moonlight or Phoenix principal being authorized;
- `payload_hash`: a contract-defined hash/commitment of the call payload.

The composing contract defines `payload_hash`. The authorization counter hashes
the `u64` amount with `abi::keccak256(amount.to_be_bytes())`, then checks that
the signed action payload matches the submitted amount before verifying the
signature. Other contracts should use the same pattern: hash only the payload
fields that the signed action is meant to bind, and reject the call before
signature verification if the submitted payload does not match.

The DRC20 reference exposes `approve_by_authorization`. Its payload hash is:

1. the ASCII domain tag `drc20.approve`;
2. owner principal length and bytes from `Principal::to_bytes()`;
3. spender principal length and bytes;
4. the big-endian `u64` amount;
5. `keccak256` over the concatenated bytes.

Admin references follow the same rule. Signed mint, role, royalty, and proxy
calls validate `contract`, `domain`, `action_id`, and `payload_hash` before
consuming the signature nonce.

The DRC721 reference exposes `approve_by_authorization` and
`set_approval_for_all_by_authorization`. Token approval hashes use the ASCII
domain tag `drc721.approve`, owner principal bytes, approved principal bytes,
and the big-endian token id. Operator approval hashes use
`drc721.approval_for_all`, owner principal bytes, operator principal bytes, and
a single `0` or `1` approval byte.

Use stable constants for `domain` and `action_id`. `domain` separates nonce
streams such as permits, role-admin actions, upgrade approvals, and voting.
`action_id` separates operations inside the same stream. Reusing a domain is
fine only when a single monotonic nonce stream is intentional.

Moonlight signs `AuthorizedAction::message_bytes()` with BLS and submits
`SignedAuthorization::Moonlight`. Phoenix signs
`AuthorizedAction::message_hash()` with Schnorr and submits
`SignedAuthorization::Phoenix`. Public contract methods should use the
action-bound helpers such as `authorize_signed_action`,
`authorize_owner_action`, `authorize_role_action`, or `authorize_admin_action`
so the envelope is checked before nonce state is consumed. The Phoenix
signature proves control of the Phoenix signing key represented by
`Principal::Phoenix`; it does not prove that a specific note exists or was
spent.

See
`standards/dusk-contract-standards/examples/build_signed_authorizations.rs` for
a compact client-side Rust example that builds the DRC20 signed-approval
and DRC721 signed-approval payload hashes, constructs `AuthorizedAction`, and
signs them with Moonlight BLS and Phoenix Schnorr keys.

Nonce protection rejects replay after a signed action is consumed. Expiry is
optional but recommended for relayed or delayed execution, because an unused
signature with only a nonce can remain valid until that nonce is consumed by
some other action. The signing example uses a finite expiry by default;
`expires_at = 0` remains available for explicit offline workflows that need a
permanent unused authorization.

## Forge Data-Drivers

Each reference contract now has two Forge WASM targets:

- contract WASM: on-chain, built with the `contract` feature and
  `-Z build-std=core,alloc`;
- data-driver WASM: off-chain JSON/rkyv conversion, built with
  `data-driver-js` into `target/data-driver`.

Build all reference data-drivers with:

```sh
CARGO_TARGET_DIR=target/data-driver \
cargo build --release --target wasm32-unknown-unknown \
  -p authorization-counter \
  -p drc20-roles-pausable \
  -p drc721-collection \
  -p multisig-controller \
  -p proxy-counter \
  --features authorization-counter/data-driver-js,drc20-roles-pausable/data-driver-js,drc721-collection/data-driver-js,multisig-controller/data-driver-js,proxy-counter/data-driver-js
```

The generated data-drivers export `init`, `get_schema`, `encode_input_fn`,
`decode_output_fn`, and `decode_event`. The example Makefiles expose this as
`make wasm-dd`, and the top-level `make standards-data-drivers` builds all five.

## Validation

The native test suite covers positive and negative paths for:

- ownership and two-step ownership;
- mixed Moonlight/Phoenix/contract owner sets;
- role grants and revokes;
- replay protection;
- domain-separated nonces;
- Moonlight BLS authorization;
- Phoenix Schnorr authorization with replay keys;
- action-bound authorization helpers that reject wrong envelopes before nonce
  movement;
- observed-or-signed owner, role, and upgrade-admin authorization;
- threshold multisig authorization, duplicate signer rejection, observed
  Moonlight/contract approval, Phoenix signed approval, and threshold-gated
  owner/threshold maintenance;
- standalone multisig controller proposal, confirmation, duplicate-confirmation
  rejection, non-owner rejection, expiry cleanup, cancellation, tombstoning,
  authority updates, 2-of-3 property coverage, and proxy-as-owner VM execution;
- timelock scheduling, cancellation, execution, and invalid states;
- role-gated timelock controller flows, including self-governed delay updates;
- reentrancy guard behavior;
- pausing;
- DRC20 transfer, allowance changes, mint, burn, initialization, and failure
  cases;
- DRC20 supply cap and voting-unit checkpoints;
- DRC721 approval, enumeration, operator transfer, mint, burn, initialization,
  and failure cases;
- DRC721 royalty policy;
- upgrade preparation, activation delay, cancellation, rollback, finalization,
  events, and namespaced proxy state.

The hardening branch also adds property-based state-machine tests for token,
authorization, ownership, role, timelock, proxy, nonce/replay, checkpoint,
royalty, multisig-controller, and cap primitives. They compare arbitrary
operation sequences against independent models and assert that rejected
operations leave native state unchanged. See
`docs/dusk-contract-standards-hardening.md` for the current hardening track.

The ignored VM test deploys all five Wasm examples, checks positive query
paths, performs real Moonlight and Phoenix signed calls against the
authorization counter, covers replay/wrong-payload/wrong-signature/wrong-target
failures, submits signed DRC20 mint and signed DRC20 approvals, verifies paused
DRC20/DRC721 signed mint rejection without nonce movement, submits signed
DRC721 owner actions and signed DRC721 approvals, submits a signed proxy admin
call, executes a proxy admin call through the standalone multisig controller,
covers replay/wrong-payload failures for those reference flows, rejects direct
target calls from individual multisig owners, and calls privileged functions
without a runtime caller to validate the negative authorization path at the VM
boundary.

Run the focused suite with:

```sh
cargo test -p dusk-contract-standards
```

Build the example Wasm contracts with:

```sh
cargo build --release -Z build-std=core,alloc --target wasm32-unknown-unknown \
  -p authorization-counter \
  -p drc20-roles-pausable \
  -p drc721-collection \
  -p multisig-controller \
  -p proxy-counter \
  --features authorization-counter/contract,drc20-roles-pausable/contract,drc721-collection/contract,multisig-controller/contract,proxy-counter/contract
```

After the Wasm build, run the VM deployment/query test with:

```sh
cargo test -p dusk-contract-standards --test examples_vm -- --ignored
```

Build the Forge data-driver WASM with:

```sh
make standards-data-drivers
```

For a local-node smoke deployment against a running Rusk endpoint:

```sh
RUSK_URL=http://localhost:8080 \
RUSK_WALLET_BIN=/path/to/rusk-wallet \
./scripts/dusk-contract-standards-local-smoke.sh
```

The script first runs the native suite, builds Wasm, runs the VM deployment
test, serializes deploy-time init arguments using the Dusk ABI serializer,
deploys the five example contracts plus a second proxy owned by the multisig
controller, and queries deployed state. It submits positive and negative
signed transactions, including the 2-of-3 multisig-owned proxy flow, and
asserts nonce/value state after rejected calls. `WALLET_DIR` should point at a
funded local wallet profile.

For an isolated local smoke wallet, set `WALLET_RESTORE_FILE` to a funded
wallet backup. The script restores it into `WALLET_DIR` when the directory does
not already contain `wallet.keystore.json`:

```sh
RUSK_URL=http://127.0.0.1:18080 \
RUSK_WALLET_BIN=/path/to/rusk-wallet \
WALLET_DIR=target/rusk-local-smoke/wallet \
WALLET_RESTORE_FILE=/path/to/wallet.dat \
./scripts/dusk-contract-standards-local-smoke.sh
```
