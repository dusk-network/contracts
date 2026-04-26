# Dusk Contract Standards Audit Packet

This document is the auditor-facing entry point for the Dusk-native standards
layer. It captures the review scope, security assumptions, invariant matrix,
validation commands, and known residual risks for this branch.

## Scope

In scope:

- `standards/dusk-contract-standards/src/**`
- `standards/examples/authorization_counter`
- `standards/examples/drc20_roles_pausable`
- `standards/examples/drc721_collection`
- `standards/examples/proxy_counter`
- `scripts/dusk-contract-standards-local-smoke.sh`
- `standards/dusk-contract-standards/tests/**`

Out of scope:

- Dusk protocol consensus, wallet, node, prover, and VM internals.
- Forge macro implementation correctness, except where the generated
  data-driver and Wasm artifacts are exercised through this repository's tests.
- Economic policy choices such as exact upgrade delays, role assignment
  procedures, and marketplace royalty enforcement.
- Compatibility with Ethereum/OpenZeppelin ABIs where Dusk-native semantics
  deliberately diverge.

## Security Model

The standards layer assumes:

- `CallContext::current()` correctly reports observed Moonlight and contract
  callers when the runtime exposes such callers.
- Phoenix calls do not expose a stable caller identity. Phoenix authorization
  must therefore be an explicit Schnorr signature over an `AuthorizedAction`.
- Dusk signature primitives verify according to their upstream implementations.
- `abi::self_id()`, `abi::block_height()`, `abi::emit`, and contract-call
  routing are provided correctly by the host.
- Client encoders use the same schema and byte serialization as the generated
  Forge data-drivers.

The layer does not assume:

- an Ethereum-like `msg.sender` for Phoenix;
- delegatecall-style proxy storage behavior;
- off-chain signatures are safe without contract/domain/action/payload binding;
- zero principals are valid owners, recipients, spenders, operators, or admins.

## Invariant Matrix

| ID | Invariant | Primary Coverage |
| --- | --- | --- |
| AUTH-1 | Signed actions bind contract, domain, action id, payload hash, nonce, principal, and expiry before nonce/replay consumption. | `tests/primitives.rs`, `tests/properties.rs`, VM test, local-node smoke |
| AUTH-2 | Rejected envelope, signature, expiry, role, owner, admin, and replay-key cases do not advance nonce/replay state. | property negative matrices, VM test, local-node smoke |
| AUTH-3 | Phoenix authorization proves control of a Schnorr key principal and never relies on observed caller identity. | primitives, properties, signed auth example, local-node smoke |
| AUTH-4 | Moonlight owners can authorize by observed caller or signed BLS action; contract owners only by observed contract caller. | primitives, reference contracts, VM test |
| MULTISIG-1 | Threshold multisig requires distinct owner quorum and rejects duplicate signers before nonce/replay consumption. | primitives |
| MULTISIG-2 | Observed Moonlight/contract owners can count toward quorum; Phoenix owners require signed action approvals. | primitives |
| MULTISIG-3 | Multisig owner and threshold maintenance requires current quorum and rejected changes leave state unchanged. | primitives |
| ACCESS-1 | Role grants/revokes are admin-gated, reject zero accounts, and emit typed events when state changes. | primitives, DRC20 reference, data-driver event decoding |
| ACCESS-2 | Owner and owner-set initialization reject zero principals atomically. | primitives, properties |
| PAUSE-1 | Reference pausable DRC20/DRC721 pause all balance-changing operations. | primitives, VM test, local-node smoke |
| PAUSE-2 | Approvals remain available while paused and do not move balances or ownership. | VM test, local-node smoke |
| TOKEN20-1 | DRC20 total supply equals the modeled sum of balances after arbitrary operation sequences. | property state-machine model |
| TOKEN20-2 | DRC20 transfer, transfer-from, allowance, mint, burn, cap, and vote checkpoint failures are atomic. | primitives, properties |
| TOKEN721-1 | DRC721 owner, balance, approval, operator, enumerable, and total-supply views remain internally consistent. | property state-machine model |
| TOKEN721-2 | DRC721 mint, transfer, burn, approval, operator, and royalty failures are atomic. | primitives, properties |
| ROYALTY-1 | Royalty receivers cannot be zero, basis points cannot exceed 10,000, and overflow-prone quotes do not mutate state. | primitives, properties |
| NONCE-1 | Nonce domains are independent, monotonic, import/export safe, and atomic on rejection. | primitives, properties |
| REPLAY-1 | Replay keys cannot be reused for the same principal and import/export is monotonic. | primitives, properties |
| PROXY-1 | Upgrade admin rejects zero admin/implementation and binds signed admin actions to exact payloads. | primitives, VM test, local-node smoke |
| PROXY-2 | Prepare, activate, cancel, rollback, and rollback-finalization obey delay/window state transitions and emit events. | primitives, properties, data-driver event decoding |
| TIMELOCK-1 | Timelock scheduling/execution/cancellation follows delay and predecessor constraints. | primitives, properties |
| TIMELOCK-2 | Controller minimum-delay changes are self-governed through scheduled operations, not direct arbitrary admin mutation. | primitives, properties |
| REENTRANCY-1 | Scoped guard rejects nested entry and resets after panics. | primitives |
| ABI-1 | Forge data-driver schemas load for every reference contract. | `tests/data_driver_fuzz.rs` |
| ABI-2 | Function inputs JSON-encode, decode, and re-encode consistently; malformed and mutated payloads do not crash. | `tests/data_driver_fuzz.rs` |
| ABI-3 | Function outputs and typed events decode from rkyv and mutated output/event payloads do not crash readers. | `tests/data_driver_fuzz.rs` |
| NODE-1 | Real local Rusk deployment accepts valid signed calls and rejects replay, bad payload, expired action, pause, and proxy replay cases while preserving expected state. | `scripts/dusk-contract-standards-local-smoke.sh` |

## Reproducible Validation

Run the audit-grade validation pass:

```sh
./scripts/dusk-contract-standards-audit-grade.sh
```

Default intensity:

- `STANDARDS_PROPTEST_CASES=8192`
- `STANDARDS_PROPTEST_MAX_SHRINK_ITERS=16384`
- `STANDARDS_DATA_DRIVER_FUZZ_CASES=4096`
- `STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS=8192`

For a funded local-node run, start Rusk and provide wallet/node settings:

```sh
RUN_LOCAL_NODE_SMOKE=1 \
RUSK_URL=http://127.0.0.1:18080 \
RUSK_WALLET_BIN=/path/to/rusk-wallet \
WALLET_DIR=target/rusk-local-smoke/wallet \
WALLET_RESTORE_FILE=/path/to/wallet.dat \
./scripts/dusk-contract-standards-audit-grade.sh
```

For dependency advisory scanning, install `cargo-audit` and opt in:

```sh
RUN_CARGO_AUDIT=1 ./scripts/dusk-contract-standards-audit-grade.sh
```

## Auditor Checklist

Reviewers should focus on:

- whether the Dusk principal model is the right abstraction for Moonlight,
  Phoenix, and contract callers;
- whether every public signed path uses action-bound helpers before nonce
  consumption;
- whether single-owner admin paths should be replaced with
  `ThresholdMultisig` composition before production deployment;
- whether payload-hash construction is unambiguous and domain separated enough
  for downstream wallets;
- whether pause semantics match product/security expectations;
- whether upgrade and timelock policies are sufficient for production systems;
- whether any event is missing for an indexer-relevant state change;
- whether generated data-driver schemas are acceptable as the client/wallet
  ABI source of truth.

## Residual Risks

The branch is audit-ready, not audit-complete. Remaining risk areas:

- independent client encoders may still disagree with Forge data-drivers unless
  they are tested differentially;
- Dusk runtime host-function behavior is assumed rather than proven here;
- no formal verification is included for arithmetic or state machines;
- dependency advisory scanning is optional unless `cargo-audit` is installed;
- local-node smoke is deterministic and adversarial for defined invariants, but
  it is not a long-running network chaos test.
