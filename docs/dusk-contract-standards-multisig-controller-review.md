# Multisig Controller Security Review

Review date: 2026-04-27

## Scope

Reviewed code and validation:

- `standards/dusk-contract-standards/src/governance/multisig_controller.rs`
- `standards/examples/multisig_controller`
- `standards/examples/proxy_counter`
- multisig primitive, property, VM, local-node smoke, and data-driver tests under
  `standards/dusk-contract-standards/tests`

The review focused on the standalone controller pattern where a target contract
is owned by `Principal::Contract(multisig_controller_id)`, and individual
Moonlight/Phoenix/contract owners approve controller operations.

## Intended Security Properties

- The target contract must treat the multisig controller contract as the owner.
  Individual multisig owners are not target admins by themselves.
- A proposal with one owner approval must not execute when the threshold is
  two.
- Confirmation requires a distinct current owner. Duplicate confirmations,
  non-owner confirmations, wrong payload signatures, and replayed signatures
  must fail.
- Signed approvals must bind the controller id, nonce domain, action id,
  operation id or maintenance payload, signer principal, nonce, expiry, and
  payload hash before nonce/replay state is consumed.
- Operation ids must be scoped to chain id, controller contract id, target call
  bytes, and salt.
- A ready operation must be removed from pending proposals and tombstoned before
  the wrapper attempts target execution.
- Expired proposals are pruned and cannot become ready.
- Authority changes that remove owners or change threshold clear stale pending
  operations.

## Review Results

No critical or high-severity issues are open from this pass.

The VM test and local-node smoke deploy `multisig_controller` with three
Phoenix owners and threshold `2`, then deploy `proxy_counter` with
`Principal::Contract(multisig_controller_id)` as admin. They verify that:

- direct root `proxy_counter.set_value` without authorization fails;
- a direct signed proxy-admin call from a multisig owner fails because the
  target owner is the controller contract, not the human owner;
- a non-owner cannot propose and does not advance nonce state;
- one valid owner proposal leaves the operation pending and does not update the
  target;
- duplicate confirmation and wrong-payload confirmation fail without nonce
  movement;
- a second distinct owner confirms and executes the target call;
- replaying the used confirmation fails;
- a third owner can be the second signer for a later operation, proving the
  threshold is truly 2-of-3 rather than a fixed owner pair.

The native property test exercises the raw controller state machine across
random owners, ids, targets, TTLs, tombstone windows, and timings. It checks
atomicity for non-owner proposals, non-owner confirmations, duplicate
confirmations, one-of-three pending behavior, expiry pruning, ready-state
tombstoning, tombstone replay rejection, and successful re-use only after the
tombstone has expired.

## Security Notes

The controller deliberately has no Ethereum-like `msg.sender` assumption for
Phoenix. Phoenix owners approve by Schnorr-signed `AuthorizedAction`.
Moonlight and contract owners may be accepted through observed runtime context
when the host exposes it.

The Forge wrapper verifies signatures before consuming nonce state, but only
consumes after the controller accepts the proposal/confirmation/maintenance
operation. This avoids burning a valid signature on duplicate confirmations,
wrong threshold membership, invalid targets, expired proposals, or invalid
maintenance payloads.

Execution is automatic at threshold. There is no separate `execute` step. This
is simpler and avoids a ready-operation queue, but systems that require a final
execution window, keeper role, or time delay should compose the multisig with a
timelock target.

A target execution failure emits `multisig/operation_executed` with
`success = false`, removes the proposal, and tombstones the id. Retrying the
same logical call requires a new salt. This avoids accidental replay, but
clients must surface failed execution clearly.

`propose` can count as a confirmation for an existing operation with the same
operation id. This is acceptable because the signed payload is the exact
operation id, but client UX should prefer the explicit `confirm` method after a
proposal already exists.

## Residual Risks

- Host-function correctness is assumed. The contract-owner path depends on
  `abi::caller()` exposing the immediate caller contract during nested calls.
- Data-driver/ABI correctness is fuzzed for generated schemas, but independent
  clients should be differentially tested against those schemas.
- The controller does not solve key-management policy. Owner selection,
  hardware-key usage, emergency procedures, and threshold choice remain
  deployment responsibilities.
- No formal verification has been performed for the controller state machine.
- The deterministic local-node smoke covers this exact multisig flow, but it is
  not a long-running adversarial network campaign.

## Recommendation

Use `MultisigController` as the default owner/admin principal for production
references that would otherwise use a single owner. For high-value upgrade or
treasury flows, set the target owner to a timelock controlled by the multisig,
or make the multisig operate only timelock-scheduled actions.
