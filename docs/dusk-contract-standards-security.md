# Dusk Contract Standards Security Notes

## Replay Domains

Every signed action must bind `contract`, `domain`, `action_id`, `nonce`,
`principal`, and `payload_hash`. Use separate nonce domains for unrelated
flows: token approvals, role admin, proxy upgrades, voting, and application
actions should not share a nonce stream unless that coupling is deliberate.

## Expiry and Nonces

Nonces stop replay after use. Expiry limits how long an unused signature can
float around in clients, relayers, or mempools. Reference client examples use
finite expiry. Use `expires_at = 0` only for offline workflows where a
permanently valid unused signature is acceptable.

## Phoenix Authorization

Phoenix does not provide a clean runtime caller identity. Treat Phoenix admin
or owner actions as explicit Schnorr authorizations over an `AuthorizedAction`.
This proves control of the Phoenix signing key represented by the principal; it
does not prove that a specific Phoenix note exists or was spent.

## Moonlight and Contract Callers

Moonlight root calls and inter-contract calls can use `CallContext::current()`.
Signed Moonlight authorization is still useful for relayed calls or workflows
where the submitter is not the owner. Contract principals should be accepted
only from observed inter-contract caller context.

## Payload Binding

Do not verify a signature without first checking that the action envelope
matches the call being submitted. Public methods should prefer the action-bound
helpers (`authorize_signed_action`, `authorize_owner_action`,
`authorize_role_action`, and `authorize_admin_action`) so wrong contract, wrong
domain, wrong action id, and wrong payload hash are rejected before nonce state
is consumed.

Payload hashes must include enough typed structure to prevent ambiguous
concatenation. Reference contracts prefix each payload with an operation tag and
length-prefix variable-size principal encodings before hashing. New standards
should follow that pattern or use a canonical structured encoder.

## Pausable References

The reference pausable DRC20 and DRC721 contracts pause all balance-changing
operations: transfers, minting, and burning. Approvals remain available while
paused so accounts can prepare permissions without moving balances or ownership.
Pause and unpause operations emit typed events, and role and royalty policy
changes are also observable through typed events.
Signed DRC721 token/operator approvals follow the same nonce-bound action
model as DRC20 signed approvals and remain available while paused.

## Reentrancy and Call Stack

Use `ReentrancyGuard` around state-changing flows that perform external calls
or may later grow such calls. Dusk call-stack behavior is not EVM delegatecall;
avoid importing EVM proxy or reentrancy assumptions directly.

## Upgrades and Timelocks

Upgrade admin signatures should bind the exact target implementation and
migration payload. For production systems, put upgrade preparation or
activation behind a timelock, keep a rollback window, and emit lifecycle events
for indexers and wallets. Timelock controller maintenance, including minimum
delay changes, should go through the timelock itself rather than a direct admin
call.

## Threshold Multisig

Do not default production admin paths to a single owner when compromise of that
owner would give full control. `ThresholdMultisig` lets composing contracts
require a distinct M-of-N owner quorum over Dusk principals. It counts observed
Moonlight/contract callers when the runtime exposes them, requires Phoenix
owners to use signed approvals, rejects duplicate signers, and verifies all
approvals before consuming any nonce/replay state.

Multisig approvals should be bound to the exact operation through
`ActionEnvelope`. Owner-set changes, threshold changes, proxy upgrades, token
minting, pausing, and role administration should use separate domains or action
ids so approvals cannot be replayed across policy surfaces.

Use the standalone `MultisigController` when a ported contract wants a single
owner/admin principal like an Ethereum contract owned by a Safe. The target
contract should assign ownership or the relevant role to the controller's
contract id. Owners then approve the target call through proposal/confirmation
or signed actions, and the controller performs the call as the observed
contract caller after threshold. Operation ids must bind chain id, controller
id, target call bytes, and salt; failed target execution is observable through
the execution event and should be retried with a new salt only when operators
intend a new attempt.

## Audit Packet

`docs/dusk-contract-standards-audit.md` is the auditor-facing packet for this
branch. It lists the exact scope, trust assumptions, invariant matrix,
validation commands, and residual risks.
