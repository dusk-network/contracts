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

## Pausable References

The reference pausable DRC20 and DRC721 contracts pause all balance-changing
operations: transfers, minting, and burning. Approvals remain available while
paused so accounts can prepare permissions without moving balances or ownership.

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
