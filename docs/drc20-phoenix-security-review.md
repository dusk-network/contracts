# DRC20Phoenix Internal Security Review

Status: implementation review for `standards/drc20-phoenix-architecture`.

## Reviewed Surface

- `Drc20Phoenix` standards primitive.
- Forge reference contract wrapper.
- Public-input builder and client-flow example.
- Local `rusk-private` smoke preflight.

## Findings And Resolutions

### Circuit Statement And Public-Input Ordering

The contract reconstructs `PrivateAssetPublicInputs` before verifier dispatch
and rejects any mismatch. Public inputs include version, chain id, contract id,
asset id, mode, root, nullifiers, output commitments, public mint amount,
public burn amount, and intent hash.

Residual risk: the final private-asset circuit does not exist on this branch.
The implementation cannot be called production cryptographic enforcement until
the prover/verifier package uses exactly the same public-input ordering.

### Verifier-Data Packaging

`Init` requires non-empty verifier data and the contract exposes a verifier-data
hash for clients. The production path calls `abi::verify_plonk` in contract
builds.

Residual risk: verifier data is admin-supplied at initialization. A production
reference should pin an audited verifier-data hash or move verifier updates
behind a timelocked/multisig governance flow.

### Verifier Misuse

Native non-contract builds reject production proofs by default. The permissive
test verifier remains private to unit tests. No public `dev verifier` feature
was added.

### Double Spend And Nullifiers

The primitive rejects empty nullifier lists, duplicate nullifiers in the same
call, and nullifiers already present in the membership set. Accepted nullifiers
are inserted into both the membership set and append log.

### Root Retention

The primitive checkpoints the initial root and every accepted mutation. Roots
are retained in a bounded window and checked before transfer/burn proof
verification.

Residual risk: window sizing is a product/security parameter. Too short causes
wallet UX failures; too long increases accepted historical anchors.

### Domain Separation

The asset id binds chain id, contract id, metadata, and deployment salt. Notes,
public inputs, and intents bind the DRC20Phoenix domain, version, chain id,
contract id, asset id, and circuit mode.

### Supply Inflation

Minting requires admin authorization, checked arithmetic, cap enforcement, and
proof public-input equality before mutation.

Residual risk: output value conservation is only enforceable once the final
private-asset circuit exists.

### Burn Accounting

Burning requires a retained root, unspent nullifiers, checked burned-supply
arithmetic, and proof public-input equality. Full burns with no change notes are
allowed.

Residual risk: `sum(inputs) = sum(outputs) + public_burn` must be enforced by
the final circuit.

### Malformed Notes

The primitive rejects notes with a wrong asset id or mismatched note
commitment. Burn change outputs may be empty; mint and transfer outputs may not.

### Replay Across Contexts

Tests cover wrong chain id, contract id, asset id, mode, root, output mutation,
nullifier mutation, and replayed nullifiers.

### Failed-Operation Atomicity

State mutation happens after validation/proof checks. Unit tests assert failed
burn and production-verifier rejection do not mutate supply, notes, nullifiers,
or roots.

### Storage And DoS Bounds

Root retention is bounded. Sync APIs are paginated. Notes/nullifiers are
append-only and permanent.

Residual risk: the final Forge reference should set product limits for proof
size, memo size, max inputs, and max outputs once circuit arities are fixed.

### Wallet Scanning Privacy

The docs recommend append-log sync over targeted `existing_nullifiers` queries
when privacy against infrastructure matters.

### Admin Abuse

The primitive uses a simple `AdminId` for the standalone reference. Production
deployments should compose it with multisig/timelock ownership rather than a
single hot wallet.

### Pause Semantics

Pause blocks mint, transfer, and burn. Queries remain available.

## Conclusion

The standards-layer state machine is hardened against ordinary state-machine
and replay bugs. The remaining blocker is cryptographic, not structural: the
branch still needs a custom private-asset circuit/prover/verifier package before
RPC-level mint/transfer/burn can be production-valid.
