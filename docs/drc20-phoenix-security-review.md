# DRC20Phoenix Internal Security Review

Status: implementation review for `standards/drc20-phoenix-architecture`.

## Reviewed Surface

- `Drc20Phoenix` standards primitive.
- Forge reference contract wrapper.
- Public-input builder and client-flow example.
- Dedicated fixed-arity DRC20Phoenix circuit package.
- Local `rusk-private` smoke with the Forge reference contract, matching
  `rusk-wallet` 0.3.0 binary, and generated Dusk-CRS verifier artifacts.

## Findings And Resolutions

### Circuit Statement And Public-Input Ordering

The contract reconstructs `PrivateAssetPublicInputs` before verifier dispatch
and rejects any mismatch. Public inputs include version, chain id, contract id,
asset id, mode, root, nullifiers, output commitments, public mint amount,
public burn amount, and intent hash.

The first fixed-arity private-asset circuit exists on this branch and consumes
the same standards public-input ordering. Proof tests cover mint and transfer
verification plus public-input mutation rejection.

Residual risk: the circuit and public-input ordering need external
cryptographic audit before deployment.

### Verifier-Data Packaging

`Init` now requires a complete v1 verifier set keyed by version, mode,
input-count, and output-count. The primitive rejects missing entries,
duplicates, unsupported arities, empty verifier data, and verifier-data hash
mismatches. The production path selects verifier data by the call arity and
calls `abi::verify_plonk` in contract builds.

Verifier artifacts and `manifest.json` are committed under
`standards/drc20-phoenix-circuits/verifier-data/`. They are generated from the
official Dusk CRS `devnet-piecrust.crs`, pinned to SHA-256
`6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059`.

Residual risk: production deployments still need circuit and verifier-artifact
audit. If verifier updates are ever allowed, they should go through
timelocked/multisig governance.

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

The circuit proves value conservation for the supported fixed arities. Residual
risk remains around audit of the Dusk-CRS-generated verifier artifacts.

### Burn Accounting

Burning requires a retained root, unspent nullifiers, checked burned-supply
arithmetic, and proof public-input equality. Full burns with no change notes are
allowed.

The circuit enforces `sum(inputs) + public_mint = sum(outputs) + public_burn`
for the supported fixed arity.

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

The v1 arity matrix bounds proof input/output counts:

```text
mint: 0 inputs / 1..2 outputs
transfer: 1..4 inputs / 2 outputs
burn: 1..4 inputs / 0..2 outputs
```

Residual risk: the Forge reference should still set product limits for proof
size and memo size.

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
and replay bugs, and the branch now includes a first custom private-asset
circuit package, fixed v1 arities, verifier dispatch, and Dusk-CRS verifier
artifacts. The local-node smoke deploys the Forge reference and submits real
mint, transfer, and burn proofs over RPC. The remaining blocker is
productionization: external audit, wallet SDK integration, indexer/privacy
behavior, and broader RPC coverage beyond the reference smoke.
