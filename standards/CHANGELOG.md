# Changelog

## Unreleased

### Added

- Added the DRC20 standards primitive, DRC20 event payloads, token extension
  helpers, and the `drc20_roles_pausable` Forge reference contract.
- Added VM coverage for signed DRC20 approvals, role-gated minting and
  pausing, vote tracking, emitted DRC20 event decoding, and Moonlight routed
  transfer/burn paths.

### Changed

- Changed the JSON form of `Principal` to the dusk-core form of its key or id.
  The stored bytes and the rkyv layout don't change.
