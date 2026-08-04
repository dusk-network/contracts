# Dependency updates for genesis contract builds

The genesis contracts (`transfer`, `stake`) are already deployed, so the bytes
that are compiled must be reproducible and reviewable. To prevent an incidental
lockfile regeneration from silently changing the dependency graph, every project
Cargo command in the root legacy/genesis workspace that resolves dependencies is
run with `--locked`, and CI runs a dependency-resolution preflight before
compiling those contracts.

This applies to the **root legacy/genesis workspace** only:

| Workspace           | Manifest / lockfile         | Toolchain            | Pinned `dlmalloc` |
| ------------------- | --------------------------- | -------------------- | ----------------- |
| Root legacy/genesis | `Cargo.toml` / `Cargo.lock` | `nightly-2024-07-30` | `0.2.6`           |

The nested `standards` workspace is intentionally **out of scope**: its
contracts are reference material and are not deployed, so their builds are not
pinned with `--locked`.

## Enforcement

- All artifact-producing genesis/test builds (`cargo build`, `cargo +dusk
  build`), tests, checks, clippy, and docs use `--locked` and therefore fail if
  the committed root lockfile is out of date with its manifest.
- `make check-locked-deps` (also run in CI via
  [`scripts/check-locked-deps.sh`](../scripts/check-locked-deps.sh)) validates
  the root lockfile and asserts the pinned `dlmalloc` version before contracts
  are compiled. It fails clearly if the resolved allocator version changes.
- Custom Cargo subcommands that do not accept `--locked` (for example
  `cargo dusk-analyzer`) are preceded by a `cargo metadata --locked` preflight.

The allocator check is not meant to prohibit updates. It ensures an allocator
change is explicit and reviewable rather than an incidental lockfile
regeneration.

## Procedure for an intentional dependency change

Any change to a dependency used in genesis contract WASM (including `dlmalloc`)
must be made deliberately and documented in the PR. Follow these steps:

1. **Make an intentional manifest or lockfile change.** Edit `Cargo.toml` and/or
   regenerate the root lockfile explicitly, and commit the updated `Cargo.lock`
   in the same PR. If the allocator version changes, update the expected version
   in [`scripts/check-locked-deps.sh`](../scripts/check-locked-deps.sh).
2. **Regenerate the affected contract binaries.** Rebuild the impacted genesis
   and/or test contract WASM using the normal build commands so the artifacts
   reflect the new dependency graph.
3. **Compare the previous and new WASM hashes and sizes.** Record the old and
   new SHA-256 hashes and byte sizes for each regenerated binary, and include
   the comparison in the PR.
4. **Explain the dependency change in the PR.** State what changed, why, and the
   expected impact on the generated binaries.
5. **Run the appropriate contract and VM regression testing.** Run the contract
   test suites, clippy, and WASM builds, plus any VM regression tests affected
   by the change.

## Out of scope for routine changes

Do not regenerate or modify committed genesis/test contract WASM binaries,
update `dlmalloc`, or update Dusk workspace dependencies unless the change is the
explicit subject of the PR and follows the procedure above.
