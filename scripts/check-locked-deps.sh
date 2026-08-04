#!/usr/bin/env bash
#
# Locked dependency preflight for the root legacy/genesis contract workspace.
#
# The genesis contracts (transfer, stake) are already deployed, so their build
# must be reproducible: an incidental lockfile regeneration must not silently
# change the dependency graph used to produce their WASM. This script:
#
#   1. Validates that the committed root Cargo.lock is consistent with its
#      manifest (`cargo metadata --locked` fails if a lockfile update would be
#      required).
#   2. Asserts the pinned allocator (`dlmalloc`) version, so that an allocator
#      change must be explicit and reviewable.
#
# The nested standards workspace is intentionally out of scope: its contracts
# are reference material and are not deployed. Changing the pinned allocator
# requires the deliberate procedure documented in docs/dependency-updates.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

ROOT_MANIFEST="Cargo.toml"
ROOT_LOCKFILE="Cargo.lock"
ROOT_DLMALLOC_VERSION="0.2.6"

fail() {
    echo "❌ $1" >&2
    exit 1
}

# Validate that the committed root lockfile is up to date with its manifest.
# Fails if a lockfile update would be required.
#
# The root legacy/genesis workspace is pinned to an older toolchain that cannot
# parse some newer host-only transitive manifests (crates requiring
# edition2024). Those crates are never part of the wasm32 contract build graph,
# so the workspace is validated for the contract target platform. Locked
# resolution still fails if the manifest requires a lockfile update.
check_locked() {
    echo "🔍 Validating locked resolution for ${ROOT_MANIFEST}"
    if ! cargo metadata --locked --format-version 1 \
        --filter-platform wasm32-unknown-unknown >/dev/null; then
        fail "Locked dependency resolution failed for ${ROOT_MANIFEST}.
   The committed lockfile is out of date with the manifest. If this change is
   intentional, follow docs/dependency-updates.md, regenerate the lockfile, and
   commit it in the same PR."
    fi
}

# Asserts that the pinned allocator version has not changed.
check_dlmalloc() {
    local lockfile="$1"
    local expected="$2"
    echo "🔍 Checking dlmalloc version in ${lockfile} (expected ${expected})"

    local versions
    versions="$(awk '
        /^\[\[package\]\]/ { name="" }
        /^name = / { gsub(/[",]/, ""); name=$3 }
        /^version = / { gsub(/[",]/, ""); if (name == "dlmalloc") print $3 }
    ' "${lockfile}")"

    if [ -z "${versions}" ]; then
        fail "dlmalloc not found in ${lockfile}; expected version ${expected}."
    fi

    if [ "${versions}" != "${expected}" ]; then
        fail "Unexpected dlmalloc resolution in ${lockfile}: found '$(echo "${versions}" | tr '\n' ' ')', expected '${expected}'.
   If this allocator change is intentional, follow docs/dependency-updates.md
   and update the expected version in scripts/check-locked-deps.sh."
    fi

    echo "✅ ${lockfile}: dlmalloc ${expected}"
}

echo "==> Contract dependency-resolution preflight"

check_locked

check_dlmalloc "${ROOT_LOCKFILE}" "${ROOT_DLMALLOC_VERSION}"

echo "✅ Locked dependency preflight passed"
