#!/bin/bash
set -e

# Create bin directory
mkdir -p bin

# Define contracts to build
CONTRACTS=("alice" "bob" "charlie" "host_fn")

echo "Building test contracts..."

for contract in "${CONTRACTS[@]}"; do
  echo "Building $contract contract..."

  TARGET_DIR="target"
  
  # Run deterministic build
  docker run --rm \
    -v "$(pwd)":/source \
    -v "$(pwd)/$TARGET_DIR":/target \
    --mount type=volume,source=dusk_registry_cache,target=/root/.cargo/registry \
    dusknode/dusk-verifiable-builds:0.2.0 \
    --manifest-path "contracts/$contract/Cargo.toml" --target wasm32-unknown-unknown
  
  # Copy the built wasm to bin directory
  cp "$TARGET_DIR/final-output/wasm32/$contract.wasm" bin/
  echo "✓ $contract.wasm built successfully"
  
  # Clean up target directory
  rm -rf "$TARGET_DIR"
done

echo "All test contracts built successfully!"
echo "Binaries stored in bin/ directory"
