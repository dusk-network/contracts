TARGET_DIR ?= ../../target

all: wasm clippy

wasm: ## Generate the optimized WASM for the contract given
	@RUSTFLAGS="$(RUSTFLAGS) --remap-path-prefix $(HOME)= -C link-args=-zstack-size=65536" \
	CARGO_TARGET_DIR=$(TARGET_DIR) \
    	cargo build \
    		--locked \
    		--release \
    		--color=always \
			-Z build-std=core,alloc \
    		--target wasm32-unknown-unknown

test:

clippy:
	@cargo clippy --locked -Z build-std=core,alloc --release --target wasm32-unknown-unknown -- -D warnings

doc:

.PHONY: all test wasm
