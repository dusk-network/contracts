TARGET_DIR ?= ../../../target
DD_TARGET_DIR ?= ../../../target/data-driver

all: wasm wasm-dd clippy

wasm:
	@RUSTFLAGS="$(RUSTFLAGS) --remap-path-prefix $(HOME)= -C link-args=-zstack-size=65536" \
	CARGO_TARGET_DIR=$(TARGET_DIR) \
	cargo build \
		--release \
		--color=always \
		-Z build-std=core,alloc \
		--target wasm32-unknown-unknown \
		--features contract \
		-p drc20-roles-pausable

test:
	@cargo test -p dusk-contract-standards

wasm-dd:
	@CARGO_TARGET_DIR=$(DD_TARGET_DIR) \
	cargo build \
		--release \
		--color=always \
		--target wasm32-unknown-unknown \
		--features data-driver-js \
		-p drc20-roles-pausable

clippy:
	@cargo clippy -p drc20-roles-pausable -Z build-std=core,alloc --release --target wasm32-unknown-unknown --features contract -- -D warnings

doc:

.PHONY: all wasm wasm-dd test clippy doc
