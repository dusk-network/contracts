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
		-p proxy-counter

test:
	@cargo test -p dusk-contract-standards

wasm-dd:
	@CARGO_TARGET_DIR=$(DD_TARGET_DIR) \
	cargo build \
		--release \
		--color=always \
		--target wasm32-unknown-unknown \
		--features data-driver-js \
		-p proxy-counter

clippy:
	@cargo clippy -p proxy-counter -Z build-std=core,alloc --release --target wasm32-unknown-unknown --features contract -- -D warnings

doc:

.PHONY: all wasm wasm-dd test clippy doc
