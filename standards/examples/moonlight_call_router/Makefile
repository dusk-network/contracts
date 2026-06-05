TARGET_DIR ?= ../../../target

all: wasm clippy

wasm:
	@RUSTFLAGS="$(RUSTFLAGS) --remap-path-prefix $(HOME)= -C link-args=-zstack-size=65536" \
	CARGO_TARGET_DIR=$(TARGET_DIR) \
	cargo build \
		--release \
		--color=always \
		-Z build-std=core,alloc \
		--target wasm32-unknown-unknown \
		--features contract \
		-p moonlight-call-router

test:

clippy:
	@cargo clippy -p moonlight-call-router -Z build-std=core,alloc --release --target wasm32-unknown-unknown --features contract -- -D warnings

doc:

.PHONY: all wasm test clippy doc
