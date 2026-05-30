check:
	cargo check -p drc20-phoenix-reference

wasm:
	cargo build -p drc20-phoenix-reference --target wasm32-unknown-unknown --release --features contract

data-driver:
	cargo build -p drc20-phoenix-reference --target wasm32-unknown-unknown --release --features data-driver

test:
	cargo test -p drc20-phoenix-reference

clippy:
	cargo clippy -p drc20-phoenix-reference -- -D warnings

.PHONY: check wasm data-driver test clippy
