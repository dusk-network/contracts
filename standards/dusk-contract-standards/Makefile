all: check test clippy

check:
	@cargo check -p dusk-contract-standards

test:
	@cargo test -p dusk-contract-standards
	@cargo test -p dusk-contract-standards --features serde
	@cargo test -p dusk-contract-standards --features forge

wasm:

clippy:
	@cargo clippy -p dusk-contract-standards -- -D warnings

doc:
	@cargo doc -p dusk-contract-standards --no-deps

.PHONY: all check test wasm clippy doc
