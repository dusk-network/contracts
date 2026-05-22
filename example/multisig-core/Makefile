COUNTER_WASM="./../target/wasm32-unknown-unknown/release/counter.wasm"

all: @cargo build --release

test: $(COUNTER_WASM) ## Run tests
	@cargo test --release
	@cargo test --release --features serde

$(COUNTER_WASM): ## Compile the counter-test contract
# 	$(MAKE) -C ./../tests/counter wasm

clippy: ## Run clippy
	@cargo clippy \
		--release \
	  -- -D warnings
	@cargo clippy --release --features serde -- -D warnings

doc: ## Build the docs
	@cargo doc --release

.PHONY: all test clippy doc 
