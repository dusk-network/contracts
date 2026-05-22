CRATE_NAME_DASHED := $(shell cargo metadata --no-deps --format-version 1 --manifest-path Cargo.toml | jq -r '.packages[] | select(.manifest_path == "$(realpath Cargo.toml)") | .name')
CRATE_NAME := $(subst -,_,$(CRATE_NAME_DASHED))

# Detect workspace root so we know where target/ actually lives
WORKSPACE_ROOT := $(shell cargo metadata --no-deps --format-version 1 --manifest-path Cargo.toml | jq -r '.workspace_root')

WASM_OPT ?= $(shell command -v wasm-opt 2>/dev/null)
WASM_TARGET = wasm32-unknown-unknown
WASM_RELEASE_DIR = $(WORKSPACE_ROOT)/target/$(WASM_TARGET)/release
WASM_FILE = $(WASM_RELEASE_DIR)/$(CRATE_NAME).wasm
WASM_OPT_FILE = $(WASM_RELEASE_DIR)/$(CRATE_NAME)_opt.wasm

TEST_CONTRACT := counter
TEST_WASM_FILE = $(WASM_RELEASE_DIR)/$(TEST_CONTRACT_NAME).wasm

all: wasm

wasm: ## Generate WASM
	@echo "Building WASM for crate: $(CRATE_NAME)"
	@RUSTFLAGS="$(RUSTFLAGS) --remap-path-prefix $(HOME)= -C link-args=-zstack-size=65536" \
	  cargo build -Z build-std=core,alloc \
			--release \
    	--color=always \
			--target $(WASM_TARGET)
	@echo "WASM build complete:"
	@$(MAKE) echo

wasm-opt: $(WASM_FILE) ## Generate optimized WASM
	@if [ -z "$(WASM_OPT)" ]; then \
		echo "wasm-opt not found. Please install it to proceed."; \
		echo "You can install wasm-opt by installing the 'binaryen' package from https://github.com/WebAssembly/binaryen"; \
		exit 1; \
	fi
	@echo "Optimizing WASM for crate: $(CRATE_NAME)"
	@wasm-opt -Oz --strip-debug -o $(WASM_OPT_FILE) $(WASM_FILE)
	@echo "Optimized WASM build complete:"
	@$(MAKE) echo-opt

echo:
	@echo $(WASM_FILE)

echo-opt:
	@echo $(WASM_OPT_FILE)

$(WASM_FILE): wasm ## Compile the WASM

$(WASM_OPT_FILE): wasm-opt ## Compile and optimize the WASM

$(TEST_WASM_FILE): ## Compile the counter-contract used for testing
# 	$(MAKE) wasm -C ../tests/counter

test: $(WASM_FILE) $(TEST_WASM_FILE) ## Run the contract tests
	@cargo test --release \
		-- --test-threads=24 # limit the threads so that CI doesn't throw a persistence error

clippy: ## Run clippy
	@cargo clippy -Z build-std=core,alloc \
		--release \
		--target $(WASM_TARGET) \
	  -- -D warnings

doc: ## Build the docs
	@cargo doc --release

.PHONY: all wasm wasm-opt echo echo-opt test clippy doc 
