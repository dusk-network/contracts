STANDARDS_EXAMPLES := standards/examples/authorization_counter standards/examples/drc20_roles_pausable standards/examples/drc721_collection standards/examples/multisig_controller standards/examples/proxy_counter
LEGACY_SUBDIRS := tests/alice tests/bob tests/charlie genesis/transfer genesis/stake tests/host_fn
STANDARDS_PROPTEST_CASES ?= 8192
STANDARDS_PROPTEST_MAX_SHRINK_ITERS ?= 16384
STANDARDS_DATA_DRIVER_FUZZ_CASES ?= 2048
STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS ?= 4096

all: setup-compiler $(LEGACY_SUBDIRS) ## Build the legacy genesis/test contracts

help: ## Display this help screen
	@grep -h \
		-E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: wasm ## Run all the tests in the subfolder
	$(MAKE) $(LEGACY_SUBDIRS) MAKECMDGOALS=test

wasm: setup-compiler ## Generate the WASM for all the contracts
	$(MAKE) $(LEGACY_SUBDIRS) MAKECMDGOALS=wasm

standards-fmt: ## Check Dusk standards formatting without the Dusk compiler bundle
	cargo fmt --manifest-path standards/Cargo.toml --all --check

standards-check: ## Check the Dusk standards crate without the Dusk compiler bundle
	$(MAKE) -C standards/dusk-contract-standards check

standards-test: ## Test the Dusk standards crate without the Dusk compiler bundle
	$(MAKE) -C standards/dusk-contract-standards test

standards-wasm: ## Build standards reference contracts without the Dusk compiler bundle
	$(MAKE) $(STANDARDS_EXAMPLES) MAKECMDGOALS=wasm

standards-clippy: ## Run standards clippy without the Dusk compiler bundle
	$(MAKE) -C standards/dusk-contract-standards clippy
	$(MAKE) $(STANDARDS_EXAMPLES) MAKECMDGOALS=clippy

standards-ci: standards-fmt standards-check standards-clippy standards-test standards-wasm ## Run regular standards CI checks

standards-data-drivers: ## Generate Forge data-driver WASM for standards reference contracts
	$(MAKE) $(STANDARDS_EXAMPLES) MAKECMDGOALS=wasm-dd

standards-properties: ## Run the longer standards property hardening suite
	STANDARDS_PROPTEST_CASES=$(STANDARDS_PROPTEST_CASES) \
	STANDARDS_PROPTEST_MAX_SHRINK_ITERS=$(STANDARDS_PROPTEST_MAX_SHRINK_ITERS) \
	cargo test --manifest-path standards/Cargo.toml -p dusk-contract-standards --test properties

standards-data-driver-fuzz: standards-data-drivers ## Fuzz Forge data-driver JSON/rkyv input codecs
	STANDARDS_DATA_DRIVER_FUZZ_CASES=$(STANDARDS_DATA_DRIVER_FUZZ_CASES) \
	STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS=$(STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS) \
	cargo test --manifest-path standards/Cargo.toml -p dusk-contract-standards --test data_driver_fuzz -- --ignored

standards-hardening: standards-properties standards-data-driver-fuzz ## Run long standards hardening checks

clippy: setup-compiler ## Run clippy
	$(MAKE) $(LEGACY_SUBDIRS) MAKECMDGOALS=clippy

keys: ## Create the keys for the circuits
	./scripts/download-rusk.sh
	./target/rusk/rusk recovery keys
	
COMPILER_VERSION=v0.3.0-rc.1
setup-compiler: ## Setup the Dusk Contract Compiler
	@./scripts/setup-compiler.sh $(COMPILER_VERSION)

doc: $(LEGACY_SUBDIRS) ## Run doc gen

$(LEGACY_SUBDIRS) $(STANDARDS_EXAMPLES):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: all test help standards-fmt standards-check standards-test standards-wasm standards-clippy standards-ci standards-data-drivers standards-properties standards-data-driver-fuzz standards-hardening $(LEGACY_SUBDIRS) $(STANDARDS_EXAMPLES)
