STANDARDS_EXAMPLES := standards/examples/authorization_counter standards/examples/drc20_roles_pausable standards/examples/drc721_collection standards/examples/proxy_counter
SUBDIRS := standards/dusk-contract-standards $(STANDARDS_EXAMPLES) tests/alice tests/bob tests/charlie genesis/transfer genesis/stake tests/host_fn
STANDARDS_PROPTEST_CASES ?= 8192
STANDARDS_PROPTEST_MAX_SHRINK_ITERS ?= 16384
STANDARDS_DATA_DRIVER_FUZZ_CASES ?= 2048
STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS ?= 4096

all: setup-compiler $(SUBDIRS) ## Build all the contracts

help: ## Display this help screen
	@grep -h \
		-E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: wasm ## Run all the tests in the subfolder
	$(MAKE) $(SUBDIRS) MAKECMDGOALS=test

wasm: setup-compiler ## Generate the WASM for all the contracts
	$(MAKE) $(SUBDIRS) MAKECMDGOALS=wasm

standards-data-drivers: ## Generate Forge data-driver WASM for standards reference contracts
	$(MAKE) $(STANDARDS_EXAMPLES) MAKECMDGOALS=wasm-dd

standards-properties: ## Run the longer standards property hardening suite
	STANDARDS_PROPTEST_CASES=$(STANDARDS_PROPTEST_CASES) \
	STANDARDS_PROPTEST_MAX_SHRINK_ITERS=$(STANDARDS_PROPTEST_MAX_SHRINK_ITERS) \
	cargo test -p dusk-contract-standards --test properties

standards-data-driver-fuzz: standards-data-drivers ## Fuzz Forge data-driver JSON/rkyv input codecs
	STANDARDS_DATA_DRIVER_FUZZ_CASES=$(STANDARDS_DATA_DRIVER_FUZZ_CASES) \
	STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS=$(STANDARDS_DATA_DRIVER_FUZZ_SHRINK_ITERS) \
	cargo test -p dusk-contract-standards --test data_driver_fuzz -- --ignored

standards-hardening: standards-properties standards-data-driver-fuzz ## Run long standards hardening checks

clippy: setup-compiler ## Run clippy
	$(MAKE) $(SUBDIRS) MAKECMDGOALS=clippy

keys: ## Create the keys for the circuits
	./scripts/download-rusk.sh
	./target/rusk/rusk recovery keys
	
COMPILER_VERSION=v0.3.0-rc.1
setup-compiler: ## Setup the Dusk Contract Compiler
	@./scripts/setup-compiler.sh $(COMPILER_VERSION)

doc: $(SUBDIRS) ## Run doc gen

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: all test help standards-data-drivers standards-properties standards-data-driver-fuzz standards-hardening $(SUBDIRS)
