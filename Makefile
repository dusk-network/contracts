SUBDIRS := contracts/alice contracts/bob contracts/charlie contracts/transfer contracts/stake contracts/host_fn

all: setup-compiler $(SUBDIRS) ## Build all the contracts

help: ## Display this help screen
	@grep -h \
		-E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: wasm ## Run all the tests in the subfolder
	$(MAKE) $(SUBDIRS) MAKECMDGOALS=test

wasm: setup-compiler ## Generate the WASM for all the contracts
	$(MAKE) $(SUBDIRS) MAKECMDGOALS=wasm

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

.PHONY: all test help $(SUBDIRS)
