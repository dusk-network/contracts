SUBDIRS := contracts/alice contracts/bob contracts/charlie contracts/transfer contracts/stake contracts/host_fn

all: setup-compiler $(SUBDIRS) ## Build all the contracts

help: ## Display this help screen
	@grep -h \
		-E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: wasm $(SUBDIRS) ## Run all the tests in the subfolder

wasm: setup-compiler $(SUBDIRS) ## Generate the WASM for all the contracts

clippy: $(SUBDIRS) ## Run clippy

COMPILER_VERSION=v0.3.0-rc.1
setup-compiler: ## Setup the Dusk Contract Compiler
	@./scripts/setup-compiler.sh $(COMPILER_VERSION)

doc: $(SUBDIRS) ## Run doc gen

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: all test help $(SUBDIRS)
