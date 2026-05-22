CONTRACTS := multisig

all: $(CONTRACTS) ## Build all the example contracts

help: ## Display this help screen
	@grep -h \
		-E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

wasm: $(CONTRACTS) ## Generate the WASM for all example contracts

test: $(CONTRACTS) ## Run the tests for all example contracts
	$(MAKE) -C ./multisig-core $@

fmt: ## Check code formatting
	@cargo fmt --all -- --check

clippy: $(CONTRACTS) ## Check clippy for all example contracts
	$(MAKE) -C ./multisig-core $@

doc: $(CONTRACTS) ## Build the docs for all example contracts
	$(MAKE) -C ./multisig-core $@

$(CONTRACTS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: all help wasm data-drivers data-drivers-js test fmt clippy doc $(CONTRACTS)
