<div align="center">

# `📜 Contracts`

> Dusk Genesis, Test & Ecosystem Contracts
</div>

## Overview

This repository contains smart contracts for the Dusk ecosystem:

- Genesis protocol contracts: part of the genesis state and provide core
  functionality to the Dusk protocol.
- Test contracts: small contracts used for integration tests and host function
  coverage.

Other parts of the protocol are implemented largely in
[Rusk](https://github.com/dusk-network/rusk).

## Genesis Protocol Contracts

### [Transfer contract](contracts/transfer)

The transfer contract acts as the entrypoint for any transaction happening on the network and manages the native Dusk token.

The on-chain ContractId for the transfer contract is:

`0100000000000000000000000000000000000000000000000000000000000000`

### [Stake contract](contracts/stake)

The stake contract tracks public key stakes. It allows users to stake Dusk tokens subject to a maturation period before becoming eligible for consensus participation.

The on-chain ContractId for the stake contract is:

`0200000000000000000000000000000000000000000000000000000000000000`

## Test Contracts

- [`alice`](contracts/alice): exercises calls into the transfer contract
  (deposit/withdraw/contract-to-contract) and staking via the relayer.
- [`bob`](contracts/bob): example contract with an owner-restricted call and a
  `ReceiveFromContract` handler.
- [`charlie`](contracts/charlie): relayer contract that stakes/unstakes/withdraws
  on behalf of a contract via the transfer and stake contracts.
- [`host_fn`](contracts/host_fn): wraps host functions (hashing, signature/proof
  verification, chain metadata, etc.) for testing.
