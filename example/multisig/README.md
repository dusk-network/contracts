# MultiSig Authorization Contract

## Overview

This contract implements a **multi-signature authorization layer** for the Dusk network.

It coordinates **admin approvals** for arbitrary operations and, once the required threshold is reached, **authorizes the execution of a call on a third-party contract**.

Notably, this contract **does not hold or move funds**.
The actual logic that moves funds, updates balances, or performs sensitive state changes **must live in an external contract** (the “target contract”), which trusts this multisig as its authorization mechanism.

In short:

> **This contract decides *who* is allowed to execute an action.
> Another contract decides *what* that action does.**

---

## Key Properties

### What this contract does

* Manages a set of **admin public keys**
* Enforces a **threshold** (e.g. 2-of-3, 3-of-5)
* Tracks **pending proposals** identified by a stable operation hash (`op_id`)
* Accumulates approvals from different admins
* Automatically executes an authorized call **once the threshold is reached**
* Prevents immediate replay of recently executed operations
* Supports multiple proposals **in parallel**
* Allows explicit repetition of the same logical operation via a `salt`

### What this contract does *not* do

* ❌ It does **not** store funds
* ❌ It does **not** transfer tokens or coins
* ❌ It does **not** custody assets
* ❌ It does **not** implement a wallet
* ❌ It does **not** aggregate off-chain signatures
* ❌ It does **not** support meta-transactions or relayers

If you are looking for a multisig **wallet**, this is not it.

---

## Architecture

```
Admins (EOAs)
   │
   │  propose / approve
   ▼
MultiSig Authorization Contract
   │
   │  authorized call
   ▼
Target Contract (Treasury, Vault, Bridge, etc.)
   │
   │  moves funds / updates balances
   ▼
Assets
```

The **target contract** must explicitly trust this multisig, for example by checking:

* `msg.sender == multisig_contract_id`, or
* ownership/role assigned to the multisig contract.

---

## Proposal Model (op_id-first)

### Operation Identity (`op_id`)

Each operation is identified by an `op_id`, computed as a hash of:

* chain id
* multisig contract id
* target contract id
* function name
* function arguments
* `salt`

Notably **excluded**:

* block height
* deadlines
* nonces

This means:

* Identical operations proposed by different admins are **merged**
* Approvals are **summed**, not duplicated
* Two proposals for the same operation become **one pending proposal**

### Salt

The `salt` field exists to allow **explicit repetition**.

* Same target + same args + same salt → same `op_id`
* Same target + same args + **different salt** → different `op_id`

In practice:

* Most operations will use a zero or fixed salt
* A non-zero salt is only needed if you want to intentionally repeat the same call

---

## Proposal Lifecycle

### 1. Propose

Any admin can call `propose(target)`.

* If the operation is new:

  * A pending proposal is created
  * The caller’s approval is recorded
* If the operation is already pending:

  * The call behaves like an approval (idempotent)
* If the operation was recently executed:

  * The call **fails** (replay protection)

### 2. Approve

Admins approve by calling `approve(op_id)`.

* Approval is **idempotent**
* Re-approving does nothing and does not fail
* Approvals can happen in any order

### 3. Auto-Execution

As soon as `approvals >= threshold`:

* The target call is executed immediately
* The pending proposal is removed
* A temporary tombstone is recorded to prevent immediate replay

There is **no separate execute step**.

---

## Expiration (TTL)

Each proposal has a **deadline**, computed automatically as:

```
deadline = current_block_height + proposal_ttl_blocks
```

If a proposal expires:

* It can no longer be approved
* It will be pruned during future proposal calls (bounded cleanup)

The TTL is configurable by admins.

---

## Replay Protection

After execution, an operation enters a **replay protection window**:

* The `op_id` is tombstoned for `replay_window_blocks`
* Any attempt to repropose the same operation during this window **fails**
* After the window expires, the operation may be proposed again

  * or earlier, by changing the `salt`

This prevents:

* delayed transactions from recreating proposals
* accidental double execution shortly after approval

---

## Parallelism

This contract supports **many concurrent proposals**:

* Proposals are keyed by `op_id`, not by a global nonce
* There is no “single active proposal” limitation
* Admins can approve different operations independently

---

## Call Restrictions

All interactions require:

* a **public transaction**
* a **direct call** (no nested contract calls)
* the sender to be a registered admin

This is enforced via:

* `public_sender` checks
* call stack depth checks

---

## Trust Model

This multisig assumes:

* Admin private keys are externally secured
* The target contract correctly enforces authorization
* The multisig contract is correctly configured as an authority/owner

This contract **only answers the question**:

> “Has this operation been approved by enough admins?”

---

## Typical Use Cases

* Treasury authorization
* Protocol parameter changes
* Contract upgrades
* Bridge governance
* Emergency pause / unpause
* DAO-style admin coordination

---

## Non-Goals

This contract intentionally does **not**:

* aggregate BLS signatures
* support gasless approvals
* provide account abstraction
* manage balances
* implement recovery or social guardians

Those concerns are better handled in separate layers.

---

## Summary

* This is a **multisig authorization engine**, not a wallet
* Approvals are simple, idempotent, and on-chain
* Execution is automatic and deterministic
* Funds always live elsewhere
