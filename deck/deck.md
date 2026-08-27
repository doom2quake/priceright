---
marp: true
theme: uncover
class: invert
paginate: true
style: |
  section { font-size: 26px; }
  h1 { color: #ff6ad5; }
  strong { color: #c04cff; }
  code { background: #160f1f; color: #3ce8a0; }
  .fail { color: #ff4d6d; }
  .pass { color: #3ce8a0; }
---

# PriceRight

### An accountability layer for **x402 agent commerce on Base**

signed x402 payments &middot; ERC-8004 identity + collateral &middot; deterministic slashing

Dipankar Sarkar &middot; Base Builder Grants &middot; 2026

---

## The problem

x402 makes an agent-to-agent USDC payment on Base one HTTP round trip.

But the rail prices the **request**, not the **answer**:

- answer right, keep the fee
- answer **wrong**, keep the fee anyway

The lazy resolver reads a stale cache instead of the fresh check, collects, and is
wrong. The party who built a workflow on that answer pays for it.

x402 priced the request. **Nothing prices being wrong.**

---

## Why Base, why now

Three things are already true on Base at once:

- **x402** settlement is native: the `exact` scheme is USDC's EIP-3009
  `transferWithAuthorization`, a fee bound to a unit of work
- **CDP AgentKit** gives agents wallets that can hold collateral and sign
- **ERC-8004** identity carries reputation that travels when the identity is sold

The accountability layer is the missing brick. PriceRight is it.

---

## Scope (milestone 1)

One economy, one hero, fully built and tested:

- a resolver agent answers subjective **yes/no** tasks
- it **pays** to answer with x402 and **bonds its ERC-8004 identity**
- a **deterministic** settlement rewards right and **slashes** wrong

Base Sepolia, testnet only. Not a marketplace, not a DAO. One credible punishment,
end to end.

---

## The solution

A task poster commits a hidden ground truth.

1. the claim endpoint answers **402 Payment Required**
2. the resolver signs an **EIP-3009 authorisation** and sends `X-PAYMENT`
3. collateral is bonded against its **ERC-8004 identity**
4. it commits a verdict + **keccak-256 of its reasoning**
5. settlement compares committed verdict vs revealed truth

<span class="pass">right &rarr; fee back + bounty + collateral, feedback 100</span>
<span class="fail">wrong &rarr; collateral **seized to the poster**, feedback 0</span>

---

## How it works

```
postTask(bounty, fee, collateral, keccak(truth,salt))       poster
claimTask(taskId, agentId, X402Payment{...v,r,s})           resolver
  -> token.transferWithAuthorization(...)   fee moves by signature
  -> vault.bondFor(bondKey(taskId), agentId, ...)
commitVerdict(taskId, v, keccak(reasoning))                 resolver
settle(taskId, truth, salt)                                 poster
  correct -> vault.release + credit resolver + feedback 100
  wrong   -> vault.slash  + credit poster   + feedback 0
```

The slash is a **pure function** of (verdict, truth). No override, and no path leaves
collateral stranded in the contracts.

---

## Demo

Keyless, no node, no credentials:

```
PRICERIGHT_OFFLINE=1 python -m priceright.main demo
```

- **agent #1** evidence policy &rarr; <span class="pass">CORRECT, +110 tUSD, collateral returned, score 100%</span>
- **agent #2** stale-cache policy &rarr; <span class="fail">WRONG, 50 tUSD collateral seized, score 0%</span>

Point `PRICERIGHT_RPC_URL` at Base Sepolia and the same code path sends real
transactions. Agent #2 is not rigged to lose: give its cache a threshold it clears and
it wins.

---

## Why the sponsor tech is load-bearing

- **x402:** the real `exact` scheme - 402 challenge, EIP-3009 authorisation over USDC,
  verify, settle. The fee moves by signature with **no allowance** to the arena.
- **CDP AgentKit:** the resolver and poster identities are CDP wallets (M2); the signer
  sits behind a seam so the swap does not touch the arena.
- **ERC-8004:** identity is a **real ERC-721** (`supportsInterface` 0x80ac58cd);
  feedback is permissionless and client-filtered; reputation follows the token.
- **Base:** Base Sepolia deployment and a queryable public slash are the M1 artifact.

---

## Results

- **46** Foundry tests and **53** Python tests pass, from a clean checkout
- The Python x402 signature is verified by Solidity `ecrecover`, and the Python suite
  regenerates that vector and pins it against the `.sol` constants - neither side drifts
- The remote facilitator is a real HTTP round trip that **fails closed**: refused or
  unreachable leaves the task open, nothing paid
- Every terminal path empties the escrow; the timeout paths are permissionless

Not yet on Base Sepolia (no funded key here); `docs/HONESTY.md` and
`docs/LIMITATIONS.md` say so plainly.

---

## Roadmap

- **M1** PriceRight repo + Base Sepolia deployment + a recorded public slash
- **M2** CDP AgentKit wallets as the resolver and poster identities
- **M3** settlement through the hosted CDP facilitator, same fail-closed guarantee
- **M4** a `bond / claim / commit / settle / readReputation` SDK, reference agent, docs

Open source, MIT, testnet-scoped. A mainnet audit precedes any real-value use.

---

# PriceRight

### Pay to answer. Bond your identity. Be wrong, pay for it.

<span class="pass">right is paid</span> &middot; <span class="fail">wrong is seized</span> &middot; no human in the loop

Dipankar Sarkar &middot; 2026
