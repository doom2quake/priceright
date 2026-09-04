# PriceRight: an accountability layer for x402 agent commerce on Base

**Applicant:** doom2quake (builder collective)
**Programme:** Base CDP Builder Grants (Coinbase Developer Platform)
**Requested:** milestone-based builder grant, non-dilutive
**New project repo:** `github.com/doom2quake/priceright` (new repo, purpose-built for this proposal)
**Stack:** x402 payment protocol / CDP AgentKit / USDC on Base
**Status of this document:** draft grant entry, testnet-only scope, no mainnet deployment

---

## 0. What we are applying to, verified

We verified the programme against Coinbase and Base pages before writing.

**VERIFIED on official pages (fetched 2026-08-24):**

- Base and the Coinbase Developer Platform fund builders shipping on Base through builder grants. The stated principle on `docs.base.org/get-started/get-funded` is "shipped code over perfect pitches": awards reward work that is already live, not a pitch deck.
- The Base Builder Grants track is retroactive and ETH-denominated (a stated range of 1 to 5 ETH, non-dilutive), applied for through `paragraph.com/@grants.base.eth`.
- The Coinbase Developer Platform runs separate builder-grant cohorts judged on creativity, utility, and real usage, tied to CDP products (AgentKit, wallets, the x402 facilitator).

**CONFLICT we are flagging honestly:** `base.org/grants` returned 404 and the CDP AgentKit-edition builder-grants launch page returned 403 to our fetch, so the exact CDP-cohort amounts and process (historically reported around $30k USD split across a handful of projects) are INFERRED from search summaries and Coinbase launch posts, not confirmed by us directly. **An operator must confirm which track is open and accepting before we invest applicant time.** This is the single gating check. Grant windows are not open right now, which is why this repo is being brought to a ready-to-submit state rather than submitted.

**INFERRED (not stated verbatim on an official page):** that an x402 accountability layer maps onto CDP's agent-commerce focus. The mapping is ours; the product names (x402, AgentKit, the CDP facilitator) are Coinbase's.

---

## 1. The problem

An agent that spends money on your behalf has no built-in reason to be right. x402 makes
it trivial for one agent to pay another for an answer, a data pull, or a task result: a
402 challenge, a signed authorization, a settlement in USDC on Base, done in one round
trip. That rail is now real and growing. What the rail does not carry is any consequence
for a wrong answer. The paying agent gets a response and a receipt; whether the response
was diligent or was a stale cached guess is invisible at settlement time. The money moves
either way.

The concrete failure is the lazy resolver. An agent is asked whether a condition holds,
it has a fresh way to check and a cheap cached value from last week, and nothing prices
the difference. It answers from the cache, collects the fee, and is wrong. The party that
suffers is whoever built a workflow on top of that answer: a settlement fires on a false
premise, a downstream agent compounds the error, and the only recourse is an
after-the-fact dispute with no on-chain record of who committed what, when, or what
reasoning stood behind it. As agent-to-agent payments scale on Base, this is the missing
primitive. x402 priced the request. Nothing prices being wrong.

## 2. Why Base and the CDP, why now

This only works where three things are already true at once, and Base plus the Coinbase
Developer Platform is where they are.

- **x402 settlement is native and load-bearing.** The `exact` scheme uses USDC's
  EIP-3009 `transferWithAuthorization`: the fee moves by an off-chain signature, bound to
  a specific request, charged once. That is exactly the primitive USDC exposes on Base and
  Base Sepolia, and it is what lets a payment be cryptographically tied to a unit of work
  instead of a loose allowance.
- **CDP AgentKit gives the agents wallets and the CDP facilitator gives them a settlement path.**
  An agent with a CDP wallet can hold collateral, sign an x402 authorization, and settle
  through a facilitator without a human in the loop. The accountability layer we build
  needs agents that can be economically bonded, and AgentKit is the shortest path to
  agents that actually custody value on Base.
- **ERC-8004 identity and reputation are emerging on this stack.** For a slash to mean
  anything, the punished agent must carry its record forward. An ERC-721 identity whose
  reputation travels with it when the identity is sold is the mechanism, and it composes
  directly with the x402 payment rail on the same chain.

The timing: x402 shipped, AgentKit is in the hands of builders, and Coinbase is actively
funding exactly this category of agent-commerce infrastructure through Base Builder Grants
and the CDP cohorts. The accountability layer is the natural next brick, and it is missing.

## 3. Evidence we ship

**Milestone-1 build, verified.** The PriceRight repo is built and green at
`projects/base-cdp/app` (a new self-contained repo, themed to Base, CDP AgentKit and
x402). Milestone 1 (the arena, vault and ERC-8004 registries, the full x402 `exact` claim
flow, and the deterministic slash, tested and runnable) is complete. Verified on this
machine on 2026-09-04:

- **`forge test`: 46 Solidity tests pass** (solc 0.8.24, no vendored dependencies) across
  the arena, the x402 payment, and the ERC-8004 registries.
- **`PYTHONPATH=. pytest tests -q`: 53 Python tests pass**, keyless and offline. No env
  vars or credentials needed.

Total **99 tests passing**. The cross-language secp256k1 / EIP-712 parity vectors are
pinned in both `test/X402Payment.t.sol` and `tests/test_x402.py`. A keyless run
(`PRICERIGHT_OFFLINE=1 python -m priceright.main demo`) plays the paid claim, the correct
settlement and the slash; the static UI (`ui/index.html`, screenshot at `docs/ui.png`)
shows the recorded run and recomputes the settlement rule in-page. What remains for M1 is
the Base Sepolia broadcast and the recorded public on-chain run, which needs a funded
testnet key this environment does not hold; the RPC adapter runs the identical code path
once that key is supplied. Honesty and limits are stated in `docs/HONESTY.md` and
`docs/LIMITATIONS.md`.

The properties that matter, each with a test:

- **x402 is the real `exact` flow, not a mock.** The claim endpoint returns a real HTTP
  402 with an `accepts` array of `PaymentRequirements`; paying it means signing an
  EIP-3009 `TransferWithAuthorization` over EIP-712, base64-ing it into an `X-PAYMENT`
  header, and having a facilitator verify and settle. The fee moves by signature not by
  allowance (`test_fee_moves_by_signature_not_by_allowance`), the payment is bound to its
  task so an authorization for one task is worthless on another
  (`test_payment_is_bound_to_its_task`), and it is charged exactly once because a replay
  reverts inside the token (`test_payment_authorisation_cannot_be_replayed`).
- **The remote facilitator is a real HTTP round trip that fails closed.** The suite stands
  up a conformant facilitator on a local socket and runs the claim through it; approved
  lets the claim land, refused and unreachable both stop it with nothing paid
  (`test_remote_facilitator_verifies_over_http_before_the_arena_settles`,
  `test_an_unreachable_facilitator_fails_closed`).
- **Cross-language signature parity is pinned both directions.** The Python client signs
  with a pure-Python secp256k1 (`priceright/secp256k1.py`, RFC 6979, EIP-2 low-s). A
  Solidity test feeds a Python-produced vector to `ecrecover`, and a Python test
  regenerates that vector and pins it against the constants in the `.sol` file. Neither
  language can drift from the other.
- **The slash is computed, not scripted.** Two agents pay the same fee; one reads the
  evidence and is paid, the other answers from a week-old cached quote and loses its
  collateral to the poster and takes a zero into its on-chain reputation. Give the same
  stale-cache policy a threshold its quote clears and it wins instead
  (`priceright guards` demonstrates this).
- **The resolver never sees the answer.** The poster hash-commits the truth before anyone
  can see it; the resolver derives its verdict from evidence and there is no `truth` field
  on the view it is given.

We are not proposing from zero. The accountability engine already runs, is tested on both
sides of the wire, and was put through a hostile independent review whose findings we
fixed with tests that fail without the fix.

## 4. Milestone roadmap

Four milestones. Each has a target date, a deliverable, how a reviewer verifies it without
trusting us, and what it unlocks. Web3 here is testnet only: Base Sepolia, no mainnet.

**M1: PriceRight repo, Base Sepolia deployment (target 2026-09-15). BUILT (deploy pending a funded key).**
Deliverable: the `priceright` repo with the arena, vault, and ERC-8004 registries deployed
to Base Sepolia, and a recorded run posting a task, settling an x402 claim, and executing a
slash on that public testnet.
Verify: the reviewer opens the recorded `run.json`, takes the transaction hashes, and reads
them back on the Base Sepolia explorer; `cast logs` against the deployed arena shows the
`Slashed` event. The 99-test suite runs green from a clean checkout.
Status: the repo, the full x402 flow, and the deterministic slash are complete and green;
the Base Sepolia broadcast is the one remaining step and needs a funded testnet key this
environment does not hold.
Unlocks: a public, queryable slash on Base.

**M2: CDP AgentKit wallets as the resolver and poster identities (target 2026-10-10).**
Deliverable: the resolver and poster hold CDP wallets provisioned through AgentKit rather
than raw local keys, and bond collateral and sign the x402 authorization from those wallets.
Verify: the reviewer inspects the wallet-provisioning code path, sees the collateral bond
transaction originate from the AgentKit-managed address on Base Sepolia, and confirms the
signer is the CDP wallet, not a bare keypair. A test pins that the bond and the x402
signature share the AgentKit address.
Unlocks: agents that any AgentKit builder can drop in, because the identity is the CDP
wallet they already use.

**M3: CDP facilitator settlement path (target 2026-11-05).**
Deliverable: the x402 claim settles through the CDP-hosted facilitator on Base Sepolia, in
addition to the local-socket facilitator already tested, with the same fail-closed guarantee.
Verify: the reviewer points the facilitator URL at the CDP facilitator, runs a claim, and
sees the `/verify` body go over the wire before anything touches the chain; a refused or
unreachable facilitator leaves the task open with no money moved.
Unlocks: settlement on the same facilitator the rest of the Base agent economy uses, so
PriceRight is a drop-in accountability wrapper rather than a parallel stack.

**M4: reusable SDK and reference agent, docs and a hosted demo (target 2026-12-01).**
Deliverable: a small library exposing `bond`, `claim`, `commit`, `settle`, and
`readReputation` against the deployed Base Sepolia contracts, a reference resolver, and a
static UI plus written docs so another builder can bond an agent and produce a slash in
under an hour.
Verify: the reviewer follows the quickstart from a clean machine and reaches a recorded
slash on Base Sepolia; the UI recomputes the settlement rule from the on-chain events
rather than displaying a stored result.
Unlocks: other Base builders wrapping their own x402 agents in accountability.

**After the grant.** The contracts and SDK stay open-source and deployed on Base Sepolia.
The next steps we would pursue with or without further funding are a mainnet audit before
any real-value deployment (explicitly out of scope for a testnet grant), a second policy
family beyond the evidence-vs-cache demo, and a facilitator-agnostic conformance test kit
so any x402 facilitator can be checked against PriceRight's fail-closed contract.

## 5. Ecosystem impact

Everything here is reusable by other Base builders and is open-sourced under MIT.

- **A dropped-in accountability layer for x402 agents.** The `bond / claim / commit /
  settle / readReputation` surface wraps any x402 resolver, so a builder who already has
  an AgentKit agent taking x402 payments can make it economically accountable without
  rewriting their agent.
- **A dependency-free x402 client and facilitator in Python.** The 402 challenge, the
  EIP-3009 EIP-712 signing, the secp256k1 implementation, and the facilitator HTTP client
  are all standard-library, which makes them a clean reference for anyone implementing the
  `exact` scheme against Base USDC.
- **A conformance harness for facilitators.** The local-socket facilitator and the
  fail-closed tests are a reusable way to check that a facilitator verifies before it
  settles and that a refusal stops the money, which is a public good for the whole x402
  facilitator ecosystem.
- **A worked ERC-8004 example on Base.** A real ERC-721 identity whose reputation
  transfers with it, permissionless filterable feedback, and a validation request filed at
  commit time, all deployed and queryable, as a reference for builders adopting the standard.

## 6. Sustainability and honest limits

**What keeps it alive after the money ends.** The core is a set of deployed testnet
contracts and a small SDK with no runtime dependencies and no hosting cost beyond a static
page and a public RPC. There is nothing to keep paying for. Maintenance is bounded because
the surface is small and the tests are the specification. Adoption, if it comes, comes from
other Base builders wrapping their own agents, not from us operating a service.

**What is NOT built, deployed, or measured. Stated plainly so diligence finds nothing we hid.**

- **No users.** Nobody uses PriceRight. There is no traction, no waitlist, no pilot.
- **No mainnet deployment.** Web3 here is testnet only. The code has run on a local anvil
  devnet; the Base Sepolia deployment is M1, not something already live. There is no mainnet
  path and no funded mainnet key has been used.
- **No revenue.** The project earns nothing and has no business model beyond being
  infrastructure other builders can use.
- **No audit.** The contracts have had a hostile internal review and carry tests, but no
  third-party security audit. Any real-value use would need one first, which is why the scope
  is testnet.
- **No partnership with Coinbase, Base, or the CDP team**, and no endorsement. This is an
  application.
- **No hosted CDP facilitator call yet.** The remote-facilitator rail is executed against a
  conformant facilitator we stand up locally; calling Coinbase's hosted facilitator needs
  credentials this environment does not have, and it is M3, not done.
- **No LLM in the resolver.** The resolver is a deterministic evidence parser, chosen so a
  demo is reproducible in front of a reviewer. A model can be dropped in behind the same
  `decide(claim, evidence)` interface, but the property that matters, that the verdict is
  derived from evidence the resolver can be given or denied, does not depend on one.

We arrive with working, tested code and a small, verifiable claim. We do not arrive with
traction, and we are not going to pretend otherwise.

---

## Citation

```bibtex
@software{sarkar_priceright_2026,
  author  = {Dipankar Sarkar},
  title   = {PriceRight: An Accountability Layer for x402 Agent Commerce on Base},
  year    = {2026},
  url     = {https://github.com/doom2quake/priceright},
  license = {MIT}
}
```

License: MIT, held by doom2quake. Testnet only; no mainnet, no real funds.
