# What is real here, and what is not

Written for a reviewer who is about to open the files. Everything below is checkable
from this repository in a few minutes. PriceRight is testnet-scoped: Base Sepolia, no
mainnet.

## Executed and verifiable

- **The contracts.** `forge test` runs 46 tests across `test/AgentArena.t.sol`,
  `test/X402Payment.t.sol` and `test/Erc8004.t.sol`, with no vendored dependencies.
  `PYTHONPATH=. python -m pytest tests -q` runs 53 more, keyless and offline.
- **A real x402 payment.** The claim fee is settled by an EIP-3009
  `transferWithAuthorization`, signed off-chain and submitted by the arena, which is
  the `exact` scheme's on-chain settlement primitive as USDC exposes it on Base. The
  resolver holds **no allowance** for the arena, so if the signature were fake the
  claim could not happen; `test_fee_moves_by_signature_not_by_allowance` is that test.
- **Cross-language signature parity.** The Python client signs with the pure-Python
  secp256k1 in `priceright/secp256k1.py`. `test/X402Payment.t.sol` feeds a vector it
  produced to Solidity's `ecrecover`, and
  `tests/test_x402.py::test_solidity_vector_matches_python_signer` regenerates that
  vector from the Python side and compares it against the constants in the `.sol` file.
  Neither side can be edited to fit the other.
- **A real local devnet run.** `./scripts/devnet.sh` starts anvil, deploys all six
  contracts with `forge create`, and runs the demo through `priceright/rpc.py`, which
  builds, RLP-encodes, signs and broadcasts EIP-1559 transactions itself. The RPC
  adapter is network-agnostic: pointing `PRICERIGHT_RPC_URL` at Base Sepolia and
  setting the five address variables runs the identical path against the public
  testnet, which is milestone 1.
- **The resolver does not see the answer.** `Poster` holds the committed truth;
  `ResolverAgent` is given a chain, a policy and a task id. `TaskView` has no `truth`
  field. Feed the evidence policy contradictory readings and its verdict flips
  (`test_evidence_policy_follows_the_evidence`).

## Not executed here, and why

- **No Base Sepolia deployment yet.** There is no funded testnet key in this
  environment, so nothing has been broadcast to Base Sepolia and there is no explorer
  link to give you. The RPC adapter is ready for it; the public deployment and the
  recorded on-chain run are milestone 1, not something already live. There is no
  mainnet path and no funded mainnet key has been used.
- **No hosted CDP facilitator call yet.** The remote rail itself is executed:
  `tests/test_x402.py` stands up a conformant facilitator on a local socket, and the
  claim really does POST the specification's `/verify` body to it over HTTP before
  anything touches the chain. Approved, refused and unreachable are all tested, and the
  last two leave the task Open with no money moved. What has *not* happened is a call
  to Coinbase's hosted CDP facilitator, because that needs credentials this environment
  does not have; that is milestone 3.
  One design point, so it is not mistaken for a shortcut: verification can be remote,
  settlement cannot. `AgentArena.claimTask` consumes the EIP-3009 authorisation itself,
  in the same transaction that records the claim and bonds collateral. A facilitator
  that broadcast the authorisation first would burn the nonce and make the claim
  impossible, so the arena is the settler and the facilitator is an extra gate in front
  of it. Neither a rejection nor an unreachable host has a fallback.
- **No CDP AgentKit wallets yet.** The resolver and poster sign with local devnet keys
  (the well-known anvil accounts, which exist everywhere and hold value nowhere).
  Provisioning those identities as CDP wallets through AgentKit is milestone 2; the
  signer sits behind a seam so the swap does not touch the arena.
- **No LLM in the resolver.** The resolver is a deterministic evidence parser, not a
  model, and nothing here claims otherwise. That is a design choice for a demo that has
  to be reproducible in front of a reviewer: the interesting property is that the
  verdict is *derived from evidence the resolver can be given or denied*, and a model
  can be dropped in behind the same `decide(claim, evidence) -> Decision` interface.
- **ERC-8004 is implemented, not imported.** `src/erc8004/` contains a self-contained
  Identity registry (a real ERC-721: `supportsInterface` reports `0x80ac58cd`,
  transfers and approvals work, and reputation is keyed by `agentId` so it follows the
  token), a Reputation registry with permissionless `giveFeedback` and client-filtered
  `getSummary`, and a Validation registry with request/response. It follows the
  standard's structure and function shapes rather than importing a reference
  deployment, and it does not implement every optional part of the specification.
  Collateral and slashing live in `AgentStakeVault`, outside the registries, because
  ERC-8004 leaves economics to an extension.
- **The fee token is a mock.** `MockERC20` implements EIP-3009 the way USDC does, so
  the arena is written against the interface a real Base deployment would use. It has a
  free `mint`; it is a devnet token, not USDC.

## The interactive panel in the UI

The left side of `ui/index.html` is a recording. The right side is not: it recomputes
`correct = (committed == truth)` in the page, against the truth the recorded poster
revealed, and hashes your reasoning with an in-page keccak-256 that is asserted against
the standard empty and `"abc"` vectors on load. It says so in the panel, and it does
not draw transaction hashes for anything it did not do.

## Provenance

Built with AI coding assistance (Claude) for contract scaffolding, test authoring and
documentation. The design decisions, the threat cases the tests encode, and the review
of the output are the author's.
