# PriceRight demo shot list

The story is two agents paying the same x402 fee and getting opposite outcomes,
against a chain a reviewer can query afterwards. x402 priced the request. PriceRight
prices being wrong.

## The keyless version (no node, no toolchain, no credentials)

```
PRICERIGHT_OFFLINE=1 PYTHONUNBUFFERED=1 PRICERIGHT_PACE=0.6 PYTHONPATH=. \
  python -u -m priceright.main demo
```

Same code path, same signatures, executed against the in-memory chain, which runs the
same state machine in process and still verifies every signature. `PRICERIGHT_PACE`
adds a pause between beats for a screen recording; leave it unset for an instant run.

Shot list:

1. Two ERC-8004 identities register: agent #1 reads evidence, agent #2 trusts a cache.
2. Agent #1 posts, reasons from three oracle readings, and the claim endpoint answers
   `402 Payment Required` with scheme `exact`, an amount, an asset and a pinned nonce.
3. The resolver signs an EIP-3009 authorisation and the settled transaction hash appears.
4. Collateral is bonded, the verdict and reasoning hash are committed.
5. Settlement: CORRECT, credited 110 tUSD, collateral returned, score 100%.
6. Agent #2, same task, answers from a week-old cached quote: WRONG, 50 tUSD of
   collateral seized and moved to the poster, score 0%.
7. The ledger line closes the loop: held equals owed out plus locked, nothing stranded.

## The refusals (30 seconds, and the most convincing part)

```
PRICERIGHT_OFFLINE=1 PYTHONPATH=. python -m priceright.main guards
```

1. An authorisation signed for task #1 is refused on task #2: the nonce is bound to
   (arena, chain, task, agent).
2. A payment whose validity window was stretched after signing fails verification.
3. Given evidence that does not cover the claim, the resolver abstains and pays nothing.
4. The same evidence policy, given contrary readings, returns the opposite verdict,
   which is what a resolver that had been handed the answer could not do.

## The Base Sepolia run (milestone 1 target)

`./scripts/devnet.sh` starts anvil, deploys the six contracts, wires the vault
operator and balances, records the run into `docs/run.json` and `ui/index.html`, and
plays the demo through the JSON-RPC adapter. Pointing `PRICERIGHT_RPC_URL` at Base
Sepolia and setting the five address variables runs the identical code path against
the public testnet. That deployment is milestone 1; the offline record above is what
ships keyless today.

```
source .devnet.env
cast logs --rpc-url $PRICERIGHT_RPC_URL --from-block 0 'Slashed(bytes32,uint256,address,uint256)'
cast call --rpc-url $PRICERIGHT_RPC_URL $PRICERIGHT_VAULT_ADDRESS 'slashedOf(uint256)(uint256)' 2
```

## The UI (`ui/index.html`, opens as a static file)

1. Left column: the recorded run, with contract addresses, the x402 header, and the
   on-chain event list carrying transaction hashes.
2. Right column: the settlement rule recomputed in the page. It says so; it does not
   pretend to send anything.
3. Flip the verdict and press "Apply the rule": the collateral bar drains, the badge
   turns red, the ERC-8004 score falls, and the reasoning hash recomputes live with an
   in-page keccak-256 that is asserted against the standard vectors on load.

## Tests

```
forge test                              # 46 Solidity
PYTHONPATH=. python -m pytest tests -q  # 53 Python
```
