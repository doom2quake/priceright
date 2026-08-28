# Limitations

Stated plainly so diligence finds nothing that was hidden. PriceRight arrives with
working, tested code and a small, verifiable claim. It does not arrive with traction,
and this document does not pretend otherwise.

- **No users.** Nobody uses PriceRight. There is no traction, no waitlist, no pilot,
  no design partner.
- **No Base Sepolia deployment yet.** Web3 here is testnet only. The code has run on a
  local anvil devnet; the Base Sepolia deployment and the recorded public on-chain run
  are milestone 1, not something already live. There is no explorer link to hand you.
- **No mainnet deployment.** There is no mainnet path and no funded mainnet key has
  been used. The whole design is scoped to Base Sepolia.
- **No revenue.** The project earns nothing and has no business model beyond being
  infrastructure other Base builders can use.
- **No audit.** The contracts have had a hostile internal review and carry tests, but
  no third-party security audit. Any real-value use would need one first, which is why
  the scope is testnet.
- **No partnerships.** There is no relationship with Coinbase, Base, or the CDP team
  beyond being a grant applicant. Nothing here is an endorsement by them.
- **No hosted CDP facilitator call yet.** The remote-facilitator rail is executed
  against a conformant facilitator stood up locally on a socket; calling Coinbase's
  hosted CDP facilitator needs credentials this environment does not have, and it is
  milestone 3, not done.
- **No CDP AgentKit wallets yet.** The resolver and poster sign with local devnet keys
  behind an adapter seam. Provisioning those identities as CDP wallets through AgentKit
  is milestone 2.
- **No LLM in the resolver.** The resolver is a deterministic evidence parser, chosen
  so a demo is reproducible in front of a reviewer. A model can be dropped in behind
  the same `decide(claim, evidence)` interface, but the property that matters, that the
  verdict is derived from evidence the resolver can be given or denied, does not depend
  on one.
- **The fee token is a mock.** `MockERC20` implements EIP-3009 the way USDC does, with
  a free `mint`. It is a devnet token, not USDC.
