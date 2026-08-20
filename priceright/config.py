"""PriceRight configuration - extends agent-core's BaseSettings.

Two sponsor rails carry the whole design:

  * **x402** is how a resolver buys the right to answer. The claim endpoint answers
    HTTP 402 with `PaymentRequirements`; the resolver signs an EIP-3009
    `TransferWithAuthorization` (the `exact` scheme's on-chain settlement primitive)
    and re-presents it in an `X-PAYMENT` header. `AgentArena.claimTask` submits that
    authorisation, so the fee moves by signature and exactly once.
  * **ERC-8004** is the identity the resolver stakes. `IdentityRegistry` is an ERC-721
    whose tokenId is the agentId; `ReputationRegistry` records the settlement as
    feedback; `ValidationRegistry` holds an attestation request filed before the truth
    was revealed. `AgentStakeVault` is the economic extension ERC-8004 leaves open.

Backends. `PRICERIGHT_RPC_URL` + the three contract addresses select the JSON-RPC backend
in `rpc.py` and every call becomes a real transaction. With none of them set the agent
runs against `InMemoryChain`, which executes the same state machine in-process and
still verifies signatures for real. `use_chain` is what selects between them, and it
is consumed in exactly one place: `chain.make_chain`.

Testnet and local devnets only. There is no mainnet path.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_core import BaseSettings, env_bool, env_int, env_str


@dataclass(frozen=True)
class PriceRightSettings(BaseSettings):
    env_prefix: str = "PRICERIGHT"
    app_name: str = "priceright"

    # x402 payment rail
    x402_facilitator_url: str = field(default_factory=lambda: env_str("PRICERIGHT_X402_FACILITATOR_URL"))
    network: str = field(default_factory=lambda: env_str("PRICERIGHT_NETWORK", "in-memory"))

    # chain (arena + ERC-8004 registries + vault)
    rpc_url: str = field(default_factory=lambda: env_str("PRICERIGHT_RPC_URL"))
    arena_address: str = field(default_factory=lambda: env_str("PRICERIGHT_ARENA_ADDRESS"))
    token_address: str = field(default_factory=lambda: env_str("PRICERIGHT_TOKEN_ADDRESS"))
    identity_address: str = field(default_factory=lambda: env_str("PRICERIGHT_IDENTITY_ADDRESS"))
    vault_address: str = field(default_factory=lambda: env_str("PRICERIGHT_VAULT_ADDRESS"))
    reputation_address: str = field(default_factory=lambda: env_str("PRICERIGHT_REPUTATION_ADDRESS"))

    # keys. Devnet keys only: the resolver signs x402 authorisations with resolver_key
    # and the poster funds bounties with poster_key. Defaults are the well-known anvil
    # accounts #0 and #1, which exist on every local devnet and nowhere with value.
    resolver_key: str = field(
        default_factory=lambda: env_str(
            "PRICERIGHT_RESOLVER_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        )
    )
    resolver2_key: str = field(
        default_factory=lambda: env_str(
            "PRICERIGHT_RESOLVER2_KEY", "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
        )
    )
    poster_key: str = field(
        default_factory=lambda: env_str(
            "PRICERIGHT_POSTER_KEY", "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
        )
    )

    # economics (fee-token base units); defaults make the demo legible
    fee: int = field(default_factory=lambda: env_int("PRICERIGHT_FEE", 10))
    bounty: int = field(default_factory=lambda: env_int("PRICERIGHT_BOUNTY", 100))
    stake: int = field(default_factory=lambda: env_int("PRICERIGHT_STAKE", 50))

    # liveness windows (seconds): a resolver must commit, a poster must reveal
    commit_window: int = field(default_factory=lambda: env_int("PRICERIGHT_COMMIT_WINDOW", 3600))
    settle_window: int = field(default_factory=lambda: env_int("PRICERIGHT_SETTLE_WINDOW", 7200))

    offline: bool = field(default_factory=lambda: env_bool("PRICERIGHT_OFFLINE", False))

    # agent-core journals runs to Firestore when a project is configured. This app
    # defaults to the in-memory journal instead, so the documented demo commands never
    # reach for a cloud project a reviewer does not have. Set PRICERIGHT_IN_MEMORY_STATE=0
    # to opt back in.
    use_in_memory_state: bool = field(default_factory=lambda: env_bool("PRICERIGHT_IN_MEMORY_STATE", True))

    @property
    def use_x402_facilitator(self) -> bool:
        """True when a remote x402 facilitator should verify/settle instead of us."""
        return bool(self.x402_facilitator_url) and not self.offline

    @property
    def use_chain(self) -> bool:
        """True when a real node and deployed contracts are configured."""
        return bool(self.rpc_url and self.arena_address and self.token_address) and not self.offline

    def resolver_private_key(self) -> int:
        return int(self.resolver_key, 16)

    def resolver2_private_key(self) -> int:
        return int(self.resolver2_key, 16)

    def poster_private_key(self) -> int:
        return int(self.poster_key, 16)


settings = PriceRightSettings()
