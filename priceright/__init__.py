"""PriceRight - a testnet agent economy where a wrong verdict costs real collateral.

A resolver agent buys the right to answer a task with an x402 `exact` payment (a signed
EIP-3009 authorisation), bonds collateral against its ERC-8004 identity, and commits a
verdict plus the hash of the reasoning that produced it. Settlement compares the
committed verdict to the revealed truth and is a pure function of the two: correct pays,
wrong moves the collateral to the poster and writes a zero into the ERC-8004 reputation
registry.

The Python layer is the agent and both chain backends. `InMemoryChain` executes the same
state machine in-process (signatures included) so the demo is keyless; `JsonRpcChain`
sends real transactions when an RPC and deployed addresses are configured. Testnet and
local devnets only.
"""

from .agent import Poster, ResolverAgent
from .arena import InMemoryChain, Settlement, TaskView

__all__ = ["InMemoryChain", "TaskView", "Settlement", "ResolverAgent", "Poster"]
__version__ = "0.1.0"
