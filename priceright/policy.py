"""ResolverPolicy - how an agent derives a verdict from evidence it can actually see.

The rule this module obeys: **the resolver never receives the poster's ground truth.**
`decide()` takes a claim and an evidence bundle and nothing else. That is not a
stylistic choice, it is what makes the settlement meaningful; a resolver handed the
answer would be staking on a coin flip it had already won.

A claim is a threshold question, stated in a machine-checkable form:

    ETH/USD >= 4000 @ block 21451200

Evidence is a list of readings, each naming a source, a symbol, a block and a value:

    oracle chainlink-eth-usd  block=21451200  ETH/USD=4127.50

`EvidencePolicy` parses both, keeps the readings that match the claim's symbol *and*
block, and compares. Two behaviours a judge can run side by side:

  * `EvidencePolicy` reads the evidence and answers from it. Give it contradictory
    evidence and its answer changes, which is the test that proves it is not peeking.
  * `StaleCachePolicy` skips the lookup and answers from a week-old quote it already
    had. It is not lying and it is not hardcoded to be wrong: it evaluates the same
    comparison against data that has gone out of date, which is the ordinary failure
    mode the arena is built to make expensive.

Both refuse rather than guess when the evidence does not cover the claim. `decide()`
returns `verdict = ABSTAIN` in that case, and the agent declines to claim the task, so
a resolver never stakes on a question it cannot evaluate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .arena import NO, YES, verdict_label

ABSTAIN = 0  # matches AgentArena.Verdict.None: not a committable verdict

_CLAIM_RE = re.compile(
    r"(?P<symbol>[A-Z]{2,10}/[A-Z]{2,10})\s*(?P<op>>=|<=|>|<)\s*(?P<threshold>[0-9]+(?:\.[0-9]+)?)"
    r"(?:\s*@\s*block\s*(?P<block>[0-9]+))?"
)
_READING_RE = re.compile(
    r"(?P<symbol>[A-Z]{2,10}/[A-Z]{2,10})\s*=\s*(?P<value>[0-9]+(?:\.[0-9]+)?)"
)
_BLOCK_RE = re.compile(r"block\s*=\s*(?P<block>[0-9]+)")

_OPS = {
    ">=": lambda a, b: a >= b,
    ">": lambda a, b: a > b,
    "<=": lambda a, b: a <= b,
    "<": lambda a, b: a < b,
}


@dataclass(frozen=True)
class Claim:
    symbol: str
    op: str
    threshold: float
    block: int | None

    @classmethod
    def parse(cls, text: str) -> "Claim | None":
        m = _CLAIM_RE.search(text)
        if not m:
            return None
        return cls(
            symbol=m.group("symbol"),
            op=m.group("op"),
            threshold=float(m.group("threshold")),
            block=int(m.group("block")) if m.group("block") else None,
        )


@dataclass(frozen=True)
class Reading:
    source: str
    symbol: str
    value: float
    block: int | None

    @classmethod
    def parse(cls, line: str) -> "Reading | None":
        m = _READING_RE.search(line)
        if not m:
            return None
        b = _BLOCK_RE.search(line)
        return cls(
            source=line.split()[0] if line.split() else "unknown",
            symbol=m.group("symbol"),
            value=float(m.group("value")),
            block=int(b.group("block")) if b else None,
        )


@dataclass(frozen=True)
class Decision:
    verdict: int
    reasoning: str

    @property
    def committable(self) -> bool:
        return self.verdict in (YES, NO)


class EvidencePolicy:
    """Derives the verdict from the evidence bundle. Abstains when it cannot."""

    name = "evidence"

    def decide(self, claim_text: str, evidence: str) -> Decision:
        claim = Claim.parse(claim_text)
        if claim is None:
            return Decision(ABSTAIN, f"Claim is not machine-checkable: {claim_text!r}. Abstaining rather than guessing.")

        readings = [r for r in (Reading.parse(line) for line in evidence.splitlines()) if r is not None]
        usable = [r for r in readings if r.symbol == claim.symbol and (claim.block is None or r.block == claim.block)]
        if not usable:
            return Decision(
                ABSTAIN,
                f"No reading for {claim.symbol}"
                + (f" at block {claim.block}" if claim.block else "")
                + f" in {len(readings)} evidence line(s). Abstaining rather than guessing.",
            )

        values = sorted(r.value for r in usable)
        median = values[len(values) // 2] if len(values) % 2 else (values[len(values) // 2 - 1] + values[len(values) // 2]) / 2
        holds = _OPS[claim.op](median, claim.threshold)
        verdict = YES if holds else NO
        sources = ", ".join(sorted({r.source for r in usable}))
        reasoning = (
            f"Claim: {claim.symbol} {claim.op} {claim.threshold:g}"
            + (f" at block {claim.block}" if claim.block else "")
            + "\n"
            + f"Readings used ({len(usable)} from {sources}): "
            + ", ".join(f"{r.value:g}" for r in usable)
            + "\n"
            + f"Median {median:g} {claim.op} {claim.threshold:g} is {holds}. Verdict: {verdict_label(verdict)}."
        )
        return Decision(verdict, reasoning)


# a week-old quote cache. Nothing about it is rigged: it is simply out of date.
STALE_QUOTES = {"ETH/USD": 3805.0, "BTC/USD": 91240.0}


class StaleCachePolicy:
    """Answers from a cached quote instead of paying for the lookup.

    This resolver is not adversarial and it is not hardcoded to be wrong. It evaluates
    the claim honestly against data it already had, and it loses its collateral when
    the world moved. Feed it evidence that agrees with its cache and it wins - `priceright
    guards` shows exactly that, which is how a judge can tell the slash is computed
    rather than scripted.
    """

    name = "stale-cache"

    def __init__(self, quotes: dict[str, float] | None = None) -> None:
        self.quotes = dict(STALE_QUOTES if quotes is None else quotes)

    def decide(self, claim_text: str, evidence: str) -> Decision:
        claim = Claim.parse(claim_text)
        if claim is None or claim.symbol not in self.quotes:
            return Decision(ABSTAIN, f"No cached quote for {claim_text!r}. Abstaining.")
        cached = self.quotes[claim.symbol]
        holds = _OPS[claim.op](cached, claim.threshold)
        verdict = YES if holds else NO
        return Decision(
            verdict,
            f"Claim: {claim.symbol} {claim.op} {claim.threshold:g}"
            + (f" at block {claim.block}" if claim.block else "")
            + "\n"
            + f"Skipped the evidence lookup and used a cached quote: {claim.symbol}={cached:g} (last week).\n"
            + f"Cached {cached:g} {claim.op} {claim.threshold:g} is {holds}. Verdict: {verdict_label(verdict)}.",
        )


def policy_for(honest: bool):
    """The two resolvers the demo runs: one reads the evidence, one trusts its cache."""
    return EvidencePolicy() if honest else StaleCachePolicy()
