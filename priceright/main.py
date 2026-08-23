"""PriceRight CLI - a testnet agent economy where a wrong verdict costs real collateral.

    priceright demo             # the whole story: paid claim, correct run, slashed run
    priceright play --wrong     # one resolver run
    priceright guards           # the refusals: replayed payment, unanswerable claim
    priceright --help

Every line printed below is the state at the moment it is printed: the agent publishes
each beat through a callback and this module renders it as it arrives, so a run that
ends in a slash still shows the collateral that was bonded before it was taken.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from .agent import Poster, ResolverAgent
from .arena import ChainError, verdict_label
from .config import settings
from .policy import EvidencePolicy
from .rpc import make_chain
from .x402 import PaymentError, PaymentPayload

CLAIM = "Settle: ETH/USD >= 4000 @ block 21451200"
EVIDENCE = "\n".join(
    [
        "chainlink-eth-usd  block=21451200  ETH/USD=4127.50",
        "pyth-eth-usd       block=21451200  ETH/USD=4126.10",
        "uniswap-twap       block=21451200  ETH/USD=4131.22",
    ]
)
# the same claim with readings that point the other way, used by `guards`
CONTRARY_EVIDENCE = "\n".join(
    [
        "chainlink-eth-usd  block=21451200  ETH/USD=3872.40",
        "pyth-eth-usd       block=21451200  ETH/USD=3869.95",
    ]
)
UNANSWERABLE_EVIDENCE = "chainlink-btc-usd  block=21451200  BTC/USD=98120.00"


def _pace() -> None:
    """Optional pause between beats for a legible screen recording. Off by default."""
    try:
        d = float(os.getenv("PRICERIGHT_PACE", "0"))
    except ValueError:
        d = 0.0
    if d > 0:
        time.sleep(d)


_C = {"g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "b": "\033[36m",
      "m": "\033[35m", "d": "\033[2m", "bold": "\033[1m", "x": "\033[0m"}


def _p(s: str = "") -> None:
    print(s)


def _kv(k: str, v: str, color: str = "b") -> None:
    print(f"  {_C['d']}{k:<15}{_C['x']} {_C[color]}{v}{_C['x']}")


def _rule(title: str = "") -> None:
    print(f"{_C['d']}{'-' * 68}{_C['x']}" + (f" {_C['bold']}{title}{_C['x']}" if title else ""))


def _short(h: str, keep: int = 18) -> str:
    return h if len(h) <= keep + 2 else f"{h[:keep]}...{h[-6:]}"


def _new_chain():
    chain = make_chain(settings)
    # a devnet needs balances before anything can be paid; a configured chain is funded
    # by its deployer, so only the in-memory mirror mints here.
    if hasattr(chain, "mint") and getattr(chain, "network", "") == "in-memory":
        from .secp256k1 import address_of

        for key in (settings.poster_private_key(), settings.resolver_private_key(),
                    settings.resolver2_private_key()):
            chain.mint(address_of(key), 10_000)
    return chain


def _render(step: str, f: dict) -> None:
    """One beat of the agent's run, printed as it happens."""
    if step == "decided":
        _rule(f"2. resolver reasons ({f['policy']} policy) before it pays")
        for line in f["reasoning"].splitlines():
            print(f"  {_C['d']}{line}{_C['x']}")
        _kv("verdict", f["verdict"], "g" if f["committable"] else "y")
    elif step == "abstained":
        _kv("outcome", "ABSTAINED: refused to stake on an unanswerable claim", "y")
    elif step == "challenged":
        _p()
        _rule("3. the claim endpoint answers HTTP 402 Payment Required")
        _kv("status", f"{f['status']} Payment Required", "m")
        _kv("scheme", f"{f['scheme']} on {f['network']}", "m")
        _kv("amount", f"{f['amount']} tUSD of {_short(f['asset'], 12)}", "m")
        _kv("pay to", f["pay_to"], "m")
        _kv("nonce", _short(f["nonce"], 20), "d")
    elif step == "signed":
        _kv("signed", f"EIP-3009 authorisation by {_short(f['payer'], 12)}", "m")
        _kv("signature", _short(f["signature"], 20), "d")
        _kv("X-PAYMENT", f"{f['header_bytes']} base64 bytes", "d")
    elif step == "paid":
        _kv("settled tx", _short(f["tx"], 20), "m")
        _p()
        _rule("4. collateral bonded against the ERC-8004 identity")
        _kv("bonded", f"{f['bonded']} tUSD", "b")
        _kv("stake now", f"{f['stake']} tUSD", "b")
    elif step == "committed":
        _p()
        _rule("5. verdict + reasoning hash committed on-chain")
        _kv("verdict", f["verdict"], "b")
        _kv("reasoning", _short(f["reasoning_hash"], 20))
        _kv("tx", _short(f["tx"], 20), "d")
    elif step == "payment_failed":
        _kv("payment", f"REJECTED: {f['error']}", "r")
    elif step == "blocked":
        _kv("guardrail", f"blocked: {f['reason']}", "y")


def _play_task(chain, poster, agent, evidence: str) -> None:
    """Post a task, let `agent` buy its way in and answer, then settle. Streams live."""
    task = poster.post(CLAIM, evidence)
    _rule("1. task posted (truth derived from the evidence, then hash-committed)")
    _kv("task", f"#{task.task_id}: {CLAIM}")
    _kv("truth commit", _short(task.truth_commit, 22))
    _kv("bounty / fee", f"{task.bounty} / {task.fee} tUSD")
    _kv("collateral", f"{task.slash_amount} tUSD")
    _kv("resolver", f"agent #{agent.agent_id} at {_short(agent.address, 12)}", "d")
    _pace()

    res = agent.play(task.task_id, CLAIM, evidence, on_event=_render)
    _pace()
    if res.status != "committed":
        _p()
        _kv("run ended", res.status, "y")
        return

    s = poster.settle(task.task_id)
    _p()
    _rule("6. settlement: committed verdict vs revealed truth, no discretion")
    _kv("revealed truth", verdict_label(s.truth))
    _kv("committed", verdict_label(s.committed))
    if s.correct:
        _kv("result", "CORRECT", "g")
        _kv("credited", f"+{s.reward_paid} tUSD (fee back + bounty)", "g")
        _kv("collateral", f"{s.collateral_returned} tUSD released back", "g")
        _kv("bonded", f"{s.stake_before} -> {s.stake_after} tUSD", "g")
        _kv("reputation", f"{s.score_before}% -> {s.score_after}%", "g")
    else:
        _kv("result", "WRONG: collateral SLASHED", "r")
        _kv("collateral", f"{s.slashed} tUSD seized and moved to the poster", "r")
        _kv("bonded", f"{s.stake_before} -> {s.stake_after} tUSD", "r")
        _kv("reputation", f"{s.score_before}% -> {s.score_after}%", "r")


def _ledger(chain, poster, agents) -> None:
    """What each party can withdraw, and the ERC-8004 record each agent now carries."""
    _rule("ledger")
    for agent in agents:
        rep = agent.reputation()
        colour = "g" if rep["slashed"] == 0 else "r"
        _kv(
            f"agent #{rep['agent_id']}",
            f"score {rep['score']}% over {rep['feedback_count']} settlement(s)  ·  "
            f"slashed {rep['slashed']} tUSD  ·  withdrawable {chain.credits_of(agent.address)} tUSD",
            colour,
        )
    _kv("poster", f"withdrawable {chain.credits_of(poster.address)} tUSD", "b")

    held = chain.balance_of(chain.arena_address)
    if hasattr(chain, "VAULT"):
        held += chain.balance_of(chain.VAULT)
    elif getattr(chain, "vault_address", ""):
        held += chain.balance_of(chain.vault_address)
    owed = chain.credits_of(poster.address) + sum(chain.credits_of(a.address) for a in agents)
    locked = sum(
        t.bounty + (t.fee + t.slash_amount if t.status in ("Claimed", "Committed") else 0)
        for t in getattr(chain, "tasks", {}).values()
        if t.status in ("Open", "Claimed", "Committed")
    )
    balanced = held == owed + locked
    _kv(
        "escrow",
        f"{held} tUSD held = {owed} owed out + {locked} still locked in unsettled tasks"
        if balanced else f"{held} tUSD held, {owed} owed, {locked} locked (UNBALANCED)",
        "d" if balanced else "r",
    )


def cmd_play(honest: bool) -> None:
    _p(f"{_C['bold']}PriceRight{_C['x']}: one resolver run\n")
    chain = _new_chain()
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=honest)
    _play_task(chain, poster, agent, EVIDENCE)
    _p()
    _ledger(chain, poster, [agent])


def cmd_demo() -> None:
    _p(f"{_C['bold']}PriceRight{_C['x']}: a testnet agent economy where a wrong verdict costs collateral")
    _p(f"{_C['d']}x402 exact-scheme fee  ·  ERC-8004 identity + feedback  ·  deterministic slashing{_C['x']}")

    chain = _new_chain()
    poster = Poster(chain)
    reader = ResolverAgent(chain, honest=True, key=settings.resolver_private_key())
    cacher = ResolverAgent(chain, honest=False, key=settings.resolver2_private_key())
    _p(f"{_C['d']}backend: {getattr(chain, 'network', 'evm')}  ·  two ERC-8004 identities registered:"
       f" #{reader.agent_id} (reads evidence) and #{cacher.agent_id} (trusts its cache){_C['x']}\n")

    _p(f"{_C['bold']}== AGENT #{reader.agent_id}: reads the evidence =={_C['x']}\n")
    _play_task(chain, poster, reader, EVIDENCE)
    _pace()

    _p()
    _p(f"{_C['bold']}== AGENT #{cacher.agent_id}: same task, answers from a week-old quote =={_C['x']}\n")
    _play_task(chain, poster, cacher, EVIDENCE)
    _pace()

    _p()
    _ledger(chain, poster, [reader, cacher])
    _p()
    _p(f"{_C['g']}One arena, one rule. The verdict that matched the revealed truth was paid; the one"
       f" that did not lost its collateral to the poster. Nobody decided that.{_C['x']}")


def cmd_guards() -> None:
    """The refusals. A demo that only shows the happy path proves nothing."""
    _p(f"{_C['bold']}PriceRight{_C['x']}: what the arena refuses\n")

    chain = _new_chain()
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)

    _rule("A. an x402 authorisation cannot be replayed onto a second task")
    t1 = poster.post(CLAIM, EVIDENCE)
    t2 = poster.post(CLAIM, EVIDENCE)
    challenge = agent.gate.challenge(t1.task_id, agent.agent_id)
    payload = agent.client.pay(challenge.requirements)
    agent.gate.grant(t1.task_id, agent.agent_id, payload.header())
    _kv("task 1", f"claimed with a signed authorisation for task #{t1.task_id}", "g")
    try:
        agent.gate.grant(t2.task_id, agent.agent_id, payload.header())
        _kv("task 2", "ACCEPTED (this would be a bug)", "r")
    except (PaymentError, ChainError) as exc:
        _kv("task 2", f"REFUSED: {exc}", "g")

    _p()
    _rule("B. a tampered payment amount does not survive verification")
    tampered = PaymentPayload.from_header(payload.header())
    bumped = PaymentPayload(
        scheme=tampered.scheme, network=tampered.network, signature=tampered.signature,
        authorization=type(tampered.authorization)(
            from_address=tampered.authorization.from_address, to=tampered.authorization.to,
            value=tampered.authorization.value * 10, valid_after=tampered.authorization.valid_after,
            valid_before=tampered.authorization.valid_before, nonce=tampered.authorization.nonce,
        ),
    )
    check = agent.gate.facilitator.verify(bumped, challenge.requirements)
    _kv("verify", f"isValid={check.is_valid} reason={check.invalid_reason}", "g" if not check.is_valid else "r")

    _p()
    _rule("C. the resolver abstains rather than stake on evidence it cannot use")
    t3 = poster.post(CLAIM, EVIDENCE)
    res = agent.play(t3.task_id, CLAIM, UNANSWERABLE_EVIDENCE, on_event=None)
    _kv("status", res.status, "g" if res.status == "abstained" else "r")
    _kv("why", res.reasoning.splitlines()[0], "d")
    _kv("fee paid", f"{chain.task(t3.task_id).fee if res.status == 'committed' else 0} tUSD", "g")

    _p()
    _rule("D. the evidence decides the verdict, not the agent's prior")
    d1 = EvidencePolicy().decide(CLAIM, EVIDENCE)
    d2 = EvidencePolicy().decide(CLAIM, CONTRARY_EVIDENCE)
    _kv("supportive", verdict_label(d1.verdict), "g")
    _kv("contrary", verdict_label(d2.verdict), "g")
    _p()
    _p(f"{_C['d']}Flip the readings and the verdict flips with them. That is the difference between"
       f" a resolver and a lookup of the answer.{_C['x']}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="priceright", description="Testnet agent economy: x402 fees, ERC-8004 slashing.")
    sub = p.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("play", help="play one task as a resolver (402 -> pay -> commit -> settle)")
    pl.add_argument("--wrong", action="store_true", help="use the prior-based resolver that gets slashed")
    sub.add_parser("demo", help="the whole story: a paid correct run and a slashed run")
    sub.add_parser("guards", help="the refusals: replay, tampering, and abstention")
    return p


def cli(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "play":
        cmd_play(honest=not args.wrong)
    elif args.cmd == "demo":
        cmd_demo()
    elif args.cmd == "guards":
        cmd_guards()
    return 0


if __name__ == "__main__":
    sys.exit(cli())
