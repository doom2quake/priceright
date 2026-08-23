"""The two participants: a task Poster and a ResolverAgent.

They are separate classes for one reason. The poster knows the answer it committed to;
the resolver must not. Keeping them apart is what makes the resolver's stake mean
something, and it is enforced by construction: `ResolverAgent` is handed a chain, a
policy and a task id, and the only way for it to reach the truth would be to read a
field that does not exist on `TaskView`.

The resolver's run is the x402 flow end to end:

    request the claim -> 402 Payment Required -> sign an EIP-3009 authorisation
    -> X-PAYMENT -> facilitator verify + settle -> claim transaction -> commit verdict

Each beat is published to an `on_event` callback as it happens, so the CLI and the UI
render the state at that moment rather than a snapshot taken after settlement.

agent-core supplies the guardrail and the run journal: the x402 payment is a limited
action, and every run is recorded with its guardrail decisions.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from agent_core import ActionLimiter, ActionPolicy, StateStore, signature_of

from .arena import ChainError, Settlement, TaskView, verdict_label
from .config import settings
from .policy import ABSTAIN, Decision, EvidencePolicy, policy_for
from .secp256k1 import address_of, to_checksum
from .x402 import ClaimGate, Facilitator, HttpFacilitator, LocalFacilitator, PaymentError, X402Client

_limiter = ActionLimiter(ActionPolicy.from_env("PRICERIGHT"))

EventSink = Optional[Callable[[str, dict], None]]


def make_facilitator(chain, cfg=settings) -> Facilitator:
    """Verify through a remote x402 facilitator when one is configured, else locally.

    Either way the arena is what submits the authorisation, because `claimTask`
    consumes it; a configured facilitator is an extra gate in front of that, not a
    replacement for it.
    """
    if cfg.use_x402_facilitator:
        return HttpFacilitator(cfg.x402_facilitator_url, chain, chain.token_domain())
    return LocalFacilitator(chain, chain.token_domain())


@dataclass
class PlayResult:
    status: str  # "committed" | "abstained" | "blocked" | "failed"
    run_id: str
    task_id: int = 0
    agent_id: int = 0
    verdict: int = ABSTAIN
    reasoning: str = ""
    reasoning_hash: str = ""
    payment_tx: str = ""
    payment_header: str = ""
    payment_response_header: str = ""
    reason: str = ""
    events: list[dict] = field(default_factory=list)


class Poster:
    """Opens tasks and reveals the truth at settlement. Holds the secret, not the agent."""

    def __init__(self, chain, cfg=settings) -> None:
        self.chain = chain
        self.cfg = cfg
        self.key = cfg.poster_private_key()
        self.address = to_checksum(address_of(self.key))
        self._secrets: dict[int, tuple[int, str]] = {}

    def post(self, claim: str, evidence: str, salt: str | None = None, **kwargs) -> TaskView:
        """Open a task whose committed truth is derived from the published evidence.

        The poster does not get to invent the answer: it runs the same evidence policy
        a diligent resolver would, and commits to that. If the evidence does not settle
        the claim, the task is not posted at all.
        """
        decision = EvidencePolicy().decide(claim, evidence)
        if not decision.committable:
            raise ValueError(f"refusing to post an unanswerable task: {decision.reasoning}")
        salt = salt or ("0x" + secrets.token_hex(32))
        task = self.chain.post_task(self.address, decision.verdict, salt=salt, **kwargs)
        self._secrets[task.task_id] = (decision.verdict, salt)
        return task

    def truth_of(self, task_id: int) -> int:
        """For the demo narrative only. The resolver is never given this."""
        return self._secrets[task_id][0]

    def settle(self, task_id: int) -> Settlement:
        truth, salt = self._secrets[task_id]
        return self.chain.settle(task_id, self.address, truth, salt)


class ResolverAgent:
    """A resolver: an ERC-8004 identity, a policy, and a wallet that can sign x402."""

    def __init__(self, chain, honest: bool = True, cfg=settings, facilitator: Facilitator | None = None,
                 key: int | None = None, policy=None) -> None:
        self.chain = chain
        self.cfg = cfg
        self.policy = policy or policy_for(honest)
        self.key = cfg.resolver_private_key() if key is None else key
        self.address = to_checksum(address_of(self.key))
        self.client = X402Client(self.key, chain.token_domain())
        self.gate = ClaimGate(chain, facilitator or make_facilitator(chain, cfg), getattr(chain, "network", "evm"))
        self.agent_id = chain.register_agent(self.address, "ipfs://priceright/resolver-card")

    def reputation(self) -> dict[str, Any]:
        count, avg = self.chain.reputation_summary(self.agent_id, tag1="priceright.settlement")
        return {
            "agent_id": self.agent_id,
            "feedback_count": count,
            "score": 100 if count == 0 else avg,
            "stake": self.chain.stake_of(self.agent_id),
            "slashed": self.chain.slashed_of(self.agent_id),
        }

    def play(self, task_id: int, claim: str, evidence: str, on_event: EventSink = None) -> PlayResult:
        """Buy the right to answer, answer, and commit. Streams each beat as it happens."""
        events: list[dict] = []

        def emit(name: str, **fields) -> None:
            events.append({"step": name, **fields})
            if on_event:
                on_event(name, fields)

        store = StateStore.create(self.cfg)
        run_id = store.start_run(trigger={"task": task_id, "claim": claim})

        allowed, reason = _limiter.check(run_id, "x402_claim")
        if not allowed:
            store.record_guardrail(run_id, "ACTION_LIMITER", "blocked", f"x402_claim: {reason}")
            store.set_status(run_id, "blocked")
            emit("blocked", reason=reason)
            return PlayResult(status="blocked", run_id=run_id, reason=reason, events=events)
        store.record_guardrail(run_id, "ACTION_LIMITER", "allowed", "x402_claim cleared")

        # 1. reason first. An agent that cannot answer does not pay to try.
        decision: Decision = self.policy.decide(claim, evidence)
        emit("decided", policy=self.policy.name, verdict=verdict_label(decision.verdict),
             committable=decision.committable, reasoning=decision.reasoning)
        if not decision.committable:
            store.set_data(run_id, "abstained", {"reasoning": decision.reasoning})
            store.set_status(run_id, "abstained")
            emit("abstained", reason=decision.reasoning)
            return PlayResult(status="abstained", run_id=run_id, task_id=task_id, agent_id=self.agent_id,
                              reasoning=decision.reasoning, reason="evidence does not settle the claim", events=events)

        # 2. the x402 handshake: ask, get 402, pay, retry with X-PAYMENT.
        challenge = self.gate.challenge(task_id, self.agent_id)
        emit("challenged", status=challenge.status, amount=challenge.requirements.max_amount_required,
             asset=challenge.requirements.asset, pay_to=challenge.requirements.pay_to,
             scheme=challenge.requirements.scheme, network=challenge.requirements.network,
             nonce=challenge.requirements.extra["nonce"])

        try:
            payload = self.client.pay(challenge.requirements)
            header = payload.header()
            emit("signed", payer=payload.authorization.from_address, signature=payload.signature,
                 header_bytes=len(header), valid_before=payload.authorization.valid_before)
            paid = self.gate.grant(task_id, self.agent_id, header)
        except (PaymentError, ChainError) as exc:
            store.set_status(run_id, "failed")
            emit("payment_failed", error=str(exc))
            return PlayResult(status="failed", run_id=run_id, task_id=task_id, agent_id=self.agent_id,
                              reason=str(exc), events=events)

        emit("paid", tx=paid.tx_hash, amount=paid.amount, payer=paid.payer,
             bonded=self.chain.task(task_id).slash_amount, stake=self.chain.stake_of(self.agent_id))
        store.set_data(run_id, "claim", {
            "fee": paid.amount, "x402_tx": paid.tx_hash,
            "x_payment_response": paid.payment_response_header,
        })

        # 3. commit the verdict and the hash of the reasoning that produced it.
        receipt = self.chain.commit_verdict(task_id, self.address, decision.verdict, decision.reasoning)
        rh = self.chain.task(task_id).reasoning_hash
        emit("committed", verdict=verdict_label(decision.verdict), reasoning_hash=rh, tx=receipt.tx_hash)
        store.set_data(run_id, "commit", {"verdict": verdict_label(decision.verdict), "reasoning_hash": rh})
        store.detect_recurrence(run_id, signature_of("verdict", task_id, verdict_label(decision.verdict)))
        store.set_status(run_id, "committed")

        return PlayResult(
            status="committed", run_id=run_id, task_id=task_id, agent_id=self.agent_id,
            verdict=decision.verdict, reasoning=decision.reasoning, reasoning_hash=rh,
            payment_tx=paid.tx_hash, payment_header=header,
            payment_response_header=paid.payment_response_header, events=events,
        )
