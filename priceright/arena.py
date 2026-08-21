"""InMemoryChain - an executable mirror of the Solidity contracts.

This is the keyless default backend. It is not a fixture and it does not paint
results: it re-implements the state machine of `AgentArena.sol`, `AgentStakeVault.sol`
and the three ERC-8004 registries, including the parts that can reject you.

  * The x402 fee is settled by verifying a real EIP-3009 signature (`secp256k1.recover`)
    against a real EIP-712 digest, marking the nonce used, and moving token balances.
    A forged or replayed authorisation fails here exactly as it fails in the token.
  * Collateral is held per task and every terminal path releases it or slashes it, so
    the balance invariant a judge would check on-chain also holds here.
  * The commit and reveal deadlines exist, and the two timeout paths are callable.

`priceright/rpc.py` implements the same interface against a JSON-RPC node, so the
agent code is identical whether it is talking to this or to a devnet.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .config import PriceRightSettings, settings
from .hashing import keccak256, keccak_hex, reasoning_hash, truth_commitment
from .secp256k1 import recover, to_checksum
from .x402 import EIP712Domain, PaymentError, PaymentPayload

# verdict encoding, matching AgentArena.Verdict
NONE, YES, NO = 0, 1, 2
_LABEL = {NONE: "None", YES: "Yes", NO: "No"}

# ERC-8004 feedback tags, matching AgentArena's bytes32 constants
TAG_SETTLEMENT = "priceright.settlement"
TAG_CORRECT = "correct"
TAG_WRONG = "wrong"
TAG_COMMIT_TIMEOUT = "commit-timeout"
TAG_REVEAL_TIMEOUT = "reveal-timeout"


def _word(value: int | str) -> bytes:
    """One ABI word: ints big-endian, addresses/bytes32 left-padded. Mirrors abi.encode."""
    if isinstance(value, int):
        return value.to_bytes(32, "big")
    raw = bytes.fromhex(value.removeprefix("0x"))
    if len(raw) > 32:
        raise ValueError("value wider than one word")
    return raw.rjust(32, b"\x00")


def verdict_label(v: int) -> str:
    return _LABEL.get(v, "?")


def settlement_rule(committed: int, truth: int) -> bool:
    """The whole adjudication: a pure function of two integers, nothing else."""
    return committed == truth


class ChainError(Exception):
    """A call the contracts would have reverted."""


@dataclass
class Receipt:
    tx_hash: str
    method: str
    events: list[dict] = field(default_factory=list)
    simulated: bool = True  # True on the in-memory mirror, False on a real node

    @property
    def where(self) -> str:
        return "in-memory mirror" if self.simulated else "chain"


@dataclass
class TaskView:
    """Everything about a task that is public on-chain. The truth is not here."""

    task_id: int
    poster: str
    bounty: int
    fee: int
    slash_amount: int
    truth_commit: str
    status: str = "Open"
    agent_id: int = 0
    resolver: str = ""
    committed: int = NONE
    reasoning_hash: str = ""
    revealed_truth: int = NONE
    correct: Optional[bool] = None
    commit_deadline: int = 0
    settle_deadline: int = 0


@dataclass
class Settlement:
    task_id: int
    agent_id: int
    committed: int
    truth: int
    correct: bool
    slashed: int
    reward_paid: int
    collateral_returned: int
    stake_before: int
    stake_after: int
    score_before: int
    score_after: int
    tx_hash: str


@dataclass
class _Feedback:
    client: str
    score: int
    tag1: str
    tag2: str


class InMemoryChain:
    """A single-process EVM stand-in holding the token, registries, vault and arena."""

    # deterministic stand-in addresses, in deployment order like a local devnet
    TOKEN = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    IDENTITY = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
    REPUTATION = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
    VALIDATION = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
    VAULT = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
    ARENA = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"

    token_name = "Test USD"
    token_version = "2"
    chain_id = 31337
    network = "in-memory"

    def __init__(self, cfg: PriceRightSettings | None = None, *, now: int | None = None) -> None:
        self.cfg = cfg or settings
        # wall-clock, because x402 authorisations carry real validAfter/validBefore
        # windows and a mirror running in the past or future would reject them.
        self.now = int(time.time()) if now is None else now
        self.commit_window = self.cfg.commit_window
        self.settle_window = self.cfg.settle_window

        self.balances: dict[str, int] = {}
        self.authorizations: dict[tuple[str, str], bool] = {}
        self.agents: dict[int, str] = {}          # agentId => controller
        self.agent_uris: dict[int, str] = {}
        self.feedback: dict[int, list[_Feedback]] = {}
        self.validations: dict[str, dict] = {}
        self.bonds: dict[str, dict] = {}
        self.credits: dict[str, int] = {}
        self.tasks: dict[int, TaskView] = {}
        self._next_task = 1
        self._next_agent = 1
        self._tx = 0
        self.events: list[dict] = []

    # --- identity to the x402 layer -----------------------------------------
    @property
    def arena_address(self) -> str:
        return self.ARENA

    @property
    def token_address(self) -> str:
        return self.TOKEN

    def token_domain(self) -> EIP712Domain:
        return EIP712Domain(self.token_name, self.token_version, self.chain_id, self.TOKEN)

    # --- token ---------------------------------------------------------------
    def mint(self, to: str, amount: int) -> None:
        to = to_checksum(to)
        self.balances[to] = self.balances.get(to, 0) + amount

    def balance_of(self, who: str) -> int:
        return self.balances.get(to_checksum(who), 0)

    def authorization_used(self, who: str, nonce: str) -> bool:
        return self.authorizations.get((to_checksum(who), nonce.lower()), False)

    def _transfer(self, frm: str, to: str, amount: int) -> None:
        frm, to = to_checksum(frm), to_checksum(to)
        if self.balances.get(frm, 0) < amount:
            raise ChainError(f"insufficient balance: {frm}")
        self.balances[frm] -= amount
        self.balances[to] = self.balances.get(to, 0) + amount

    def _transfer_with_authorization(self, payload: PaymentPayload, expected_to: str, expected_value: int) -> None:
        """EIP-3009, verified the way the token verifies it."""
        auth = payload.authorization
        if self.now <= auth.valid_after:
            raise ChainError("AuthorizationNotYetValid")
        if self.now >= auth.valid_before:
            raise ChainError("AuthorizationExpired")
        key = (to_checksum(auth.from_address), auth.nonce.lower())
        if self.authorizations.get(key):
            raise ChainError("AuthorizationAlreadyUsed")
        try:
            v, r, s = payload.vrs()
        except PaymentError as exc:
            raise ChainError(f"InvalidSignature: {exc}") from exc
        signer = recover(auth.digest(self.token_domain()), v, r, s)
        if signer is None or to_checksum(signer) != to_checksum(auth.from_address):
            raise ChainError("InvalidSignature")
        if to_checksum(auth.to) != to_checksum(expected_to) or auth.value != expected_value:
            raise ChainError("AuthorizationTermsMismatch")
        self.authorizations[key] = True
        self._transfer(auth.from_address, auth.to, auth.value)

    # --- ERC-8004 identity ---------------------------------------------------
    def register_agent(self, controller: str, metadata_uri: str) -> int:
        agent_id = self._next_agent
        self._next_agent += 1
        self.agents[agent_id] = to_checksum(controller)
        self.agent_uris[agent_id] = metadata_uri
        self._emit("Registered", agent_id=agent_id, tokenURI=metadata_uri, owner=to_checksum(controller))
        return agent_id

    def owner_of(self, agent_id: int) -> str:
        if agent_id not in self.agents:
            raise ChainError("UnknownAgent")
        return self.agents[agent_id]

    def transfer_agent(self, agent_id: int, frm: str, to: str) -> None:
        if to_checksum(self.owner_of(agent_id)) != to_checksum(frm):
            raise ChainError("WrongOwner")
        self.agents[agent_id] = to_checksum(to)
        self._emit("Transfer", agent_id=agent_id, frm=to_checksum(frm), to=to_checksum(to))

    # --- ERC-8004 reputation -------------------------------------------------
    def give_feedback(self, client: str, agent_id: int, score: int, tag1: str, tag2: str) -> None:
        if agent_id not in self.agents:
            raise ChainError("UnknownAgent")
        if not 0 <= score <= 100:
            raise ChainError("ScoreOutOfRange")
        self.feedback.setdefault(agent_id, []).append(_Feedback(to_checksum(client), score, tag1, tag2))
        self._emit("NewFeedback", agent_id=agent_id, client=to_checksum(client), score=score, tag1=tag1, tag2=tag2)

    def reputation_summary(self, agent_id: int, clients: list[str] | None = None, tag1: str = "") -> tuple[int, int]:
        items = [
            f for f in self.feedback.get(agent_id, [])
            if (not clients or to_checksum(f.client) in {to_checksum(c) for c in clients})
            and (not tag1 or f.tag1 == tag1)
        ]
        if not items:
            return 0, 0
        return len(items), sum(f.score for f in items) // len(items)

    # --- collateral vault ----------------------------------------------------
    def stake_of(self, agent_id: int) -> int:
        return sum(b["amount"] for b in self.bonds.values() if b["agent_id"] == agent_id and not b["closed"])

    def slashed_of(self, agent_id: int) -> int:
        return sum(b["amount"] for b in self.bonds.values() if b["agent_id"] == agent_id and b.get("slashed"))

    def _bond(self, key: str, agent_id: int, depositor: str, amount: int) -> None:
        if key in self.bonds:
            raise ChainError("DuplicateBond")
        self.bonds[key] = {"agent_id": agent_id, "depositor": to_checksum(depositor), "amount": amount,
                           "closed": False, "slashed": False}
        if amount:
            self._transfer(depositor, self.VAULT, amount)
        self._emit("Bonded", bond_key=key, agent_id=agent_id, amount=amount)

    def _close_bond(self, key: str) -> dict:
        b = self.bonds.get(key)
        if b is None:
            raise ChainError("NoSuchBond")
        if b["closed"]:
            raise ChainError("BondClosed")
        b["closed"] = True
        return b

    def _release(self, key: str) -> int:
        b = self._close_bond(key)
        if b["amount"]:
            self._transfer(self.VAULT, self.ARENA, b["amount"])
        self._emit("Released", bond_key=key, agent_id=b["agent_id"], amount=b["amount"])
        return b["amount"]

    def _slash(self, key: str) -> int:
        b = self._close_bond(key)
        b["slashed"] = True
        if b["amount"]:
            self._transfer(self.VAULT, self.ARENA, b["amount"])
        self._emit("Slashed", bond_key=key, agent_id=b["agent_id"], amount=b["amount"])
        return b["amount"]

    # --- arena ---------------------------------------------------------------
    def claim_nonce(self, task_id: int, agent_id: int) -> str:
        """keccak256(abi.encode(CLAIM_SCOPE, arena, chainId, taskId, agentId)).

        Byte-identical to `AgentArena.claimNonce`, which is why a nonce computed here
        is accepted there. `tests/test_x402.py` pins the two against each other.
        """
        return keccak_hex(
            keccak256(b"x402.priceright.claim.v1")
            + _word(self.ARENA)
            + _word(self.chain_id)
            + _word(task_id)
            + _word(agent_id)
        )

    def bond_key(self, task_id: int) -> str:
        """keccak256(abi.encode(arena, taskId)) - the vault key for this task."""
        return keccak_hex(_word(self.ARENA) + _word(task_id))

    def post_task(self, poster: str, truth: int, *, bounty: int | None = None, fee: int | None = None,
                  slash_amount: int | None = None, salt: str | None = None) -> TaskView:
        """Open a task. Only the commitment is stored; the truth and salt stay with the
        poster, exactly as on-chain. Nothing in this object can reveal the answer."""
        if truth not in (YES, NO):
            raise ChainError("truth must be YES(1) or NO(2)")
        task_id = self._next_task
        self._next_task += 1
        salt = salt or ("0x" + secrets.token_hex(32))
        t = TaskView(
            task_id=task_id,
            poster=to_checksum(poster),
            bounty=self.cfg.bounty if bounty is None else bounty,
            fee=self.cfg.fee if fee is None else fee,
            slash_amount=self.cfg.stake if slash_amount is None else slash_amount,
            truth_commit=truth_commitment(truth, salt),
        )
        if t.bounty:
            self._transfer(poster, self.ARENA, t.bounty)
        self.tasks[task_id] = t
        self._emit("TaskPosted", task_id=task_id, poster=t.poster, bounty=t.bounty, fee=t.fee, slash=t.slash_amount)
        return t

    def task(self, task_id: int) -> TaskView:
        """The public view of a task. Deliberately has no `truth` field."""
        if task_id not in self.tasks:
            raise ChainError("UnknownTask")
        return self.tasks[task_id]

    def claim_task(self, task_id: int, agent_id: int, payment: PaymentPayload) -> Receipt:
        """x402-settled claim. Called by the facilitator once verification passed."""
        t = self.task(task_id)
        if t.status != "Open":
            raise ChainError("NotOpen")
        payer = to_checksum(payment.authorization.from_address)
        if to_checksum(self.owner_of(agent_id)) != payer:
            raise ChainError("NotResolver")
        if payment.authorization.value != t.fee:
            raise ChainError("FeeAmountMismatch")
        if payment.authorization.nonce.lower() != self.claim_nonce(task_id, agent_id).lower():
            raise ChainError("NonceNotBoundToTask")
        if t.fee:
            self._transfer_with_authorization(payment, self.ARENA, t.fee)
            self._emit("X402PaymentSettled", task_id=task_id, payer=payer, amount=t.fee,
                       nonce=payment.authorization.nonce)
        t.status = "Claimed"
        t.agent_id = agent_id
        t.resolver = payer
        t.commit_deadline = self.now + self.commit_window
        self._bond(self.bond_key(task_id), agent_id, payer, t.slash_amount)
        self._emit("TaskClaimed", task_id=task_id, agent_id=agent_id, resolver=payer, fee=t.fee,
                   bonded=t.slash_amount, commit_deadline=t.commit_deadline)
        return self._receipt("claimTask")

    def commit_verdict(self, task_id: int, caller: str, verdict: int, reasoning: str) -> Receipt:
        t = self.task(task_id)
        if t.status != "Claimed":
            raise ChainError("NotClaimed")
        if to_checksum(caller) != to_checksum(t.resolver):
            raise ChainError("NotResolver")
        if self.now > t.commit_deadline:
            raise ChainError("DeadlinePassed")
        if verdict not in (YES, NO):
            raise ChainError("BadVerdict")
        rh = reasoning_hash(reasoning)
        t.committed = verdict
        t.reasoning_hash = rh
        t.status = "Committed"
        t.settle_deadline = self.now + self.settle_window
        vh = self._validation_hash(task_id, rh)
        self.validations[vh] = {"validator": self.ARENA, "agent_id": t.agent_id, "answered": False, "response": 0}
        self._emit("VerdictCommitted", task_id=task_id, agent_id=t.agent_id, verdict=verdict_label(verdict),
                   reasoning_hash=rh, settle_deadline=t.settle_deadline)
        self._emit("ValidationRequest", agent_id=t.agent_id, validator=self.ARENA, request_hash=vh)
        return self._receipt("commitVerdict")

    def settle(self, task_id: int, caller: str, truth: int, salt: str) -> Settlement:
        t = self.task(task_id)
        if t.status != "Committed":
            raise ChainError("NotCommitted")
        if to_checksum(caller) != to_checksum(t.poster):
            raise ChainError("NotPoster")
        if self.now > t.settle_deadline:
            raise ChainError("DeadlinePassed")
        if truth not in (YES, NO):
            raise ChainError("BadVerdict")
        if truth_commitment(truth, salt) != t.truth_commit:
            raise ChainError("TruthMismatch")

        stake_before = self.stake_of(t.agent_id)
        count_before, score_before = self.reputation_summary(t.agent_id, tag1=TAG_SETTLEMENT)
        if count_before == 0:
            score_before = 100  # an agent with no settlement history starts unblemished

        correct = settlement_rule(t.committed, truth)
        t.correct = correct
        t.revealed_truth = truth
        t.status = "Settled"

        slashed = 0
        returned = 0
        if correct:
            returned = self._release(self.bond_key(task_id))
            reward = t.fee + t.bounty
            self._credit(t.resolver, reward + returned)
        else:
            slashed = self._slash(self.bond_key(task_id))
            reward = 0
            self._credit(t.poster, t.fee + t.bounty + slashed)

        self.give_feedback(self.ARENA, t.agent_id, 100 if correct else 0, TAG_SETTLEMENT,
                           TAG_CORRECT if correct else TAG_WRONG)
        vh = self._validation_hash(task_id, t.reasoning_hash)
        if vh in self.validations:
            self.validations[vh].update(answered=True, response=100 if correct else 0)
        self._emit("TaskSettled", task_id=task_id, agent_id=t.agent_id, correct=correct,
                   truth=verdict_label(truth), slashed=slashed, reward=reward)
        _, score_after = self.reputation_summary(t.agent_id, tag1=TAG_SETTLEMENT)
        return Settlement(
            task_id=task_id, agent_id=t.agent_id, committed=t.committed, truth=truth, correct=correct,
            slashed=slashed, reward_paid=reward, collateral_returned=returned,
            stake_before=stake_before, stake_after=self.stake_of(t.agent_id),
            score_before=score_before, score_after=score_after,
            tx_hash=self._receipt("settle").tx_hash,
        )

    def timeout_commit(self, task_id: int) -> Receipt:
        t = self.task(task_id)
        if t.status != "Claimed":
            raise ChainError("NotClaimed")
        if self.now <= t.commit_deadline:
            raise ChainError("DeadlineNotReached")
        t.status = "Settled"
        returned = self._release(self.bond_key(task_id))
        self._credit(t.poster, t.fee + t.bounty)
        self._credit(t.resolver, returned)
        self.give_feedback(self.ARENA, t.agent_id, 0, TAG_SETTLEMENT, TAG_COMMIT_TIMEOUT)
        self._emit("TaskTimedOut", task_id=task_id, agent_id=t.agent_id, reason=TAG_COMMIT_TIMEOUT)
        return self._receipt("timeoutCommit")

    def timeout_settle(self, task_id: int) -> Receipt:
        t = self.task(task_id)
        if t.status != "Committed":
            raise ChainError("NotCommitted")
        if self.now <= t.settle_deadline:
            raise ChainError("DeadlineNotReached")
        t.status = "Settled"
        returned = self._release(self.bond_key(task_id))
        self._credit(t.resolver, t.fee + t.bounty + returned)
        self.give_feedback(self.ARENA, t.agent_id, 100, TAG_SETTLEMENT, TAG_REVEAL_TIMEOUT)
        self._emit("TaskTimedOut", task_id=task_id, agent_id=t.agent_id, reason=TAG_REVEAL_TIMEOUT)
        return self._receipt("timeoutSettle")

    def cancel_task(self, task_id: int, caller: str) -> Receipt:
        t = self.task(task_id)
        if t.status != "Open":
            raise ChainError("NotOpen")
        if to_checksum(caller) != to_checksum(t.poster):
            raise ChainError("NotPoster")
        t.status = "Cancelled"
        self._credit(t.poster, t.bounty)
        self._emit("TaskCancelled", task_id=task_id, refunded=t.bounty)
        return self._receipt("cancelTask")

    def withdraw(self, who: str) -> int:
        who = to_checksum(who)
        amount = self.credits.get(who, 0)
        if amount == 0:
            raise ChainError("NothingToWithdraw")
        self.credits[who] = 0
        self._transfer(self.ARENA, who, amount)
        self._emit("Withdrawn", account=who, amount=amount)
        return amount

    def credits_of(self, who: str) -> int:
        return self.credits.get(to_checksum(who), 0)

    def validation_status(self, task_id: int) -> dict[str, Any]:
        t = self.task(task_id)
        return self.validations.get(self._validation_hash(task_id, t.reasoning_hash), {})

    def advance(self, seconds: int) -> None:
        """Move the mirror's clock, the way `vm.warp` does in the Foundry suite."""
        self.now += seconds

    # --- internals -----------------------------------------------------------
    def _validation_hash(self, task_id: int, rh: str) -> str:
        if not rh:
            return ""
        return keccak_hex(_word(self.ARENA) + _word(task_id) + _word(rh))

    def _credit(self, who: str, amount: int) -> None:
        if amount == 0:
            return
        who = to_checksum(who)
        self.credits[who] = self.credits.get(who, 0) + amount
        self._emit("Credited", account=who, amount=amount, balance=self.credits[who])

    def _receipt(self, method: str) -> Receipt:
        self._tx += 1
        tx_hash = keccak_hex(f"in-memory:{method}:{self._tx}".encode("utf-8"))
        return Receipt(tx_hash=tx_hash, method=method, events=list(self.events), simulated=True)

    def _emit(self, name: str, **fields) -> None:
        self.events.append({"event": name, **fields})
