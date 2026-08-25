"""Arena, policy and agent tests. Keyless: in-memory chain, local x402 facilitator.

Every test here corresponds to something that has to be true for the demo's claim to
hold, and several of them fail against the earlier version of this repo: collateral
used to be stranded, the escrow could be frozen by either party, the resolver was
handed the ground truth, and the CLI reported the post-settlement stake as if it were
the amount bonded at claim time.
"""

from __future__ import annotations

import pytest

from priceright.agent import Poster, ResolverAgent
from priceright.arena import NO, YES, ChainError, InMemoryChain, settlement_rule, verdict_label
from priceright.config import PriceRightSettings
from priceright.hashing import keccak_hex, reasoning_hash, truth_commitment
from priceright.policy import ABSTAIN, EvidencePolicy, StaleCachePolicy
from priceright.rpc import RpcError, make_chain

CLAIM = "Settle: ETH/USD >= 4000 @ block 21451200"
SUPPORTIVE = "chainlink-eth-usd  block=21451200  ETH/USD=4127.50\npyth-eth-usd  block=21451200  ETH/USD=4126.10"
CONTRARY = "chainlink-eth-usd  block=21451200  ETH/USD=3872.40\npyth-eth-usd  block=21451200  ETH/USD=3869.95"
WRONG_BLOCK = "chainlink-eth-usd  block=21400000  ETH/USD=4127.50"
WRONG_SYMBOL = "chainlink-btc-usd  block=21451200  BTC/USD=98120.00"

FUNDING = 10_000


@pytest.fixture()
def chain() -> InMemoryChain:
    cfg = PriceRightSettings()
    c = InMemoryChain(cfg)
    for key in (cfg.poster_private_key(), cfg.resolver_private_key(), cfg.resolver2_private_key()):
        from priceright.secp256k1 import address_of

        c.mint(address_of(key), FUNDING)
    return c


def _total_supply(chain: InMemoryChain) -> int:
    return sum(chain.balances.values())


# --- keccak parity with Solidity ---------------------------------------------


def test_keccak_matches_known_vectors():
    assert keccak_hex(b"") == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak_hex(b"abc") == "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def test_truth_commitment_is_deterministic_and_truth_dependent():
    salt = "0x" + "11" * 32
    c1 = truth_commitment(YES, salt)
    assert c1 == truth_commitment(YES, salt)
    assert len(c1) == 66 and c1.startswith("0x")
    assert truth_commitment(NO, salt) != c1


def test_reasoning_hash_changes_on_edit():
    assert reasoning_hash("oracle printed 4127") != reasoning_hash("oracle printed 4128")


# --- the policy derives verdicts, it does not read the answer -----------------


def test_evidence_policy_follows_the_evidence():
    assert EvidencePolicy().decide(CLAIM, SUPPORTIVE).verdict == YES
    # the exact test that a truth-reading policy fails: flip the readings, flip the verdict
    assert EvidencePolicy().decide(CLAIM, CONTRARY).verdict == NO


def test_evidence_policy_abstains_when_the_evidence_does_not_cover_the_claim():
    assert EvidencePolicy().decide(CLAIM, WRONG_SYMBOL).verdict == ABSTAIN
    assert EvidencePolicy().decide(CLAIM, WRONG_BLOCK).verdict == ABSTAIN
    assert EvidencePolicy().decide("is the sky blue?", SUPPORTIVE).verdict == ABSTAIN


def test_stale_cache_policy_is_not_hardcoded_to_be_wrong():
    """It answers from its cache. When the cache happens to agree, it is right."""
    stale = StaleCachePolicy()
    assert stale.decide(CLAIM, SUPPORTIVE).verdict == NO  # cache says 3805, evidence says 4127
    # the same policy against a lower threshold its stale quote does clear
    assert stale.decide("Settle: ETH/USD >= 3000 @ block 21451200", SUPPORTIVE).verdict == YES


def test_resolver_is_never_handed_the_truth(chain):
    poster = Poster(chain)
    task = poster.post(CLAIM, SUPPORTIVE)
    public = chain.task(task.task_id)
    assert not hasattr(public, "truth")
    assert not hasattr(public, "salt")
    # before settlement the only thing on-chain about the answer is its commitment
    assert public.revealed_truth == 0
    assert public.truth_commit.startswith("0x")


# --- x402-gated claim ---------------------------------------------------------


def test_claim_requires_a_paid_x402_authorisation(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    task = poster.post(CLAIM, SUPPORTIVE)
    before = chain.balance_of(agent.address)
    res = agent.play(task.task_id, CLAIM, SUPPORTIVE)
    assert res.status == "committed"
    assert res.payment_tx
    # exactly the fee, charged once, plus the collateral bond
    assert chain.balance_of(agent.address) == before - task.fee - task.slash_amount
    assert chain.authorization_used(agent.address, chain.claim_nonce(task.task_id, agent.agent_id))


def test_agent_that_cannot_answer_pays_nothing(chain):
    """Fail closed: an abstaining resolver must not have bought a claim first."""
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    task = poster.post(CLAIM, SUPPORTIVE)
    before = chain.balance_of(agent.address)
    res = agent.play(task.task_id, CLAIM, WRONG_SYMBOL)
    assert res.status == "abstained"
    assert chain.balance_of(agent.address) == before
    assert chain.task(task.task_id).status == "Open"


# --- settlement moves every token --------------------------------------------


def test_correct_settlement_returns_the_collateral(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    task = poster.post(CLAIM, SUPPORTIVE)
    agent.play(task.task_id, CLAIM, SUPPORTIVE)
    s = poster.settle(task.task_id)

    assert s.correct is True
    assert s.reward_paid == task.fee + task.bounty
    assert s.collateral_returned == task.slash_amount
    # the defect this pins: the bond used to stay in the contract forever
    assert chain.credits_of(agent.address) == task.fee + task.bounty + task.slash_amount
    assert chain.stake_of(agent.agent_id) == 0
    chain.withdraw(agent.address)
    assert chain.balance_of(agent.address) == FUNDING + task.bounty


def test_wrong_settlement_moves_the_collateral_to_the_poster(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=False)
    task = poster.post(CLAIM, SUPPORTIVE)
    agent.play(task.task_id, CLAIM, SUPPORTIVE)
    s = poster.settle(task.task_id)

    assert s.correct is False
    assert s.slashed == task.slash_amount
    assert chain.credits_of(agent.address) == 0
    assert chain.credits_of(poster.address) == task.fee + task.bounty + task.slash_amount
    chain.withdraw(poster.address)
    assert chain.balance_of(poster.address) == FUNDING + task.fee + task.slash_amount
    assert chain.balance_of(agent.address) == FUNDING - task.fee - task.slash_amount


@pytest.mark.parametrize("honest", [True, False])
def test_no_tokens_are_stranded(chain, honest):
    supply_before = _total_supply(chain)
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=honest)
    task = poster.post(CLAIM, SUPPORTIVE)
    agent.play(task.task_id, CLAIM, SUPPORTIVE)
    poster.settle(task.task_id)
    for who in (agent.address, poster.address):
        if chain.credits_of(who):
            chain.withdraw(who)
    assert chain.balance_of(chain.ARENA) == 0
    assert chain.balance_of(chain.VAULT) == 0
    assert _total_supply(chain) == supply_before


def test_settlement_is_a_pure_function():
    assert settlement_rule(YES, YES) and settlement_rule(NO, NO)
    assert not settlement_rule(YES, NO) and not settlement_rule(NO, YES)


# --- liveness: neither side can freeze the escrow -----------------------------


def test_resolver_that_never_commits_can_be_timed_out(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    task = poster.post(CLAIM, SUPPORTIVE)
    challenge = agent.gate.challenge(task.task_id, agent.agent_id)
    agent.gate.grant(task.task_id, agent.agent_id, agent.client.pay(challenge.requirements).header())

    with pytest.raises(ChainError):
        chain.timeout_commit(task.task_id)  # too early
    chain.advance(chain.commit_window + 1)
    chain.timeout_commit(task.task_id)

    assert chain.credits_of(poster.address) == task.fee + task.bounty
    assert chain.credits_of(agent.address) == task.slash_amount  # no verdict, no slash
    assert chain.stake_of(agent.agent_id) == 0


def test_poster_that_never_reveals_loses_the_bounty(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    task = poster.post(CLAIM, SUPPORTIVE)
    agent.play(task.task_id, CLAIM, SUPPORTIVE)

    with pytest.raises(ChainError):
        chain.timeout_settle(task.task_id)
    chain.advance(chain.settle_window + 1)
    chain.timeout_settle(task.task_id)

    assert chain.credits_of(agent.address) == task.fee + task.bounty + task.slash_amount
    assert chain.credits_of(poster.address) == 0


def test_deadlines_are_enforced_on_commit_and_settle(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    task = poster.post(CLAIM, SUPPORTIVE)
    challenge = agent.gate.challenge(task.task_id, agent.agent_id)
    agent.gate.grant(task.task_id, agent.agent_id, agent.client.pay(challenge.requirements).header())
    chain.advance(chain.commit_window + 1)
    with pytest.raises(ChainError, match="DeadlinePassed"):
        chain.commit_verdict(task.task_id, agent.address, YES, "too late")


def test_open_task_can_be_cancelled_but_a_claimed_one_cannot(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    t1 = poster.post(CLAIM, SUPPORTIVE)
    chain.cancel_task(t1.task_id, poster.address)
    assert chain.credits_of(poster.address) == t1.bounty

    t2 = poster.post(CLAIM, SUPPORTIVE)
    agent.play(t2.task_id, CLAIM, SUPPORTIVE)
    with pytest.raises(ChainError, match="NotOpen"):
        chain.cancel_task(t2.task_id, poster.address)


def test_lifecycle_guards(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    task = poster.post(CLAIM, SUPPORTIVE)
    with pytest.raises(ChainError, match="NotClaimed"):
        chain.commit_verdict(task.task_id, agent.address, YES, "x")
    agent.play(task.task_id, CLAIM, SUPPORTIVE)
    with pytest.raises(ChainError, match="DeadlineNotReached"):
        chain.timeout_settle(task.task_id)  # committed, but the reveal window is open
    poster.settle(task.task_id)
    with pytest.raises(ChainError, match="NotCommitted"):
        poster.settle(task.task_id)


def test_settle_rejects_a_reveal_that_breaks_the_commitment(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    task = poster.post(CLAIM, SUPPORTIVE)
    agent.play(task.task_id, CLAIM, SUPPORTIVE)
    truth, salt = poster._secrets[task.task_id]
    with pytest.raises(ChainError, match="TruthMismatch"):
        chain.settle(task.task_id, poster.address, NO if truth == YES else YES, salt)


def test_poster_refuses_to_open_an_unanswerable_task(chain):
    with pytest.raises(ValueError, match="unanswerable"):
        Poster(chain).post(CLAIM, WRONG_SYMBOL)


# --- ERC-8004 records ---------------------------------------------------------


def test_settlement_writes_erc8004_feedback_and_answers_the_validation_request(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=False)
    task = poster.post(CLAIM, SUPPORTIVE)
    agent.play(task.task_id, CLAIM, SUPPORTIVE)
    assert chain.validation_status(task.task_id)["answered"] is False  # filed before the reveal
    poster.settle(task.task_id)

    rep = agent.reputation()
    assert rep["feedback_count"] == 1 and rep["score"] == 0 and rep["slashed"] == task.slash_amount
    assert chain.validation_status(task.task_id) == {
        "validator": chain.ARENA, "agent_id": agent.agent_id, "answered": True, "response": 0
    }


def test_identity_transfer_carries_the_record(chain):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=False)
    task = poster.post(CLAIM, SUPPORTIVE)
    agent.play(task.task_id, CLAIM, SUPPORTIVE)
    poster.settle(task.task_id)

    new_owner = "0x000000000000000000000000000000000000dEaD"
    chain.transfer_agent(agent.agent_id, agent.address, new_owner)
    assert chain.owner_of(agent.agent_id).lower() == new_owner.lower()
    count, avg = chain.reputation_summary(agent.agent_id, tag1="priceright.settlement")
    assert (count, avg) == (1, 0)


# --- the run stream the CLI renders ------------------------------------------


def test_run_stream_reports_each_step_at_the_time_it_happens(chain):
    """The CLI used to print the post-settlement stake in the claim step."""
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=False)  # this run ends in a slash
    task = poster.post(CLAIM, SUPPORTIVE)

    seen: list[tuple[str, dict]] = []
    res = agent.play(task.task_id, CLAIM, SUPPORTIVE, on_event=lambda n, f: seen.append((n, f)))
    poster.settle(task.task_id)

    names = [n for n, _ in seen]
    assert names == ["decided", "challenged", "signed", "paid", "committed"]
    paid = dict(seen)["paid"]
    # bonded at claim time, not the zero it becomes after the slash
    assert paid["bonded"] == task.slash_amount
    assert paid["stake"] == task.slash_amount
    assert chain.stake_of(agent.agent_id) == 0  # ...and it really is gone afterwards
    assert res.status == "committed"


def test_blocked_runs_report_the_guardrail(chain, monkeypatch):
    poster = Poster(chain)
    agent = ResolverAgent(chain, honest=True)
    task = poster.post(CLAIM, SUPPORTIVE)
    monkeypatch.setattr("priceright.agent._limiter.check", lambda run_id, action: (False, "dry-run"))
    res = agent.play(task.task_id, CLAIM, SUPPORTIVE)
    assert res.status == "blocked" and res.reason == "dry-run"
    assert chain.task(task.task_id).status == "Open"


# --- backend selection --------------------------------------------------------


def test_make_chain_refuses_a_half_configured_environment(monkeypatch):
    """A configured RPC with no addresses used to run the mirror silently."""
    cfg = PriceRightSettings()
    object.__setattr__(cfg, "rpc_url", "http://127.0.0.1:8545")
    object.__setattr__(cfg, "arena_address", "")
    object.__setattr__(cfg, "offline", False)
    with pytest.raises(RpcError, match="partial chain configuration"):
        make_chain(cfg)


def test_make_chain_uses_the_mirror_when_nothing_is_configured():
    cfg = PriceRightSettings()
    object.__setattr__(cfg, "rpc_url", "")
    object.__setattr__(cfg, "arena_address", "")
    assert isinstance(make_chain(cfg), InMemoryChain)


def test_a_configured_facilitator_url_is_actually_used(chain):
    """The other half of the same defect: settings that nothing reads.

    `PRICERIGHT_X402_FACILITATOR_URL` has to change which facilitator the agent talks to,
    and `PRICERIGHT_OFFLINE` has to be able to take it back out again.
    """
    from priceright.agent import make_facilitator
    from priceright.x402 import HttpFacilitator, LocalFacilitator

    cfg = PriceRightSettings()
    object.__setattr__(cfg, "x402_facilitator_url", "http://127.0.0.1:9/")
    object.__setattr__(cfg, "offline", False)
    remote = make_facilitator(chain, cfg)
    assert isinstance(remote, HttpFacilitator) and remote.url == "http://127.0.0.1:9"

    object.__setattr__(cfg, "offline", True)
    assert isinstance(make_facilitator(chain, cfg), LocalFacilitator)


def test_verdict_labels():
    assert (verdict_label(YES), verdict_label(NO), verdict_label(0)) == ("Yes", "No", "None")
