"""Record a full run to JSON, so the UI can show a real one instead of a drawing.

`priceright record --out ui/run.json` plays the demo against whichever backend is
configured and writes down what actually happened: the contract addresses, the 402
challenge, the base64 X-PAYMENT header the resolver produced, every transaction hash,
the decoded on-chain events and the closing ledger. `scripts/devnet.sh --record`
points it at a live anvil node and injects the result into `ui/index.html`, which is
why the event list in the UI carries transaction hashes you can look up with `cast`.

When the record is produced against the in-memory mirror it says so, and the UI
labels it as such. Nothing in the pipeline can turn a mirrored run into an on-chain
one: `simulated` comes straight off the receipts.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .agent import Poster, ResolverAgent
from .arena import verdict_label
from .config import settings
from .rpc import make_chain


def _contracts(chain) -> dict[str, str]:
    if hasattr(chain, "TOKEN"):
        return {
            "token": chain.TOKEN, "identity": chain.IDENTITY, "reputation": chain.REPUTATION,
            "validation": chain.VALIDATION, "vault": chain.VAULT, "arena": chain.ARENA,
        }
    return {
        "token": chain.token_address, "identity": chain.identity_address,
        "reputation": chain.reputation_address, "vault": chain.vault_address,
        "arena": chain.arena_address,
    }


def _run(chain, poster: Poster, agent: ResolverAgent, claim: str, evidence: str) -> dict[str, Any]:
    steps: dict[str, dict] = {}
    res = agent.play(task_id=(task := poster.post(claim, evidence)).task_id, claim=claim, evidence=evidence,
                     on_event=lambda name, fields: steps.setdefault(name, fields))
    out: dict[str, Any] = {
        "agent_id": agent.agent_id,
        "address": agent.address,
        "policy": agent.policy.name,
        "task_id": task.task_id,
        "bounty": task.bounty,
        "fee": task.fee,
        "collateral": task.slash_amount,
        "truth_commit": task.truth_commit,
        "status": res.status,
        "verdict": verdict_label(res.verdict),
        "reasoning": res.reasoning,
        "reasoning_hash": res.reasoning_hash,
    }
    if res.status != "committed":
        out["reason"] = res.reason
        return out

    challenge = steps.get("challenged", {})
    signed = steps.get("signed", {})
    paid = steps.get("paid", {})
    out["x402"] = {
        "status": challenge.get("status"),
        "scheme": challenge.get("scheme"),
        "network": challenge.get("network"),
        "amount": challenge.get("amount"),
        "asset": challenge.get("asset"),
        "pay_to": challenge.get("pay_to"),
        "nonce": challenge.get("nonce"),
        "signature": signed.get("signature"),
        "payment_header": res.payment_header,
        "payment_response": res.payment_response_header,
        "settle_tx": paid.get("tx"),
    }
    out["bonded"] = paid.get("bonded")
    out["commit_tx"] = steps.get("committed", {}).get("tx")

    s = poster.settle(task.task_id)
    out["settlement"] = {
        "revealed_truth": verdict_label(s.truth),
        "committed": verdict_label(s.committed),
        "correct": s.correct,
        "reward_paid": s.reward_paid,
        "collateral_returned": s.collateral_returned,
        "slashed": s.slashed,
        "stake_before": s.stake_before,
        "stake_after": s.stake_after,
        "score_before": s.score_before,
        "score_after": s.score_after,
        "tx": s.tx_hash,
    }
    out["reputation"] = agent.reputation()
    return out


def record(claim: str, evidence: str) -> dict[str, Any]:
    chain = make_chain(settings)
    simulated = getattr(chain, "network", "") == "in-memory"
    if simulated:
        from .secp256k1 import address_of

        for key in (settings.poster_private_key(), settings.resolver_private_key(),
                    settings.resolver2_private_key()):
            chain.mint(address_of(key), 10_000)

    poster = Poster(chain)
    reader = ResolverAgent(chain, honest=True, key=settings.resolver_private_key())
    cacher = ResolverAgent(chain, honest=False, key=settings.resolver2_private_key())

    runs = [
        _run(chain, poster, reader, claim, evidence),
        _run(chain, poster, cacher, claim, evidence),
    ]
    return {
        "generated_by": "priceright record",
        "simulated": simulated,
        "backend": getattr(chain, "network", "evm"),
        "chain_id": getattr(chain, "chain_id", 0),
        "rpc": settings.rpc_url,
        "contracts": _contracts(chain),
        "claim": claim,
        "evidence": evidence.splitlines(),
        "runs": runs,
        "events": list(getattr(chain, "events", [])),
        "ledger": {
            "poster": {"address": poster.address, "withdrawable": chain.credits_of(poster.address)},
            "agents": [
                {"agent_id": a.agent_id, "address": a.address, "withdrawable": chain.credits_of(a.address)}
                for a in (reader, cacher)
            ],
        },
    }


def main(argv: list[str] | None = None) -> int:
    from .main import CLAIM, EVIDENCE

    p = argparse.ArgumentParser(prog="priceright-record", description="Record a run to JSON for the UI.")
    p.add_argument("--out", default="-", help="output path, or - for stdout")
    p.add_argument("--inject", default="", help="also inject the record into this HTML file")
    args = p.parse_args(argv)

    data = record(CLAIM, EVIDENCE)
    blob = json.dumps(data, indent=2, sort_keys=False)
    if args.out == "-":
        print(blob)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(blob + "\n")
    if args.inject:
        inject(args.inject, data)
    return 0


def inject(html_path: str, data: dict) -> None:
    """Replace the recorded-run block in the UI with this record."""
    start, end = "/*RUN_RECORD_START*/", "/*RUN_RECORD_END*/"
    with open(html_path, encoding="utf-8") as fh:
        html = fh.read()
    if start not in html or end not in html:
        raise SystemExit(f"{html_path} has no run-record markers")
    head, rest = html.split(start, 1)
    _, tail = rest.split(end, 1)
    payload = json.dumps(data, separators=(",", ":"))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(f"{head}{start}\nconst RUN={payload};\n{end}{tail}")


if __name__ == "__main__":
    sys.exit(main())
