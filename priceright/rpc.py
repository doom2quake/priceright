"""JsonRpcChain - the same arena, driven over JSON-RPC with real transactions.

`InMemoryChain` and this class expose one interface, so the agent, the x402 gate and
the CLI are byte-identical whichever is in play. The difference is that every state
change here is an EIP-1559 transaction: RLP-encoded, signed with the same pure-Python
secp256k1 used to sign x402 authorisations, broadcast with `eth_sendRawTransaction`,
and waited on for a receipt. The `Receipt.tx_hash` you see in the CLI is then a hash
you can look up on the node.

`scripts/devnet.sh` deploys the contracts to a local anvil node with `forge create`
and runs the whole story through this adapter. Pointing `PRICERIGHT_RPC_URL` at a
public testnet works the same way and needs only a funded key; see the honesty note in
the README for what has and has not been executed on a public network.
"""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from .abi import call_data, decode_address, decode_bytes32, decode_uint, rlp_encode
from .arena import (
    NO,
    YES,
    ChainError,
    Receipt,
    Settlement,
    TaskView,
    TAG_SETTLEMENT,
    settlement_rule,
    verdict_label,
)
from .config import PriceRightSettings, settings
from .hashing import keccak256
from .secp256k1 import address_of, sign, to_checksum
from .x402 import EIP712Domain, PaymentPayload

_EVENT_SIGNATURES = [
    "TaskPosted(uint256,address,uint256,uint256,uint256)",
    "TaskCancelled(uint256,address,uint256)",
    "X402PaymentSettled(uint256,address,uint256,bytes32)",
    "TaskClaimed(uint256,uint256,address,uint256,uint256,uint64)",
    "VerdictCommitted(uint256,uint256,uint8,bytes32,uint64)",
    "TaskSettled(uint256,uint256,bool,uint8,uint256,uint256)",
    "TaskTimedOut(uint256,uint256,bytes32,uint256,uint256)",
    "Credited(address,uint256,uint256)",
    "Withdrawn(address,uint256)",
    "Bonded(bytes32,uint256,address,uint256)",
    "Released(bytes32,uint256,address,uint256)",
    "Slashed(bytes32,uint256,address,uint256)",
    "NewFeedback(uint256,address,uint8,bytes32,bytes32,string,bytes32)",
    "ValidationRequest(address,uint256,string,bytes32)",
    "ValidationResponse(address,uint256,bytes32,uint8,string,bytes32)",
    "AuthorizationUsed(address,bytes32)",
    "Transfer(address,address,uint256)",
]
_TOPIC_TO_NAME = {"0x" + keccak256(s.encode()).hex(): s.split("(")[0] for s in _EVENT_SIGNATURES}


class RpcError(ChainError):
    """The node rejected a call, or a transaction reverted."""


class EthRpc:
    """A very small JSON-RPC client (stdlib only, so there is no hidden dependency)."""

    def __init__(self, url: str, timeout: int = 30) -> None:
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - operator-supplied RPC URL
            out = json.loads(resp.read())
        if "error" in out:
            raise RpcError(f"{method}: {out['error'].get('message', out['error'])}")
        return out["result"]


class JsonRpcChain:
    """The arena, over a real node."""

    network = "evm"

    def __init__(self, cfg: PriceRightSettings | None = None) -> None:
        self.cfg = cfg or settings
        if not self.cfg.rpc_url:
            raise RpcError("PRICERIGHT_RPC_URL is not set")
        for name in ("arena_address", "token_address", "identity_address", "vault_address", "reputation_address"):
            if not getattr(self.cfg, name):
                raise RpcError(f"PRICERIGHT_{name.upper()} is required for the chain backend")
        self.rpc = EthRpc(self.cfg.rpc_url)
        self.arena_address = to_checksum(self.cfg.arena_address)
        self.token_address = to_checksum(self.cfg.token_address)
        self.identity_address = to_checksum(self.cfg.identity_address)
        self.vault_address = to_checksum(self.cfg.vault_address)
        self.reputation_address = to_checksum(self.cfg.reputation_address)
        self.chain_id = int(self.rpc.call("eth_chainId", []), 16)
        self.network = self.cfg.network or f"eip155:{self.chain_id}"
        self._keys: dict[str, int] = {}
        for key_hex in (self.cfg.resolver_key, self.cfg.resolver2_key, self.cfg.poster_key):
            if key_hex:
                pk = int(key_hex, 16)
                self._keys[to_checksum(address_of(pk))] = pk
        self.token_name = self._call_string(self.token_address, "name()")
        self.token_version = self._call_string(self.token_address, "version()")
        self.events: list[dict] = []
        self._secrets: dict[int, tuple[int, str]] = {}

    # --- identity to the x402 layer -----------------------------------------
    def token_domain(self) -> EIP712Domain:
        return EIP712Domain(self.token_name, self.token_version, self.chain_id, self.token_address)

    # --- reads ---------------------------------------------------------------
    def _eth_call(self, to: str, data: str) -> str:
        return self.rpc.call("eth_call", [{"to": to, "data": data}, "latest"])

    def _call_string(self, to: str, signature: str) -> str:
        raw = bytes.fromhex(self._eth_call(to, call_data(signature, [], [])).removeprefix("0x"))
        length = int.from_bytes(raw[32:64], "big")
        return raw[64:64 + length].decode("utf-8")

    def balance_of(self, who: str) -> int:
        return decode_uint(self._eth_call(self.token_address, call_data("balanceOf(address)", ["address"], [who])))

    def authorization_used(self, who: str, nonce: str) -> bool:
        data = call_data("authorizationState(address,bytes32)", ["address", "bytes32"], [who, nonce])
        return decode_uint(self._eth_call(self.token_address, data)) == 1

    def claim_nonce(self, task_id: int, agent_id: int) -> str:
        data = call_data("claimNonce(uint256,uint256)", ["uint256", "uint256"], [task_id, agent_id])
        return decode_bytes32(self._eth_call(self.arena_address, data))

    def bond_key(self, task_id: int) -> str:
        data = call_data("bondKey(uint256)", ["uint256"], [task_id])
        return decode_bytes32(self._eth_call(self.arena_address, data))

    def owner_of(self, agent_id: int) -> str:
        data = call_data("ownerOf(uint256)", ["uint256"], [agent_id])
        return to_checksum(decode_address(self._eth_call(self.identity_address, data)))

    def stake_of(self, agent_id: int) -> int:
        return decode_uint(self._eth_call(self.vault_address, call_data("stakeOf(uint256)", ["uint256"], [agent_id])))

    def slashed_of(self, agent_id: int) -> int:
        return decode_uint(self._eth_call(self.vault_address, call_data("slashedOf(uint256)", ["uint256"], [agent_id])))

    def credits_of(self, who: str) -> int:
        return decode_uint(self._eth_call(self.arena_address, call_data("credits(address)", ["address"], [who])))

    def reputation_summary(self, agent_id: int, clients: list[str] | None = None, tag1: str = "") -> tuple[int, int]:
        tag_bytes = tag1.encode("utf-8").ljust(32, b"\x00") if tag1 else b"\x00" * 32
        data = call_data(
            "getSummary(uint256,address[],bytes32)",
            ["uint256", "address[]", "bytes32"],
            [agent_id, clients or [], "0x" + tag_bytes.hex()],
        )
        out = self._eth_call(self.reputation_address, data)
        return decode_uint(out, 0), decode_uint(out, 1)

    def task(self, task_id: int) -> TaskView:
        out = self._eth_call(self.arena_address, call_data("getTask(uint256)", ["uint256"], [task_id]))
        status = ["Open", "Claimed", "Committed", "Settled", "Cancelled"][decode_uint(out, 4)]
        commit_by, settle_by = self._deadlines(task_id)
        return TaskView(
            task_id=task_id,
            poster=to_checksum(decode_address(out, 0)),
            bounty=decode_uint(out, 1),
            fee=decode_uint(out, 2),
            slash_amount=decode_uint(out, 3),
            truth_commit="",  # the commitment is not part of getTask; the poster holds it
            status=status,
            agent_id=decode_uint(out, 5),
            resolver=to_checksum(decode_address(out, 6)),
            committed=decode_uint(out, 7),
            reasoning_hash=decode_bytes32(out, 8),
            revealed_truth=decode_uint(out, 9),
            correct=None if status != "Settled" else bool(decode_uint(out, 10)),
            commit_deadline=commit_by,
            settle_deadline=settle_by,
        )

    def _deadlines(self, task_id: int) -> tuple[int, int]:
        out = self._eth_call(self.arena_address, call_data("deadlines(uint256)", ["uint256"], [task_id]))
        return decode_uint(out, 0), decode_uint(out, 1)

    # --- writes --------------------------------------------------------------
    def _key_for(self, who: str) -> int:
        pk = self._keys.get(to_checksum(who))
        if pk is None:
            raise RpcError(f"no private key configured for {who}")
        return pk

    def _send(self, sender: str, to: str, data: str, method: str) -> Receipt:
        """Sign and broadcast an EIP-1559 transaction, then wait for its receipt."""
        pk = self._key_for(sender)
        frm = to_checksum(address_of(pk))
        nonce = int(self.rpc.call("eth_getTransactionCount", [frm, "pending"]), 16)
        base_fee = int(self.rpc.call("eth_getBlockByNumber", ["pending", False])["baseFeePerGas"], 16)
        tip = 1_000_000_000
        max_fee = base_fee * 2 + tip
        try:
            gas = int(self.rpc.call("eth_estimateGas", [{"from": frm, "to": to, "data": data}]), 16)
            gas = gas + gas // 4
        except RpcError as exc:
            raise RpcError(f"{method} would revert: {exc}") from exc

        payload = [self.chain_id, nonce, tip, max_fee, gas, to, 0, data, []]
        sighash = keccak256(b"\x02" + rlp_encode(payload))
        v, r, s = sign(pk, sighash)
        signed = b"\x02" + rlp_encode(payload + [v - 27, r.lstrip(b"\x00"), s.lstrip(b"\x00")])
        tx_hash = self.rpc.call("eth_sendRawTransaction", ["0x" + signed.hex()])
        receipt = self._await_receipt(tx_hash)
        if int(receipt["status"], 16) != 1:
            raise RpcError(f"{method} reverted (tx {tx_hash})")
        events = self._decode_logs(receipt.get("logs", []))
        self.events.extend(events)
        return Receipt(tx_hash=tx_hash, method=method, events=events, simulated=False)

    def _await_receipt(self, tx_hash: str, tries: int = 120) -> dict:
        for _ in range(tries):
            receipt = self.rpc.call("eth_getTransactionReceipt", [tx_hash])
            if receipt:
                return receipt
            time.sleep(0.25)
        raise RpcError(f"no receipt for {tx_hash}")

    def _decode_logs(self, logs: list[dict]) -> list[dict]:
        out = []
        for log in logs:
            topics = log.get("topics", [])
            if not topics:
                continue
            name = _TOPIC_TO_NAME.get(topics[0].lower())
            if not name:
                continue
            entry: dict[str, Any] = {
                "event": name,
                "address": to_checksum(log["address"]),
                "tx": log.get("transactionHash", ""),
                "block": int(log.get("blockNumber", "0x0"), 16),
            }
            for i, topic in enumerate(topics[1:], start=1):
                entry[f"topic{i}"] = topic
            if name == "TaskSettled":
                entry.update(
                    task_id=int(topics[1], 16),
                    agent_id=int(topics[2], 16),
                    correct=bool(decode_uint(log["data"], 0)),
                    truth=verdict_label(decode_uint(log["data"], 1)),
                    slashed=decode_uint(log["data"], 2),
                    reward=decode_uint(log["data"], 3),
                )
            elif name in ("Slashed", "Released", "Bonded"):
                entry.update(agent_id=int(topics[2], 16), amount=decode_uint(log["data"], 0))
            elif name == "X402PaymentSettled":
                entry.update(task_id=int(topics[1], 16), amount=decode_uint(log["data"], 0))
            out.append(entry)
        return out

    def mint(self, to: str, amount: int) -> Receipt:
        sender = next(iter(self._keys))
        return self._send(sender, self.token_address, call_data("mint(address,uint256)", ["address", "uint256"], [to, amount]), "mint")

    def approve_vault(self, owner: str, amount: int) -> Receipt:
        data = call_data("approve(address,uint256)", ["address", "uint256"], [self.vault_address, amount])
        return self._send(owner, self.token_address, data, "approve")

    def approve_arena(self, owner: str, amount: int) -> Receipt:
        data = call_data("approve(address,uint256)", ["address", "uint256"], [self.arena_address, amount])
        return self._send(owner, self.token_address, data, "approve")

    def register_agent(self, controller: str, metadata_uri: str) -> int:
        data = call_data("register(string)", ["string"], [metadata_uri])
        agent_id = decode_uint(
            self.rpc.call("eth_call", [{"from": controller, "to": self.identity_address, "data": data}, "latest"])
        )
        self._send(controller, self.identity_address, data, "register")
        return agent_id

    def post_task(self, poster: str, truth: int, *, bounty: int | None = None, fee: int | None = None,
                  slash_amount: int | None = None, salt: str | None = None) -> TaskView:
        import secrets

        from .hashing import truth_commitment

        if truth not in (YES, NO):
            raise ChainError("truth must be YES(1) or NO(2)")
        salt = salt or ("0x" + secrets.token_hex(32))
        commit = truth_commitment(truth, salt)
        bounty = self.cfg.bounty if bounty is None else bounty
        fee = self.cfg.fee if fee is None else fee
        slash_amount = self.cfg.stake if slash_amount is None else slash_amount
        data = call_data(
            "postTask(uint256,uint256,uint256,bytes32)",
            ["uint256", "uint256", "uint256", "bytes32"],
            [bounty, fee, slash_amount, commit],
        )
        task_id = decode_uint(
            self.rpc.call("eth_call", [{"from": poster, "to": self.arena_address, "data": data}, "latest"])
        )
        self._send(poster, self.arena_address, data, "postTask")
        self._secrets[task_id] = (truth, salt)
        view = self.task(task_id)
        view.truth_commit = commit
        return view

    def claim_task(self, task_id: int, agent_id: int, payment: PaymentPayload) -> Receipt:
        auth = payment.authorization
        v, r, s = payment.vrs()
        data = call_data(
            "claimTask(uint256,uint256,(address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32))",
            ["uint256", "uint256", "(address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"],
            [
                task_id,
                agent_id,
                [
                    auth.from_address,
                    auth.value,
                    auth.valid_after,
                    auth.valid_before,
                    auth.nonce,
                    v,
                    "0x" + r.hex(),
                    "0x" + s.hex(),
                ],
            ],
        )
        return self._send(auth.from_address, self.arena_address, data, "claimTask")

    def commit_verdict(self, task_id: int, caller: str, verdict: int, reasoning: str) -> Receipt:
        from .hashing import reasoning_hash

        data = call_data(
            "commitVerdict(uint256,uint8,bytes32)",
            ["uint256", "uint8", "bytes32"],
            [task_id, verdict, reasoning_hash(reasoning)],
        )
        return self._send(caller, self.arena_address, data, "commitVerdict")

    def settle(self, task_id: int, caller: str, truth: int, salt: str) -> Settlement:
        t = self.task(task_id)
        before_stake = self.stake_of(t.agent_id)
        count_before, score_before = self.reputation_summary(t.agent_id, tag1=TAG_SETTLEMENT)
        data = call_data("settle(uint256,uint8,bytes32)", ["uint256", "uint8", "bytes32"], [task_id, truth, salt])
        receipt = self._send(caller, self.arena_address, data, "settle")
        settled = next((e for e in receipt.events if e["event"] == "TaskSettled"), {})
        correct = bool(settled.get("correct", settlement_rule(t.committed, truth)))
        _, score_after = self.reputation_summary(t.agent_id, tag1=TAG_SETTLEMENT)
        return Settlement(
            task_id=task_id,
            agent_id=t.agent_id,
            committed=t.committed,
            truth=truth,
            correct=correct,
            slashed=int(settled.get("slashed", 0)),
            reward_paid=int(settled.get("reward", 0)),
            collateral_returned=before_stake if correct else 0,
            stake_before=before_stake,
            stake_after=self.stake_of(t.agent_id),
            # an agent with no settlement history starts unblemished, not at zero
            score_before=100 if count_before == 0 else score_before,
            score_after=score_after,
            tx_hash=receipt.tx_hash,
        )

    def withdraw(self, who: str) -> int:
        before = self.balance_of(who)
        self._send(who, self.arena_address, call_data("withdraw()", [], []), "withdraw")
        return self.balance_of(who) - before

    def timeout_commit(self, task_id: int) -> Receipt:
        return self._send(
            next(iter(self._keys)), self.arena_address, call_data("timeoutCommit(uint256)", ["uint256"], [task_id]),
            "timeoutCommit",
        )

    def timeout_settle(self, task_id: int) -> Receipt:
        return self._send(
            next(iter(self._keys)), self.arena_address, call_data("timeoutSettle(uint256)", ["uint256"], [task_id]),
            "timeoutSettle",
        )

    def validation_status(self, task_id: int) -> dict[str, Any]:
        data = call_data("validationHashOf(uint256)", ["uint256"], [task_id])
        return {"request_hash": decode_bytes32(self._eth_call(self.arena_address, data))}

    def truth_of(self, task_id: int) -> tuple[int, str]:
        """The poster's own record of what it committed. Not readable from the chain."""
        if task_id not in self._secrets:
            raise ChainError("this process did not post that task")
        return self._secrets[task_id]

    def advance(self, seconds: int) -> None:
        """Devnet only: anvil exposes evm_increaseTime; a public testnet will refuse."""
        self.rpc.call("evm_increaseTime", [seconds])
        self.rpc.call("evm_mine", [])


def make_chain(cfg: PriceRightSettings | None = None):
    """The one place `use_chain` is consumed.

    Configured RPC + addresses -> real transactions. Nothing configured -> the
    in-memory mirror. A half-configured environment raises instead of silently
    running the mirror while the operator believes they are on-chain.
    """
    cfg = cfg or settings
    from .arena import InMemoryChain

    if cfg.offline:
        return InMemoryChain(cfg)
    if cfg.rpc_url or cfg.arena_address:
        if not cfg.use_chain:
            raise RpcError(
                "partial chain configuration: PRICERIGHT_RPC_URL, PRICERIGHT_ARENA_ADDRESS and PRICERIGHT_TOKEN_ADDRESS "
                "must all be set (or none of them, to use the in-memory mirror)"
            )
        return JsonRpcChain(cfg)
    return InMemoryChain(cfg)
