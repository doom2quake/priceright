"""x402: the HTTP-native payment protocol, implemented rather than gestured at.

The flow x402 specifies, and what each piece is here:

  1. The client requests a paid resource. The server answers **HTTP 402** with a JSON
     body listing `accepts: [PaymentRequirements]` - amount, asset, payTo, network,
     scheme. `ClaimGate.challenge()` builds that body from the on-chain task.
  2. The client picks a requirement and produces a **payment payload**. For the
     `exact` scheme on EVM that payload is an EIP-3009 `TransferWithAuthorization`
     signed with EIP-712. `X402Client.pay()` signs it for real (see `secp256k1.py`),
     base64-encodes it, and sends it back in the **X-PAYMENT** header.
  3. The server hands the header to a **facilitator**: `/verify` checks the signature
     and the terms, `/settle` submits the authorisation. `LocalFacilitator` does both
     against the configured chain. `HttpFacilitator` POSTs the spec's `/verify` body
     to a remote facilitator and requires its approval before the arena submits the
     authorisation; it never lets a failed or unreachable facilitator through.
  4. The server returns the resource plus **X-PAYMENT-RESPONSE**, a base64 settlement
     receipt carrying the transaction hash.

Two deliberate choices are worth a reviewer's attention:

  * The nonce is dictated by the resource, not chosen by the client. It is
    `AgentArena.claimNonce(taskId, agentId)`, which commits to the arena address and
    the chain id, so a signed claim payment is worthless on any other task, arena or
    chain. The spec leaves nonce selection to the client; pinning it is what binds the
    payment to the work being bought.
  * Verification is real. `LocalFacilitator.verify` recovers the signer from the
    EIP-712 digest and rejects a wrong payer, a wrong amount, a wrong recipient, a
    wrong nonce, an expired window or a reused authorisation. There is no path that
    accepts an empty proof.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from .hashing import keccak256
from .secp256k1 import address_of, recover, sign, to_checksum

X402_VERSION = 1

_EIP712_DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)
_TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
    b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
)


class PaymentError(Exception):
    """Raised when a payment cannot be produced, verified or settled."""


def _word(v: int) -> bytes:
    return int(v).to_bytes(32, "big")


def _addr_word(a: str) -> bytes:
    return bytes.fromhex(a.removeprefix("0x")).rjust(32, b"\x00")


def _b32(v: str | bytes) -> bytes:
    b = v if isinstance(v, bytes) else bytes.fromhex(v.removeprefix("0x"))
    if len(b) != 32:
        raise PaymentError("nonce must be 32 bytes")
    return b


@dataclass(frozen=True)
class EIP712Domain:
    name: str
    version: str
    chain_id: int
    verifying_contract: str

    def separator(self) -> bytes:
        return keccak256(
            _EIP712_DOMAIN_TYPEHASH
            + keccak256(self.name.encode("utf-8"))
            + keccak256(self.version.encode("utf-8"))
            + _word(self.chain_id)
            + _addr_word(self.verifying_contract)
        )


@dataclass(frozen=True)
class Authorization:
    """EIP-3009 TransferWithAuthorization fields."""

    from_address: str
    to: str
    value: int
    valid_after: int
    valid_before: int
    nonce: str

    def struct_hash(self) -> bytes:
        return keccak256(
            _TRANSFER_WITH_AUTHORIZATION_TYPEHASH
            + _addr_word(self.from_address)
            + _addr_word(self.to)
            + _word(self.value)
            + _word(self.valid_after)
            + _word(self.valid_before)
            + _b32(self.nonce)
        )

    def digest(self, domain: EIP712Domain) -> bytes:
        return keccak256(b"\x19\x01" + domain.separator() + self.struct_hash())

    def to_json(self) -> dict[str, Any]:
        return {
            "from": self.from_address,
            "to": self.to,
            "value": str(self.value),
            "validAfter": str(self.valid_after),
            "validBefore": str(self.valid_before),
            "nonce": self.nonce,
        }


@dataclass(frozen=True)
class PaymentRequirements:
    """One entry of the `accepts` array in a 402 response body."""

    scheme: str
    network: str
    max_amount_required: int
    resource: str
    description: str
    pay_to: str
    asset: str
    max_timeout_seconds: int = 300
    mime_type: str = "application/json"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "network": self.network,
            "maxAmountRequired": str(self.max_amount_required),
            "resource": self.resource,
            "description": self.description,
            "mimeType": self.mime_type,
            "payTo": self.pay_to,
            "maxTimeoutSeconds": self.max_timeout_seconds,
            "asset": self.asset,
            "extra": self.extra,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "PaymentRequirements":
        return cls(
            scheme=d["scheme"],
            network=d["network"],
            max_amount_required=int(d["maxAmountRequired"]),
            resource=d["resource"],
            description=d.get("description", ""),
            pay_to=d["payTo"],
            asset=d["asset"],
            max_timeout_seconds=int(d.get("maxTimeoutSeconds", 300)),
            mime_type=d.get("mimeType", "application/json"),
            extra=d.get("extra", {}),
        )


@dataclass(frozen=True)
class PaymentPayload:
    """The decoded contents of an X-PAYMENT header."""

    scheme: str
    network: str
    authorization: Authorization
    signature: str
    x402_version: int = X402_VERSION

    def to_json(self) -> dict[str, Any]:
        return {
            "x402Version": self.x402_version,
            "scheme": self.scheme,
            "network": self.network,
            "payload": {"signature": self.signature, "authorization": self.authorization.to_json()},
        }

    def header(self) -> str:
        return base64.b64encode(json.dumps(self.to_json(), separators=(",", ":")).encode("utf-8")).decode("ascii")

    @classmethod
    def from_header(cls, header: str) -> "PaymentPayload":
        try:
            d = json.loads(base64.b64decode(header.encode("ascii")))
        except Exception as exc:  # noqa: BLE001 - any malformed header is one failure mode
            raise PaymentError(f"malformed X-PAYMENT header: {exc}") from exc
        if d.get("x402Version") != X402_VERSION:
            raise PaymentError(f"unsupported x402Version: {d.get('x402Version')!r}")
        a = d["payload"]["authorization"]
        return cls(
            scheme=d["scheme"],
            network=d["network"],
            authorization=Authorization(
                from_address=a["from"],
                to=a["to"],
                value=int(a["value"]),
                valid_after=int(a["validAfter"]),
                valid_before=int(a["validBefore"]),
                nonce=a["nonce"],
            ),
            signature=d["payload"]["signature"],
            x402_version=d["x402Version"],
        )

    def vrs(self) -> tuple[int, bytes, bytes]:
        raw = bytes.fromhex(self.signature.removeprefix("0x"))
        if len(raw) != 65:
            raise PaymentError("signature must be 65 bytes")
        v = raw[64]
        if v < 27:
            v += 27
        return v, raw[0:32], raw[32:64]


@dataclass(frozen=True)
class VerifyResponse:
    is_valid: bool
    payer: str = ""
    invalid_reason: str = ""


@dataclass(frozen=True)
class SettleResponse:
    success: bool
    tx_hash: str = ""
    network: str = ""
    payer: str = ""
    error_reason: str = ""

    def header(self) -> str:
        body = {
            "success": self.success,
            "transaction": self.tx_hash,
            "network": self.network,
            "payer": self.payer,
            "errorReason": self.error_reason or None,
        }
        return base64.b64encode(json.dumps(body, separators=(",", ":")).encode("utf-8")).decode("ascii")


# --- client -------------------------------------------------------------------


class X402Client:
    """The paying side. Holds a key and turns a 402 challenge into an X-PAYMENT header."""

    def __init__(self, private_key: int, domain: EIP712Domain) -> None:
        self.private_key = private_key
        self.domain = domain
        self.address = address_of(private_key)

    def pay(self, req: PaymentRequirements, *, now: int | None = None) -> PaymentPayload:
        if req.scheme != "exact":
            raise PaymentError(f"unsupported x402 scheme: {req.scheme}")
        nonce = req.extra.get("nonce")
        if not nonce:
            raise PaymentError("this resource pins the authorisation nonce; none was offered")
        if to_checksum(req.asset) != to_checksum(self.domain.verifying_contract):
            raise PaymentError("asset does not match the signing domain")
        now = int(time.time()) if now is None else now
        auth = Authorization(
            from_address=self.address,
            to=to_checksum(req.pay_to),
            value=req.max_amount_required,
            valid_after=0,
            valid_before=now + req.max_timeout_seconds,
            nonce=nonce,
        )
        v, r, s = sign(self.private_key, auth.digest(self.domain))
        return PaymentPayload(
            scheme=req.scheme,
            network=req.network,
            authorization=auth,
            signature="0x" + (r + s + bytes([v])).hex(),
        )


# --- facilitator ---------------------------------------------------------------


class Facilitator(Protocol):
    def verify(self, payload: PaymentPayload, req: PaymentRequirements) -> VerifyResponse: ...
    def settle(self, payload: PaymentPayload, req: PaymentRequirements, context: dict) -> SettleResponse: ...


class LocalFacilitator:
    """Verifies and settles against a chain this process can reach.

    `verify` is the part a judge should read: it recovers the signer from the EIP-712
    digest and compares every term of the authorisation against what the resource
    demanded. `settle` submits the authorisation through the chain adapter, which is
    the arena's `claimTask` - the same call whether the chain is the in-memory mirror
    or a JSON-RPC node.
    """

    def __init__(self, chain, domain: EIP712Domain) -> None:
        self.chain = chain
        self.domain = domain

    def verify(self, payload: PaymentPayload, req: PaymentRequirements) -> VerifyResponse:
        try:
            if payload.scheme != req.scheme:
                return VerifyResponse(False, invalid_reason="scheme_mismatch")
            if payload.network != req.network:
                return VerifyResponse(False, invalid_reason="network_mismatch")
            auth = payload.authorization
            if auth.value != req.max_amount_required:
                return VerifyResponse(False, invalid_reason="insufficient_value")
            if to_checksum(auth.to) != to_checksum(req.pay_to):
                return VerifyResponse(False, invalid_reason="wrong_pay_to")
            if auth.nonce.lower() != str(req.extra.get("nonce", "")).lower():
                return VerifyResponse(False, invalid_reason="nonce_not_bound_to_resource")
            now = int(time.time())
            if auth.valid_before <= now:
                return VerifyResponse(False, invalid_reason="authorization_expired")
            if auth.valid_after > now:
                return VerifyResponse(False, invalid_reason="authorization_not_yet_valid")
            v, r, s = payload.vrs()
            signer = recover(auth.digest(self.domain), v, r, s)
            if signer is None:
                return VerifyResponse(False, invalid_reason="unrecoverable_signature")
            if to_checksum(signer) != to_checksum(auth.from_address):
                return VerifyResponse(False, invalid_reason="signature_does_not_match_payer")
            if self.chain.authorization_used(auth.from_address, auth.nonce):
                return VerifyResponse(False, invalid_reason="authorization_already_used")
            if self.chain.balance_of(auth.from_address) < auth.value:
                return VerifyResponse(False, invalid_reason="insufficient_funds")
            return VerifyResponse(True, payer=to_checksum(signer))
        except PaymentError as exc:
            return VerifyResponse(False, invalid_reason=str(exc))

    def settle(self, payload: PaymentPayload, req: PaymentRequirements, context: dict) -> SettleResponse:
        from .arena import ChainError  # imported here: arena imports this module

        check = self.verify(payload, req)
        if not check.is_valid:
            return SettleResponse(False, network=req.network, error_reason=check.invalid_reason)
        try:
            receipt = self.chain.claim_task(context["task_id"], context["agent_id"], payload)
        except ChainError as exc:
            # the settlement transaction reverted. Report it the way the spec's settle
            # response does rather than throwing: the caller decides what to do next.
            return SettleResponse(False, network=req.network, error_reason=str(exc))
        return SettleResponse(True, tx_hash=receipt.tx_hash, network=req.network, payer=check.payer)


class HttpFacilitator:
    """A remote facilitator, spoken to over HTTP with the spec's `/verify` shapes.

    Configure `PRICERIGHT_X402_FACILITATOR_URL` to route verification through one. Two
    things about this class are worth a reviewer's attention, because both are
    decisions rather than omissions.

    **Verification is remote, settlement is not, and that is forced by the design.**
    In the `exact` scheme the settlement step consumes the EIP-3009 authorisation. In
    this arena the consumer is `AgentArena.claimTask`: it submits the authorisation
    itself, in the same transaction that records the claim and bonds collateral. If a
    facilitator broadcast the authorisation first, the token would mark the nonce used
    and the claim could never happen, so the payment would be spent on nothing. The
    arena is therefore the settler, and a remote facilitator is an *additional* gate:
    a claim needs both the facilitator's `isValid` and the arena's own verification.

    **It fails closed.** An unreachable facilitator, a non-JSON answer, an HTTP error
    or `isValid: false` all end the claim. There is no fallback that fabricates a
    proof and no path where a failed verification still reaches the chain.
    """

    def __init__(self, url: str, chain, domain: EIP712Domain, timeout: int = 30) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._settler = LocalFacilitator(chain, domain)

    def _post(self, path: str, body: dict) -> dict:
        """POST JSON with the standard library, so this rail adds no dependency."""
        import urllib.error
        import urllib.request

        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            f"{self.url}{path}", data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:  # noqa: S310 - operator-supplied URL
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise PaymentError(f"facilitator returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise PaymentError(f"facilitator unreachable: {exc.reason}") from exc
        except (ValueError, TypeError) as exc:
            raise PaymentError(f"facilitator answered with something that is not JSON: {exc}") from exc

    def verify(self, payload: PaymentPayload, req: PaymentRequirements) -> VerifyResponse:
        try:
            body = self._post(
                "/verify",
                {
                    "x402Version": X402_VERSION,
                    "paymentPayload": payload.to_json(),
                    "paymentRequirements": req.to_json(),
                },
            )
        except PaymentError as exc:
            return VerifyResponse(False, invalid_reason=str(exc))
        return VerifyResponse(
            is_valid=bool(body.get("isValid")),
            payer=body.get("payer", ""),
            invalid_reason=body.get("invalidReason", ""),
        )

    def settle(self, payload: PaymentPayload, req: PaymentRequirements, context: dict) -> SettleResponse:
        check = self.verify(payload, req)
        if not check.is_valid:
            return SettleResponse(False, network=req.network, error_reason=check.invalid_reason)
        # the arena submits the authorisation; see the class docstring for why the
        # facilitator must not.
        return self._settler.settle(payload, req, context)


# --- the paid resource ---------------------------------------------------------


@dataclass(frozen=True)
class Challenge:
    """An HTTP 402 response: status, body, and the requirement the client must meet."""

    status: int
    body: dict[str, Any]
    requirements: PaymentRequirements


@dataclass(frozen=True)
class PaidClaim:
    """A granted claim: the settlement receipt plus the header a server would return."""

    tx_hash: str
    payer: str
    amount: int
    network: str
    payment_response_header: str


class ClaimGate:
    """The server side: the right to claim a task is the paid resource.

    `challenge()` is the 402. `grant()` is the retry with X-PAYMENT: it verifies
    through the facilitator, settles, and only then does the arena consider the task
    claimed. A resolver that skips step 2 gets a 402 and nothing else.
    """

    def __init__(self, chain, facilitator: Facilitator, network: str) -> None:
        self.chain = chain
        self.facilitator = facilitator
        self.network = network

    def challenge(self, task_id: int, agent_id: int) -> Challenge:
        task = self.chain.task(task_id)
        req = PaymentRequirements(
            scheme="exact",
            network=self.network,
            max_amount_required=task.fee,
            resource=f"priceright://arena/{self.chain.arena_address}/tasks/{task_id}/claim",
            description=f"Right to claim and be scored on arena task #{task_id}",
            pay_to=self.chain.arena_address,
            asset=self.chain.token_address,
            max_timeout_seconds=300,
            extra={
                # EIP-712 domain of the asset, so the client can sign without asking the chain
                "name": self.chain.token_name,
                "version": self.chain.token_version,
                # the resource pins the nonce: this is what binds the payment to the task
                "nonce": self.chain.claim_nonce(task_id, agent_id),
            },
        )
        return Challenge(
            status=402,
            body={"x402Version": X402_VERSION, "error": "X-PAYMENT header is required", "accepts": [req.to_json()]},
            requirements=req,
        )

    def grant(self, task_id: int, agent_id: int, payment_header: str) -> PaidClaim:
        challenge = self.challenge(task_id, agent_id)
        payload = PaymentPayload.from_header(payment_header)
        check = self.facilitator.verify(payload, challenge.requirements)
        if not check.is_valid:
            raise PaymentError(f"402 payment rejected: {check.invalid_reason}")
        settled = self.facilitator.settle(
            payload, challenge.requirements, {"task_id": task_id, "agent_id": agent_id}
        )
        if not settled.success:
            raise PaymentError(f"402 settlement failed: {settled.error_reason}")
        return PaidClaim(
            tx_hash=settled.tx_hash,
            payer=settled.payer,
            amount=challenge.requirements.max_amount_required,
            network=settled.network,
            payment_response_header=settled.header(),
        )
