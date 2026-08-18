"""Minimal ABI + RLP codec.

Enough of the Ethereum wire formats to build calldata, sign EIP-1559 transactions and
read return data without pulling in web3. Only the types this project actually sends
are supported, and anything else raises rather than guessing, so a typo in a signature
fails loudly instead of encoding garbage.
"""

from __future__ import annotations

from .hashing import keccak256

_STATIC = {"uint256", "uint64", "uint8", "address", "bytes32", "bool"}


def selector(signature: str) -> bytes:
    """First 4 bytes of keccak(signature), e.g. `transfer(address,uint256)`."""
    return keccak256(signature.encode("ascii"))[:4]


def _word(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative values are not supported")
    return value.to_bytes(32, "big")


def _to_bytes32(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        b = value
    else:
        b = bytes.fromhex(value.removeprefix("0x"))
    if len(b) != 32:
        raise ValueError("bytes32 must be 32 bytes")
    return b


def _addr(value: str) -> bytes:
    b = bytes.fromhex(value.removeprefix("0x"))
    if len(b) != 20:
        raise ValueError("address must be 20 bytes")
    return b.rjust(32, b"\x00")


def encode_single(typ: str, value) -> bytes:
    if typ in ("uint256", "uint64", "uint8"):
        return _word(int(value))
    if typ == "bool":
        return _word(1 if value else 0)
    if typ == "address":
        return _addr(value)
    if typ == "bytes32":
        return _to_bytes32(value)
    raise ValueError(f"unsupported static type: {typ}")


def encode(types: list[str], values: list) -> bytes:
    """ABI-encode a parameter list. Supports the static types plus `string`.

    Tuples of static types are written inline as `(t1,t2,...)`, matching how solc
    lays out a struct argument whose members are all static.
    """
    if len(types) != len(values):
        raise ValueError("types/values length mismatch")
    head = b""
    tail = b""
    # head slots: one word per top-level static type, or the flattened tuple
    slots = []
    for typ in types:
        if typ.startswith("(") and typ.endswith(")"):
            slots.append(len([t for t in typ[1:-1].split(",") if t]))
        else:
            slots.append(1)
    head_size = sum(slots) * 32

    for typ, value in zip(types, values):
        if typ == "string":
            head += _word(head_size + len(tail))
            raw = value.encode("utf-8")
            tail += _word(len(raw)) + raw + b"\x00" * ((32 - len(raw) % 32) % 32)
        elif typ.endswith("[]"):
            member = typ[:-2]
            if member not in _STATIC:
                raise ValueError("only arrays of static types are supported")
            head += _word(head_size + len(tail))
            tail += _word(len(value)) + b"".join(encode_single(member, v) for v in value)
        elif typ.startswith("(") and typ.endswith(")"):
            members = [t for t in typ[1:-1].split(",") if t]
            if any(m not in _STATIC for m in members):
                raise ValueError("only all-static tuples are supported")
            if len(members) != len(value):
                raise ValueError("tuple arity mismatch")
            head += b"".join(encode_single(m, v) for m, v in zip(members, value))
        else:
            head += encode_single(typ, value)
    return head + tail


def call_data(signature: str, types: list[str], values: list) -> str:
    """0x-prefixed calldata for `signature`."""
    return "0x" + (selector(signature) + encode(types, values)).hex()


def decode_uint(data: str, index: int = 0) -> int:
    raw = bytes.fromhex(data.removeprefix("0x"))
    return int.from_bytes(raw[index * 32:(index + 1) * 32], "big")


def decode_address(data: str, index: int = 0) -> str:
    raw = bytes.fromhex(data.removeprefix("0x"))
    return "0x" + raw[index * 32 + 12:(index + 1) * 32].hex()


def decode_bytes32(data: str, index: int = 0) -> str:
    raw = bytes.fromhex(data.removeprefix("0x"))
    return "0x" + raw[index * 32:(index + 1) * 32].hex()


# --- RLP (only what an EIP-1559 transaction needs) ----------------------------


def rlp_encode(item) -> bytes:
    if isinstance(item, int):
        item = b"" if item == 0 else item.to_bytes((item.bit_length() + 7) // 8, "big")
    if isinstance(item, str):
        item = bytes.fromhex(item.removeprefix("0x"))
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        return _rlp_len(len(item), 0x80) + item
    if isinstance(item, (list, tuple)):
        body = b"".join(rlp_encode(x) for x in item)
        return _rlp_len(len(body), 0xC0) + body
    raise TypeError(f"cannot rlp-encode {type(item)!r}")


def _rlp_len(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    enc = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(enc)]) + enc
