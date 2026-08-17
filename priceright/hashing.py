"""Keccak-256 helpers that mirror the on-chain hashing exactly.

The arena commits `keccak256(bytes(reasoning))` for a resolver's reasoning and
`keccak256(abi.encodePacked(uint8(truth), salt))` for the poster's ground-truth
commitment. We reproduce both here so the offline mirror and the live contract
agree byte-for-byte: hash the same reasoning off-chain, get the same 32-byte value
the contract stored, and the commitment reveal checks out identically.

`hashlib.sha3_256` is NIST SHA-3, which pads differently and is not the hash Ethereum
uses, so it cannot be substituted here. This is Keccak-f[1600] with the original 0x01
padding byte, implemented in pure Python: no external dependency, and digests that match
Solidity's `keccak256` on the standard vectors (pinned in `tests/test_priceright.py`).
"""

from __future__ import annotations


# --- pure-Python keccak-256 (Ethereum variant) --------------------------------
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(state: list[list[int]]) -> None:
    for rc in _RC:
        # theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(state[x][y], _ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        # iota
        state[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Ethereum keccak-256 of `data`, returning 32 raw bytes."""
    rate = 136  # bytes (1088 bits) for keccak-256
    # pad10*1 with Ethereum keccak domain (0x01 first pad byte)
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] ^= 0x80

    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)

    out = bytearray()
    while len(out) < 32:
        for y in range(5):
            for x in range(5):
                if len(out) >= 32:
                    break
                out += state[x][y].to_bytes(8, "little")
    return bytes(out[:32])


def keccak_hex(data: bytes) -> str:
    """0x-prefixed keccak-256 hex of `data`."""
    return "0x" + keccak256(data).hex()


def reasoning_hash(reasoning: str) -> str:
    """keccak256(bytes(reasoning)) - matches AgentArena's on-chain commit."""
    return keccak_hex(reasoning.encode("utf-8"))


def truth_commitment(truth: int, salt_hex: str) -> str:
    """keccak256(abi.encodePacked(uint8(truth), salt)) - the poster's commitment.

    `truth` is 1 (Yes) or 2 (No); `salt_hex` is a 0x 32-byte hex string.
    abi.encodePacked(uint8, bytes32) is simply the truth byte followed by the salt.
    """
    salt = bytes.fromhex(salt_hex[2:] if salt_hex.startswith("0x") else salt_hex)
    if len(salt) != 32:
        raise ValueError("salt must be 32 bytes")
    return keccak_hex(bytes([truth & 0xFF]) + salt)
