"""Minimal pure-python Ed25519 (RFC 8032) for Tor v3 .onion key generation.

Only implements what Aeterra needs: public key derivation from a 32-byte
seed, plus Tor v3 onion address derivation and key file construction.
Stdlib only.
"""

import base64
import hashlib
import secrets

# --- Ed25519 (RFC 8032, public key from seed) ---
_P = 2 ** 255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _xrecover(_GY)
_G = (_GX, _GY)


def _edwards_add(p, q):
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _D * x1 * x2 * y1 * y2, _P - 2, _P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _D * x1 * x2 * y1 * y2, _P - 2, _P)
    return (x3 % _P, y3 % _P)


def _scalarmult(p, e):
    q = (0, 1)
    while e > 0:
        if e & 1:
            q = _edwards_add(q, p)
        p = _edwards_add(p, p)
        e >>= 1
    return q


def _encodepoint(p):
    x, y = p
    bits = (y & ((1 << 255) - 1)) | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def pubkey_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= ~(1 | 2 | 4 | (1 << 255))  # clear bits 0,1,2 and 255
    a |= 1 << 254  # set bit 254
    return _encodepoint(_scalarmult(_G, a))


# --- Tor v3 onion address + key files ---
_SECRET_HDR = b"== ed25519v1-secret: type0 ==" + b"\x00" * 3
_PUBLIC_HDR = b"== ed25519v1-public: type0 ==" + b"\x00" * 3
assert len(_SECRET_HDR) == 32 and len(_PUBLIC_HDR) == 32


def onion_address(pubkey: bytes) -> str:
    """Derive the v3 .onion address (without suffix) from a 32-byte pubkey."""
    if len(pubkey) != 32:
        raise ValueError("pubkey must be 32 bytes")
    chk = hashlib.sha3_256(b".onion checksum" + pubkey + b"\x03").digest()[:2]
    return base64.b32encode(pubkey + chk + b"\x03").decode("ascii").lower()


def _clamped_scalar(seed: bytes):
    """Return (a_int, a_bytes, h_second_half) from a 32-byte seed."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= ~(1 | 2 | 4 | (1 << 255))  # clear bits 0,1,2 and 255
    a |= 1 << 254  # set bit 254
    return a, a.to_bytes(32, "little"), h[32:64]


def generate_keypair():
    """Generate a fresh v3 onion keypair.

    Tor's secret key file layout (verified against mkp224o output):
      32-byte header + clamped scalar a (32) + SHA512(seed)[32:64] (32).
    It is NOT seed||pubkey (libsodium layout) -- Tor rejects that.

    Returns dict with: seed, scalar, pubkey, address, secret_key_file
    (96 bytes), public_key_file (64 bytes), hostname (with .onion + newline).
    """
    seed = secrets.token_bytes(32)
    a, a_bytes, h2 = _clamped_scalar(seed)
    pubkey = _encodepoint(_scalarmult(_G, a))
    addr = onion_address(pubkey)
    return {
        "seed": seed,
        "scalar": a_bytes,
        "pubkey": pubkey,
        "address": addr,
        "secret_key_file": _SECRET_HDR + a_bytes + h2,
        "public_key_file": _PUBLIC_HDR + pubkey,
        "hostname": (addr + ".onion\n").encode("ascii"),
    }


if __name__ == "__main__":
    # Self-test: keypair generation + Tor file format + address shape.
    kp = generate_keypair()
    assert len(kp["seed"]) == 32
    assert len(kp["scalar"]) == 32
    assert len(kp["pubkey"]) == 32
    assert len(kp["secret_key_file"]) == 96
    assert len(kp["public_key_file"]) == 64
    assert kp["secret_key_file"][:32] == _SECRET_HDR
    assert kp["public_key_file"][:32] == _PUBLIC_HDR
    assert kp["public_key_file"][32:] == kp["pubkey"]
    # Tor derives the pubkey as scalar*B from secret[32:64]; must match.
    a = int.from_bytes(kp["secret_key_file"][32:64], "little")
    assert _encodepoint(_scalarmult(_G, a)) == kp["pubkey"]
    addr = kp["address"]
    assert len(addr) == 56 and addr == addr.lower()
    assert all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in addr)
    assert kp["hostname"] == (addr + ".onion\n").encode("ascii")
    # Determinism: same seed -> same pubkey/address.
    assert pubkey_from_seed(kp["seed"]) == kp["pubkey"]
    assert onion_address(kp["pubkey"]) == addr
    print("self-test OK:", addr + ".onion")
