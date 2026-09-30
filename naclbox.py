"""NaCl ``crypto_box_open`` (Curve25519-XSalsa20-Poly1305) on ``cryptography`` alone.

Hermes ships ``cryptography`` but not PyNaCl, and Access's token transfer is a NaCl box. Only the
decrypt side is needed: X25519 and Poly1305 come from ``cryptography``; the Salsa20 core is the
reference algorithm (tests pin it to vectors produced by libsodium through PyNaCl).
"""
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_SIGMA = struct.unpack("<4I", b"expand 32-byte k")
_M = 0xFFFFFFFF
# Quarter-round index sets: four column rounds, then four row rounds (one double round).
_QUARTERS = ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11),
             (0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14))


def _rotl(v, c):
    return ((v << c) & _M) | (v >> (32 - c))


def _rounds(key, block16):
    k = struct.unpack("<8I", key)
    n = struct.unpack("<4I", block16)
    x = [_SIGMA[0], *k[:4], _SIGMA[1], *n, _SIGMA[2], *k[4:], _SIGMA[3]]
    initial = list(x)
    for _ in range(10):
        for a, b, c, d in _QUARTERS:
            x[b] ^= _rotl((x[a] + x[d]) & _M, 7)
            x[c] ^= _rotl((x[b] + x[a]) & _M, 9)
            x[d] ^= _rotl((x[c] + x[b]) & _M, 13)
            x[a] ^= _rotl((x[d] + x[c]) & _M, 18)
    return x, initial


def hsalsa20(key, nonce16):
    x, _ = _rounds(key, nonce16)
    return struct.pack("<8I", *(x[i] for i in (0, 5, 10, 15, 6, 7, 8, 9)))


def xsalsa20_stream(key, nonce24, length):
    subkey, iv = hsalsa20(key, nonce24[:16]), nonce24[16:]
    out = bytearray()
    counter = 0
    while len(out) < length:
        x, initial = _rounds(subkey, iv + struct.pack("<Q", counter))
        out += struct.pack("<16I", *((a + b) & _M for a, b in zip(x, initial)))
        counter += 1
    return bytes(out[:length])


class PrivateKey:
    def __init__(self):
        self._key = X25519PrivateKey.generate()
        self.public_key = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @classmethod
    def from_bytes(cls, raw):
        self = cls.__new__(cls)
        self._key = X25519PrivateKey.from_private_bytes(raw)
        self.public_key = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return self

    def box_open(self, peer_public, message):
        """``nonce(24) ‖ mac(16) ‖ ciphertext`` → plaintext; raises ``ValueError`` on forgery."""
        if len(message) < 40:
            raise ValueError("NaCl box is too short.")
        nonce, mac, ciphertext = message[:24], message[24:40], message[40:]
        shared = self._key.exchange(X25519PublicKey.from_public_bytes(peer_public))
        key = hsalsa20(shared, bytes(16))
        stream = xsalsa20_stream(key, nonce, 32 + len(ciphertext))
        try:
            Poly1305.verify_tag(stream[:32], ciphertext, mac)
        except Exception:
            raise ValueError("NaCl box failed authentication.") from None
        return bytes(a ^ b for a, b in zip(ciphertext, stream[32:]))
