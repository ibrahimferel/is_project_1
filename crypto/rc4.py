"""
RC4 stream cipher, implemented from scratch.

EDUCATIONAL ONLY. RC4 is broken: its first keystream bytes are biased, the
WEP Wi-Fi standard was broken through its key scheduling (Fluhrer, Mantin and
Shamir, 2001), and RFC 7465 (2015) prohibits RC4 in TLS.

How a stream cipher works
-------------------------
RC4 does not encrypt blocks. It generates a pseudo-random byte stream (the
keystream) from the key and XORs it with the data:

    ciphertext = plaintext XOR keystream
    plaintext  = ciphertext XOR keystream          (same operation!)

Two phases:
  1. KSA  (Key-Scheduling Algorithm): shuffle the array S = [0..255]
     using the key.
  2. PRGA (Pseudo-Random Generation Algorithm): keep swapping elements of S
     and output one byte per step.

Biggest practical danger: NEVER reuse a key. If two messages are encrypted
with the same keystream, then  c1 XOR c2 = p1 XOR p2  and the key no longer
matters. The Crypto Lab demonstrates this.
"""


def ksa(key: bytes):
    """Key-Scheduling Algorithm: returns the initial permutation S."""
    if not 1 <= len(key) <= 256:
        raise ValueError("RC4 key must be 1..256 bytes")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def prga(s, length: int) -> bytes:
    """Pseudo-Random Generation Algorithm: produce `length` keystream bytes.

    Works on a copy of S so the caller's array is not modified.
    """
    s = list(s)
    i = j = 0
    out = bytearray()
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) % 256])
    return bytes(out)


def keystream(key: bytes, length: int) -> bytes:
    return prga(ksa(key), length)


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Encrypt or decrypt (they are the same operation)."""
    ks = keystream(key, len(data))
    return bytes(d ^ k for d, k in zip(data, ks))
