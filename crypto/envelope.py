"""
How the application actually protects data: every stored value is sealed
with a cipher (AES, DES or RC4) plus HMAC-SHA256 ("encrypt-then-MAC"), and
each user's data key is protected with envelope encryption.

The assignment asks for all stored data to be encrypted with AES, RC4 AND
DES, so the app stores three independent sealed copies of every value
(see ALGORITHMS). The AES copy is the one the app relies on; the DES and RC4
copies exist so the three ciphers can be compared on real data (see
analysis.py). Each copy is a complete ciphertext: any one of them can be
decrypted on its own.

Why not just "AES-CBC"?
-----------------------
CBC hides the content, but an attacker who can modify the database could
flip bits in the ciphertext and change the decrypted result, or exploit
padding errors (a "padding oracle" attack). So every ciphertext gets a MAC
tag, and the tag is checked BEFORE anything is decrypted. RC4 needs the MAC
even more: flipping a ciphertext bit flips exactly that plaintext bit.

Sealed blob format
------------------
    version (1 byte) | IV or nonce | ciphertext | HMAC tag (32 bytes)

    version  cipher                 IV/nonce   ciphertext length
    0x01     AES-256-CBC            16 bytes   padded to a multiple of 16
    0x02     DES-CBC                 8 bytes   padded to a multiple of 8
    0x03     RC4-drop1536           16 bytes   same as the plaintext

    tag = HMAC-SHA256(mac_key, version | len(context) | context | IV | ciphertext)

`context` is a label like b"file|user:7|id:ab12..". It is not stored, but it
is included in the MAC, so a ciphertext copied from one record or one user
into another will FAIL to verify (prevents "cut-and-paste" attacks).

Block ciphers use CBC, never ECB (equal blocks would give equal ciphertext).
RC4 is a stream cipher, so it has no mode; the danger is reusing a key
(C1 XOR C2 = P1 XOR P2). So each message gets its own RC4 key,
HMAC(rc4_key, random 16-byte nonce), and the first 1536 keystream bytes,
the most biased ones, are thrown away (RFC 4345).

Keys from one master key
------------------------
Using the same key for two purposes is bad practice, so from one 32-byte
master key we derive independent sub-keys with HMAC (an HKDF-style
"expand" step): enc_key = HMAC(master, "<cipher> enc"), mac_key =
HMAC(master, "<cipher> mac"). DES uses the first 8 bytes of its enc_key
(56 effective bits: that is the weakness of DES, not of the derivation).

Note: SHA-256 and HMAC come from Python's standard library (hashlib/hmac).
Only the ciphers (AES, DES, RC4) are implemented from scratch in this project.
"""

import hashlib
import hmac
import secrets

from .aes import AES
from .des import DES
from .modes import cbc_decrypt, cbc_encrypt, pkcs7_pad, pkcs7_unpad, PaddingError
from .rc4 import rc4_crypt

TAG_LEN = 32
KEY_LEN = 32          # master keys (DEK, KEK) are 256 bits
RC4_DROP = 1536

# The order matters only for display; "aes" is the primary copy.
ALGORITHMS = ("aes", "des", "rc4")

# name: (version byte, label used to derive its keys, IV/nonce length, block size)
_SPEC = {
    "aes": (b"\x01", b"securevault", 16, 16),   # labels kept from v1 so old data still opens
    "des": (b"\x02", b"securevault des", 8, 8),
    "rc4": (b"\x03", b"securevault rc4", 16, 1),
}
_BY_VERSION = {spec[0]: name for name, spec in _SPEC.items()}

LABELS = {"aes": "AES-256-CBC", "des": "DES-CBC", "rc4": "RC4-drop1536"}


class DecryptionError(Exception):
    """Raised when a ciphertext is corrupted, tampered with, or the key is wrong.

    Deliberately one error type with no details: telling an attacker *why*
    decryption failed (bad MAC vs bad padding) is what padding-oracle attacks
    are built on.
    """


def generate_key() -> bytes:
    """A fresh random 256-bit key from the OS CSPRNG (never use `random`)."""
    return secrets.token_bytes(KEY_LEN)


def _subkeys(master_key: bytes, alg: str):
    if len(master_key) != KEY_LEN:
        raise ValueError("master key must be 32 bytes")
    label = _SPEC[alg][1]
    enc_key = hmac.new(master_key, label + b" enc v1", hashlib.sha256).digest()
    mac_key = hmac.new(master_key, label + b" mac v1", hashlib.sha256).digest()
    return enc_key, mac_key


def _tag(mac_key: bytes, version: bytes, context: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    msg = version + len(context).to_bytes(2, "big") + context + iv + ciphertext
    return hmac.new(mac_key, msg, hashlib.sha256).digest()


def _encrypt(alg, enc_key, iv, plaintext):
    if alg == "aes":
        return cbc_encrypt(AES(enc_key), pkcs7_pad(plaintext, 16), iv)
    if alg == "des":
        return cbc_encrypt(DES(enc_key[:8]), pkcs7_pad(plaintext, 8), iv)
    return rc4_crypt(hmac.new(enc_key, iv, hashlib.sha256).digest(), plaintext, RC4_DROP)


def _decrypt(alg, enc_key, iv, ciphertext):
    if alg == "aes":
        return pkcs7_unpad(cbc_decrypt(AES(enc_key), ciphertext, iv), 16)
    if alg == "des":
        return pkcs7_unpad(cbc_decrypt(DES(enc_key[:8]), ciphertext, iv), 8)
    return rc4_crypt(hmac.new(enc_key, iv, hashlib.sha256).digest(), ciphertext, RC4_DROP)


def algorithm_of(blob: bytes) -> str:
    """Which cipher sealed this blob (read from its version byte)."""
    try:
        return _BY_VERSION[blob[:1]]
    except KeyError:
        raise DecryptionError("malformed ciphertext") from None


def seal(master_key: bytes, plaintext: bytes, context: bytes, alg: str = "aes") -> bytes:
    """Encrypt and authenticate `plaintext` with one cipher."""
    version, _label, iv_len, _bs = _SPEC[alg]
    enc_key, mac_key = _subkeys(master_key, alg)
    iv = secrets.token_bytes(iv_len)                       # new random IV/nonce every time
    ciphertext = _encrypt(alg, enc_key, iv, plaintext)
    return version + iv + ciphertext + _tag(mac_key, version, context, iv, ciphertext)


def seal_all(master_key: bytes, plaintext: bytes, context: bytes) -> dict:
    """Seal `plaintext` once with every cipher: {"aes": blob, "des": blob, "rc4": blob}."""
    return {alg: seal(master_key, plaintext, context, alg) for alg in ALGORITHMS}


def open_sealed(master_key: bytes, blob: bytes, context: bytes) -> bytes:
    """Verify, then decrypt. Raises DecryptionError on any problem."""
    alg = algorithm_of(blob)
    version, _label, iv_len, block = _SPEC[alg]
    # A block-cipher ciphertext holds at least one block (the padding).
    if len(blob) < 1 + iv_len + (block if block > 1 else 0) + TAG_LEN:
        raise DecryptionError("malformed ciphertext")
    enc_key, mac_key = _subkeys(master_key, alg)
    iv = blob[1:1 + iv_len]
    ciphertext = blob[1 + iv_len:-TAG_LEN]
    tag = blob[-TAG_LEN:]

    # 1. Check integrity FIRST, with a constant-time comparison.
    if not hmac.compare_digest(tag, _tag(mac_key, version, context, iv, ciphertext)):
        raise DecryptionError("integrity check failed")
    # 2. Only now decrypt.
    try:
        return _decrypt(alg, enc_key, iv, ciphertext)
    except (PaddingError, ValueError):
        raise DecryptionError("decryption failed") from None


def iv_length(alg: str) -> int:
    return _SPEC[alg][2]


# --- Envelope encryption of the per-user Data Encryption Key (DEK) ----------
#
#   password --PBKDF2--> KEK (key-encryption key, never stored)
#   DEK (random)  --seal with KEK--> wrapped_dek (stored in the users table)
#   user data --seal with DEK--> ciphertext (stored)
#
# Benefits: changing a password only re-wraps the 32-byte DEK instead of
# re-encrypting every file, and nobody (not even the server operator) can
# unwrap the DEK without the user's password.

def wrap_key(kek: bytes, dek: bytes, username: str) -> bytes:
    return seal(kek, dek, b"dek-wrap|user:" + username.lower().encode())


def unwrap_key(kek: bytes, wrapped: bytes, username: str) -> bytes:
    dek = open_sealed(kek, wrapped, b"dek-wrap|user:" + username.lower().encode())
    if len(dek) != KEY_LEN:
        raise DecryptionError("bad key length")
    return dek
