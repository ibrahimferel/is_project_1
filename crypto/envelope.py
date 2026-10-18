"""
How the application actually protects data: AES-256-CBC + HMAC-SHA256
("encrypt-then-MAC"), plus envelope encryption of each user's data key.

Why not just "AES-CBC"?
-----------------------
CBC hides the content, but an attacker who can modify the database could
flip bits in the ciphertext and change the decrypted result, or exploit
padding errors (a "padding oracle" attack). So every ciphertext gets a MAC
tag, and the tag is checked BEFORE anything is decrypted.

Sealed blob format
------------------
    version (1 byte) | IV (16 bytes) | AES-CBC ciphertext | HMAC tag (32 bytes)

    tag = HMAC-SHA256(mac_key, version | len(context) | context | IV | ciphertext)

`context` is a label like b"file|user:7|id:ab12..". It is not stored, but it
is included in the MAC, so a ciphertext copied from one record or one user
into another will FAIL to verify (prevents "cut-and-paste" attacks).

Two keys from one
-----------------
Using the same key for AES and for HMAC is bad practice, so from one 32-byte
master key we derive two independent sub-keys with HMAC (an HKDF-style
"expand" step):  enc_key = HMAC(master, "enc"),  mac_key = HMAC(master, "mac").

Note: SHA-256 and HMAC come from Python's standard library (hashlib/hmac).
Only the ciphers (AES, DES, RC4) are implemented from scratch in this project.
"""

import hashlib
import hmac
import secrets

from .aes import AES
from .modes import cbc_decrypt, cbc_encrypt, pkcs7_pad, pkcs7_unpad, PaddingError

VERSION = b"\x01"
IV_LEN = 16
TAG_LEN = 32
KEY_LEN = 32  # AES-256


class DecryptionError(Exception):
    """Raised when a ciphertext is corrupted, tampered with, or the key is wrong.

    Deliberately one error type with no details: telling an attacker *why*
    decryption failed (bad MAC vs bad padding) is what padding-oracle attacks
    are built on.
    """


def generate_key() -> bytes:
    """A fresh random 256-bit key from the OS CSPRNG (never use `random`)."""
    return secrets.token_bytes(KEY_LEN)


def _subkeys(master_key: bytes):
    if len(master_key) != KEY_LEN:
        raise ValueError("master key must be 32 bytes")
    enc_key = hmac.new(master_key, b"securevault enc v1", hashlib.sha256).digest()
    mac_key = hmac.new(master_key, b"securevault mac v1", hashlib.sha256).digest()
    return enc_key, mac_key


def _tag(mac_key: bytes, context: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    msg = VERSION + len(context).to_bytes(2, "big") + context + iv + ciphertext
    return hmac.new(mac_key, msg, hashlib.sha256).digest()


def seal(master_key: bytes, plaintext: bytes, context: bytes) -> bytes:
    """Encrypt and authenticate `plaintext`."""
    enc_key, mac_key = _subkeys(master_key)
    iv = secrets.token_bytes(IV_LEN)                       # new random IV every time
    ciphertext = cbc_encrypt(AES(enc_key), pkcs7_pad(plaintext, 16), iv)
    return VERSION + iv + ciphertext + _tag(mac_key, context, iv, ciphertext)


def open_sealed(master_key: bytes, blob: bytes, context: bytes) -> bytes:
    """Verify, then decrypt. Raises DecryptionError on any problem."""
    if len(blob) < 1 + IV_LEN + 16 + TAG_LEN or blob[:1] != VERSION:
        raise DecryptionError("malformed ciphertext")
    enc_key, mac_key = _subkeys(master_key)
    iv = blob[1:1 + IV_LEN]
    ciphertext = blob[1 + IV_LEN:-TAG_LEN]
    tag = blob[-TAG_LEN:]

    # 1. Check integrity FIRST, with a constant-time comparison.
    if not hmac.compare_digest(tag, _tag(mac_key, context, iv, ciphertext)):
        raise DecryptionError("integrity check failed")
    # 2. Only now decrypt.
    try:
        return pkcs7_unpad(cbc_decrypt(AES(enc_key), ciphertext, iv), 16)
    except (PaddingError, ValueError):
        raise DecryptionError("decryption failed") from None


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
