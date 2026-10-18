"""
Password hashing and password-based key derivation with PBKDF2-HMAC-SHA256.

Hashing vs encryption
---------------------
* Encryption is REVERSIBLE: whoever has the key gets the plaintext back.
  We use it for data the user needs to read again (files, profile fields).
* Password hashing is ONE-WAY: we can only re-compute the hash from a
  candidate password and compare. We never need the password back, so we
  must not be able to get it back. If the database leaks, the attacker gets
  hashes, not passwords.

Why not plain SHA-256(password)?
--------------------------------
1. No salt: equal passwords have equal hashes, and precomputed tables
   (rainbow tables) work. -> We add a random 16-byte SALT per user.
2. Too fast: a GPU computes billions of SHA-256 per second, so guessing is
   cheap. -> PBKDF2 repeats HMAC-SHA256 many times (600,000 by default,
   the OWASP recommendation for PBKDF2-HMAC-SHA256) to make every guess slow.

Argon2id (memory-hard) is the modern first choice; PBKDF2 is used here
because it ships with Python's standard library and is easy to explain.

Stored format:  pbkdf2_sha256$<iterations>$<salt b64>$<hash b64>
Storing the iteration count lets us raise it later without breaking old hashes.
"""

import base64
import hashlib
import hmac
import secrets

DEFAULT_ITERATIONS = 600_000
SALT_LEN = 16


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    salt = secrets.token_bytes(SALT_LEN)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_b64, hash_b64 = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        iterations = int(iterations)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    # compare_digest takes the same time whether the first or last byte differs,
    # so response timing does not reveal how much of the hash matched.
    return hmac.compare_digest(candidate, expected)


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Derive the 32-byte key-encryption key (KEK) from the password.

    Uses a DIFFERENT salt from the login hash, so the stored verifier and the
    encryption key are unrelated values.
    """
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
