"""
Padding and modes of operation for any block cipher in this package
(AES with 16-byte blocks or DES with 8-byte blocks).

A block cipher only encrypts ONE fixed-size block. A "mode of operation"
says how to encrypt a message of many blocks.

ECB (Electronic Codebook)  -- DO NOT USE for real data
    C_i = E(K, P_i)
    Every block is encrypted independently, so equal plaintext blocks give
    equal ciphertext blocks. Structure leaks (see the "ECB penguin" demo in
    the Crypto Lab).

CBC (Cipher Block Chaining) -- used by this application
    C_0 = E(K, P_0 XOR IV)
    C_i = E(K, P_i XOR C_(i-1))
    Each block depends on all previous blocks and on a random IV, so equal
    plaintexts give different ciphertexts. CBC alone gives CONFIDENTIALITY
    but not INTEGRITY: an attacker can flip bits. That is why envelope.py
    adds an HMAC ("encrypt-then-MAC").

Functions here expect data whose length is a multiple of the block size.
Use pkcs7_pad / pkcs7_unpad around them.
"""


class PaddingError(ValueError):
    pass


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """PKCS#7: append N bytes of value N (1 <= N <= block_size).

    A full block of padding is added when the data is already aligned, so
    the padding can always be removed unambiguously.
    """
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size:
        raise PaddingError("invalid padded length")
    n = data[-1]
    if not 1 <= n <= block_size or data[-n:] != bytes([n]) * n:
        raise PaddingError("invalid padding")
    return data[:-n]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings (done on big integers for speed)."""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _check_aligned(data: bytes, block_size: int):
    if len(data) % block_size:
        raise ValueError("data length must be a multiple of the block size; pad it first")


def ecb_encrypt(cipher, data: bytes) -> bytes:
    bs = cipher.block_size
    _check_aligned(data, bs)
    return b"".join(cipher.encrypt_block(data[i:i + bs]) for i in range(0, len(data), bs))


def ecb_decrypt(cipher, data: bytes) -> bytes:
    bs = cipher.block_size
    _check_aligned(data, bs)
    return b"".join(cipher.decrypt_block(data[i:i + bs]) for i in range(0, len(data), bs))


def cbc_encrypt(cipher, data: bytes, iv: bytes) -> bytes:
    bs = cipher.block_size
    _check_aligned(data, bs)
    if len(iv) != bs:
        raise ValueError("IV must be exactly one block long")
    out = []
    previous = iv
    for i in range(0, len(data), bs):
        previous = cipher.encrypt_block(xor_bytes(data[i:i + bs], previous))
        out.append(previous)
    return b"".join(out)


def cbc_decrypt(cipher, data: bytes, iv: bytes) -> bytes:
    bs = cipher.block_size
    _check_aligned(data, bs)
    if len(iv) != bs:
        raise ValueError("IV must be exactly one block long")
    out = []
    previous = iv
    for i in range(0, len(data), bs):
        block = data[i:i + bs]
        out.append(xor_bytes(cipher.decrypt_block(block), previous))
        previous = block
    return b"".join(out)
