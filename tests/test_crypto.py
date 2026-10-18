"""
Known-answer tests: our from-scratch ciphers must produce exactly the outputs
published in the official standards. If one table entry were wrong, these
would fail. Run with:  python -m unittest -v
"""

import os
import unittest

from crypto import envelope, passwords
from crypto.aes import AES, SBOX, INV_SBOX
from crypto.des import DES
from crypto.modes import (cbc_decrypt, cbc_encrypt, ecb_encrypt, pkcs7_pad,
                          pkcs7_unpad, PaddingError)
from crypto.rc4 import rc4_crypt

H = bytes.fromhex


class TestAES(unittest.TestCase):
    PT = H("00112233445566778899aabbccddeeff")

    def test_sbox_is_computed_correctly(self):
        self.assertEqual(SBOX[0x00], 0x63)
        self.assertEqual(SBOX[0x53], 0xED)          # FIPS-197 worked example
        self.assertEqual(sorted(SBOX), list(range(256)))  # it is a permutation
        self.assertTrue(all(INV_SBOX[SBOX[x]] == x for x in range(256)))

    def test_fips197_appendix_c(self):
        vectors = [
            (H("000102030405060708090a0b0c0d0e0f"), "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (H("000102030405060708090a0b0c0d0e0f1011121314151617"), "dda97ca4864cdfe06eaf70a0ec0d7191"),
            (H("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
             "8ea2b7ca516745bfeafc49904b496089"),
        ]
        for key, expected in vectors:
            aes = AES(key)
            self.assertEqual(aes.encrypt_block(self.PT).hex(), expected)
            self.assertEqual(aes.decrypt_block(H(expected)), self.PT)

    def test_traced_and_fast_paths_agree(self):
        for _ in range(200):
            aes = AES(os.urandom(32))
            block = os.urandom(16)
            self.assertEqual(aes.encrypt_block(block), aes.encrypt_block(block, trace=[]))
            self.assertEqual(aes.decrypt_block(block), aes.decrypt_block(block, trace=[]))

    def test_trace_has_every_step(self):
        trace = []
        AES(bytes(16)).encrypt_block(bytes(16), trace)
        steps = [t["step"] for t in trace]
        self.assertEqual(steps.count("SubBytes"), 10)
        self.assertEqual(steps.count("MixColumns"), 9)   # not in the final round

    def test_sp800_38a_ecb_and_cbc(self):
        key = H("2b7e151628aed2a6abf7158809cf4f3c")
        pt = H("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
        self.assertEqual(ecb_encrypt(AES(key), pt[:16]).hex(), "3ad77bb40d7a3660a89ecaf32466ef97")
        iv = H("000102030405060708090a0b0c0d0e0f")
        ct = cbc_encrypt(AES(key), pt, iv)
        self.assertEqual(ct.hex(), "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")
        self.assertEqual(cbc_decrypt(AES(key), ct, iv), pt)


class TestModes(unittest.TestCase):
    def test_pkcs7(self):
        self.assertEqual(pkcs7_pad(b"", 16), bytes([16]) * 16)
        self.assertEqual(pkcs7_pad(b"abc", 8), b"abc" + bytes([5]) * 5)
        self.assertEqual(pkcs7_unpad(pkcs7_pad(b"hello", 16), 16), b"hello")
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"A" * 15 + b"\x03", 16)

    def test_ecb_leaks_repetition_cbc_does_not(self):
        aes = AES(os.urandom(16))
        data = b"SAME BLOCK HERE!" * 4
        ecb = ecb_encrypt(aes, data)
        cbc = cbc_encrypt(aes, data, os.urandom(16))
        self.assertEqual(len({ecb[i:i + 16] for i in range(0, 64, 16)}), 1)
        self.assertEqual(len({cbc[i:i + 16] for i in range(0, 64, 16)}), 4)


class TestDES(unittest.TestCase):
    def test_known_answers(self):
        cases = [("133457799BBCDFF1", "0123456789ABCDEF", "85e813540f0ab405"),
                 ("0E329232EA6D0D73", "8787878787878787", "0000000000000000")]
        for key, pt, ct in cases:
            des = DES(H(key))
            self.assertEqual(des.encrypt_block(H(pt)).hex(), ct)
            self.assertEqual(des.decrypt_block(H(ct)), H(pt))

    def test_cbc_round_trip_with_8_byte_blocks(self):
        des, iv = DES(os.urandom(8)), os.urandom(8)
        msg = b"DES works with any mode, too."
        ct = cbc_encrypt(des, pkcs7_pad(msg, 8), iv)
        self.assertEqual(pkcs7_unpad(cbc_decrypt(des, ct, iv), 8), msg)


class TestRC4(unittest.TestCase):
    def test_known_answers(self):
        self.assertEqual(rc4_crypt(b"Key", b"Plaintext").hex(), "bbf316e8d940af0ad3")
        self.assertEqual(rc4_crypt(b"Wiki", b"pedia").hex(), "1021bf0420")
        self.assertEqual(rc4_crypt(b"Secret", b"Attack at dawn").hex(), "45a01f645fc35b383552544b9bf5")

    def test_encrypt_equals_decrypt(self):
        ct = rc4_crypt(b"k", b"hello")
        self.assertEqual(rc4_crypt(b"k", ct), b"hello")


class TestEnvelope(unittest.TestCase):
    def test_round_trip_and_random_iv(self):
        k = envelope.generate_key()
        a = envelope.seal(k, b"secret", b"ctx")
        b = envelope.seal(k, b"secret", b"ctx")
        self.assertNotEqual(a, b)                      # fresh IV each time
        self.assertEqual(envelope.open_sealed(k, a, b"ctx"), b"secret")

    def test_tampering_is_detected(self):
        k = envelope.generate_key()
        blob = bytearray(envelope.seal(k, b"pay 100", b"ctx"))
        blob[20] ^= 1                                   # flip one ciphertext bit
        with self.assertRaises(envelope.DecryptionError):
            envelope.open_sealed(k, bytes(blob), b"ctx")

    def test_wrong_key_or_context_fails(self):
        k = envelope.generate_key()
        blob = envelope.seal(k, b"x", b"profile|user:1|field:nik")
        with self.assertRaises(envelope.DecryptionError):
            envelope.open_sealed(envelope.generate_key(), blob, b"profile|user:1|field:nik")
        with self.assertRaises(envelope.DecryptionError):   # cut-and-paste into another field
            envelope.open_sealed(k, blob, b"profile|user:1|field:phone")

    def test_key_wrapping(self):
        kek, dek = envelope.generate_key(), envelope.generate_key()
        wrapped = envelope.wrap_key(kek, dek, "alice")
        self.assertEqual(envelope.unwrap_key(kek, wrapped, "alice"), dek)
        with self.assertRaises(envelope.DecryptionError):
            envelope.unwrap_key(kek, wrapped, "mallory")


class TestPasswords(unittest.TestCase):
    def test_hash_and_verify(self):
        h = passwords.hash_password("correct horse", 1000)
        self.assertTrue(h.startswith("pbkdf2_sha256$1000$"))
        self.assertNotIn("correct horse", h)
        self.assertTrue(passwords.verify_password("correct horse", h))
        self.assertFalse(passwords.verify_password("wrong horse", h))

    def test_same_password_different_hashes(self):
        self.assertNotEqual(passwords.hash_password("pw", 1000), passwords.hash_password("pw", 1000))

    def test_garbage_hash_is_rejected(self):
        self.assertFalse(passwords.verify_password("x", "not-a-hash"))


if __name__ == "__main__":
    unittest.main()
