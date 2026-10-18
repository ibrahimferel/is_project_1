"""
DES (Data Encryption Standard, FIPS 46-3) implemented from scratch.

EDUCATIONAL ONLY. DES has a 56-bit effective key: in 1998 the EFF's
"Deep Crack" machine found a DES key in about 56 hours, and today it can be
brute-forced far faster. It is in this project only so you can study a
Feistel network and compare it with AES (a substitution-permutation network).

Structure
---------
    64-bit block --IP--> L0 | R0
    for i in 1..16:   L_i = R_(i-1)
                      R_i = L_(i-1) XOR f(R_(i-1), K_i)
    output = FP(R16 | L16)          (note the final swap)

    f(R, K) = P( S-boxes( E(R) XOR K ) )
        E   : expand 32 -> 48 bits
        XOR : mix in the 48-bit round key
        S   : 8 S-boxes, each 6 bits -> 4 bits   (the only non-linear part)
        P   : permute the 32 bits

Decryption is the SAME algorithm with the round keys in reverse order.
That is the beauty of a Feistel network: f never has to be inverted.

Bit numbering follows the standard: bit 1 is the MOST significant bit.
"""

# Initial permutation
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final permutation = inverse of IP (computed, so it cannot contain a typo)
FP = [0] * 64
for _out, _in in enumerate(IP):
    FP[_in - 1] = _out + 1

# Expansion: 32 -> 48 bits (some bits are used twice)
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Permutation applied to the S-box output
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Key schedule: Permuted Choice 1 (64 -> 56 bits, drops the 8 parity bits)
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2 (56 -> 48 bits round key)
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Left rotations of the two 28-bit key halves per round
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# The 8 S-boxes. Each has 4 rows x 16 columns of 4-bit values.
SBOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


def permute(value: int, table, in_bits: int) -> int:
    """Build a new integer whose i-th bit is bit table[i] of `value`.

    Bits are numbered 1..in_bits from the most significant side, exactly as
    in the DES standard, so the tables above can be used unchanged.
    """
    out = 0
    for position in table:
        out = (out << 1) | ((value >> (in_bits - position)) & 1)
    return out


def _rotate_left_28(value: int, n: int) -> int:
    return ((value << n) | (value >> (28 - n))) & 0x0FFFFFFF


def key_schedule(key: bytes):
    """Derive the sixteen 48-bit round keys K1..K16."""
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes (64 bits, 56 used)")
    k56 = permute(int.from_bytes(key, "big"), PC1, 64)
    c, d = k56 >> 28, k56 & 0x0FFFFFFF          # two 28-bit halves
    round_keys = []
    for shift in SHIFTS:
        c, d = _rotate_left_28(c, shift), _rotate_left_28(d, shift)
        round_keys.append(permute((c << 28) | d, PC2, 56))
    return round_keys


def feistel(right: int, round_key: int) -> int:
    """The DES round function f(R, K)."""
    x = permute(right, E, 32) ^ round_key        # 48 bits
    out = 0
    for i in range(8):                           # 8 chunks of 6 bits
        chunk = (x >> (42 - 6 * i)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 1)    # outer bits b1 b6
        col = (chunk >> 1) & 0x0F                     # inner bits b2..b5
        out = (out << 4) | SBOXES[i][row][col]
    return permute(out, P, 32)


class DES:
    block_size = 8
    name = "DES"

    def __init__(self, key: bytes):
        self.round_keys = key_schedule(key)
        # Round keys split into 8 six-bit chunks for the fast path (below).
        self._enc_chunks = [_key_chunks(k) for k in self.round_keys]
        self._dec_chunks = self._enc_chunks[::-1]

    def _crypt(self, block: bytes, keys, trace):
        if len(block) != 8:
            raise ValueError("DES block must be exactly 8 bytes")
        x = permute(int.from_bytes(block, "big"), IP, 64)
        left, right = x >> 32, x & 0xFFFFFFFF
        if trace is not None:
            trace.append({"round": 0, "key": None, "L": left, "R": right})
        for i, k in enumerate(keys, start=1):
            left, right = right, left ^ feistel(right, k)
            if trace is not None:
                trace.append({"round": i, "key": k, "L": left, "R": right})
        # Undo the last swap, then the final permutation.
        out = permute((right << 32) | left, FP, 64)
        return out.to_bytes(8, "big")

    def encrypt_block(self, block: bytes, trace=None) -> bytes:
        if trace is None:
            return _fast_crypt(self._enc_chunks, block)
        return self._crypt(block, self.round_keys, trace)

    def decrypt_block(self, block: bytes, trace=None) -> bytes:
        if trace is None:
            return _fast_crypt(self._dec_chunks, block)
        return self._crypt(block, list(reversed(self.round_keys)), trace)


# ---------------------------------------------------------------------------
# Fast path (used when no trace is requested)
# ---------------------------------------------------------------------------
#
# The bit-by-bit `permute` above is easy to check against the standard but
# makes DES about 20x slower than our AES, far too slow to encrypt stored
# files. Software DES (e.g. libdes / OpenSSL) uses the same tricks as here:
#
#   * IP and FP: one table per input byte, so a 64-bit permutation becomes
#     8 lookups OR-ed together.
#   * E: a 1-bit rotation of R lines up every 6-bit chunk of E(R), so the
#     expansion is just shifts and masks.
#   * S-box + P: SP[i][x] = P(S_i(x) placed at chunk i), so all 8 S-boxes and
#     the P permutation become 8 lookups.
#
# Every table is COMPUTED from IP, FP, P and SBOXES above (no pasted
# constants), and tests/test_crypto.py checks that both paths agree.

def _byte_tables(table, in_bits):
    return [[permute(v << (in_bits - 8 - 8 * p), table, in_bits) for v in range(256)]
            for p in range(in_bits // 8)]


_IP_T = _byte_tables(IP, 64)
_FP_T = _byte_tables(FP, 64)
_SP = [[permute(SBOXES[i][((x & 0x20) >> 4) | (x & 1)][(x >> 1) & 0x0F] << (28 - 4 * i), P, 32)
        for x in range(64)] for i in range(8)]


def _key_chunks(round_key):
    return tuple((round_key >> (42 - 6 * i)) & 0x3F for i in range(8))


def _permute64(tables, block):
    out = 0
    for t, byte in zip(tables, block):
        out |= t[byte]
    return out


def _fast_crypt(key_chunks, block):
    if len(block) != 8:
        raise ValueError("DES block must be exactly 8 bytes")
    sp0, sp1, sp2, sp3, sp4, sp5, sp6, sp7 = _SP
    x = _permute64(_IP_T, block)
    left, right = x >> 32, x & 0xFFFFFFFF
    for k0, k1, k2, k3, k4, k5, k6, k7 in key_chunks:
        r = ((right >> 1) | (right << 31)) & 0xFFFFFFFF     # bits 32,1,2,...,31
        left, right = right, left ^ (
            sp0[(r >> 26) ^ k0] | sp1[((r >> 22) & 63) ^ k1] |
            sp2[((r >> 18) & 63) ^ k2] | sp3[((r >> 14) & 63) ^ k3] |
            sp4[((r >> 10) & 63) ^ k4] | sp5[((r >> 6) & 63) ^ k5] |
            sp6[((r >> 2) & 63) ^ k6] | sp7[(((r & 0xF) << 2) | (r >> 30)) ^ k7])
    return _permute64(_FP_T, ((right << 32) | left).to_bytes(8, "big")).to_bytes(8, "big")
