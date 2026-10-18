"""
AES (Advanced Encryption Standard, FIPS-197) implemented from scratch.

Nothing here comes from a crypto library. Even the S-box is *computed*
from its mathematical definition instead of being copied as a table, so
you can see where every number comes from.

The state
---------
AES works on a 16-byte block arranged as a 4x4 matrix of bytes, filled
column by column:

    input bytes:  b0 b1 b2 ... b15

    state:        b0  b4  b8  b12      row 0
                  b1  b5  b9  b13      row 1
                  b2  b6  b10 b14      row 2
                  b3  b7  b11 b15      row 3

In this file the state is a flat Python list of 16 ints in the same order
as the input bytes, so state[r + 4*c] is "row r, column c".

One round of encryption = SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
(the last round skips MixColumns). AES-128/192/256 use 10/12/14 rounds.

SECURITY NOTE: this implementation is for learning. It uses table lookups
whose timing depends on secret data (a cache-timing side channel) and pure
Python is slow. Real systems should use a vetted library (e.g. the
`cryptography` package with AES-GCM). See README.md, section "Why not use
this AES in production?".
"""

# ---------------------------------------------------------------------------
# 1. Arithmetic in GF(2^8)
#
# AES treats every byte as a polynomial over GF(2) with 8 coefficients, e.g.
# 0x57 = 0101 0111 = x^6 + x^4 + x^2 + x + 1.
# Addition is XOR. Multiplication is polynomial multiplication reduced
# modulo the irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B).
# ---------------------------------------------------------------------------

def xtime(a: int) -> int:
    """Multiply a byte by x (= 2) in GF(2^8)."""
    a <<= 1
    if a & 0x100:          # the result overflowed 8 bits -> reduce by m(x)
        a ^= 0x11B
    return a


def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) ("Russian peasant" method)."""
    result = 0
    while b:
        if b & 1:
            result ^= a    # addition in GF(2^8) is XOR
        a = xtime(a)
        b >>= 1
    return result


def gf_inverse(a: int) -> int:
    """Multiplicative inverse in GF(2^8). By convention inverse(0) = 0.

    The non-zero elements form a group of size 255, so a^255 = 1 and
    therefore a^254 = a^-1.
    """
    if a == 0:
        return 0
    result, base, exponent = 1, a, 254
    while exponent:
        if exponent & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exponent >>= 1
    return result


def _affine_transform(b: int) -> int:
    """The affine step of the S-box (FIPS-197 section 5.1.1).

    bit_i' = b_i ^ b_(i+4) ^ b_(i+5) ^ b_(i+6) ^ b_(i+7) ^ c_i, with c = 0x63
    """
    c = 0x63
    out = 0
    for i in range(8):
        bit = ((b >> i) ^ (b >> ((i + 4) % 8)) ^ (b >> ((i + 5) % 8))
               ^ (b >> ((i + 6) % 8)) ^ (b >> ((i + 7) % 8)) ^ (c >> i)) & 1
        out |= bit << i
    return out


# The S-box: inverse in GF(2^8), then the affine transform.
SBOX = tuple(_affine_transform(gf_inverse(x)) for x in range(256))
INV_SBOX = tuple(SBOX.index(y) for y in range(256))

# Pre-computed multiplication tables used by MixColumns / InvMixColumns.
# They are just gf_mul(x, n) for every x, stored so we do not recompute.
MUL2 = tuple(gf_mul(x, 2) for x in range(256))
MUL3 = tuple(gf_mul(x, 3) for x in range(256))
MUL9 = tuple(gf_mul(x, 9) for x in range(256))
MUL11 = tuple(gf_mul(x, 11) for x in range(256))
MUL13 = tuple(gf_mul(x, 13) for x in range(256))
MUL14 = tuple(gf_mul(x, 14) for x in range(256))

# Round constants for key expansion: RCON[i] = x^(i-1) in GF(2^8).
RCON = [0x00, 0x01]
for _ in range(14):
    RCON.append(xtime(RCON[-1]))


# ---------------------------------------------------------------------------
# 2. The four round operations (and their inverses)
# ---------------------------------------------------------------------------

def sub_bytes(state):
    """Non-linear step: replace every byte with SBOX[byte]."""
    return [SBOX[b] for b in state]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def shift_rows(state):
    """Row r is rotated left by r positions (row 0 is unchanged).

    new[row r, col c] = old[row r, col (c + r) mod 4]
    """
    return [state[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(state):
    """Row r is rotated right by r positions."""
    return [state[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def mix_columns(state):
    """Each column is multiplied by a fixed matrix in GF(2^8):

        | 2 3 1 1 |   | s0 |
        | 1 2 3 1 | x | s1 |
        | 1 1 2 3 |   | s2 |
        | 3 1 1 2 |   | s3 |

    This spreads every input byte over the whole column ("diffusion").
    """
    out = []
    for c in range(4):
        s0, s1, s2, s3 = state[4 * c: 4 * c + 4]
        out += [
            MUL2[s0] ^ MUL3[s1] ^ s2 ^ s3,
            s0 ^ MUL2[s1] ^ MUL3[s2] ^ s3,
            s0 ^ s1 ^ MUL2[s2] ^ MUL3[s3],
            MUL3[s0] ^ s1 ^ s2 ^ MUL2[s3],
        ]
    return out


def inv_mix_columns(state):
    """Inverse matrix: [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]."""
    out = []
    for c in range(4):
        s0, s1, s2, s3 = state[4 * c: 4 * c + 4]
        out += [
            MUL14[s0] ^ MUL11[s1] ^ MUL13[s2] ^ MUL9[s3],
            MUL9[s0] ^ MUL14[s1] ^ MUL11[s2] ^ MUL13[s3],
            MUL13[s0] ^ MUL9[s1] ^ MUL14[s2] ^ MUL11[s3],
            MUL11[s0] ^ MUL13[s1] ^ MUL9[s2] ^ MUL14[s3],
        ]
    return out


def add_round_key(state, round_key):
    """XOR the state with the 16-byte round key. XOR is its own inverse."""
    return [s ^ k for s, k in zip(state, round_key)]


# ---------------------------------------------------------------------------
# 3. Key expansion (FIPS-197 section 5.2)
# ---------------------------------------------------------------------------

def expand_key(key: bytes):
    """Turn a 16/24/32-byte key into (rounds + 1) round keys of 16 bytes.

    The key is split into Nk 4-byte words. Each new word is the XOR of the
    word Nk positions back and the previous word; every Nk-th word is first
    transformed with RotWord, SubWord and a round constant.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes (128/192/256 bits)")
    nk = len(key) // 4                 # key length in 32-bit words: 4, 6, 8
    rounds = nk + 6                    # 10, 12, 14
    words = [list(key[4 * i: 4 * i + 4]) for i in range(nk)]

    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]             # RotWord: [a,b,c,d] -> [b,c,d,a]
            temp = [SBOX[b] for b in temp]          # SubWord
            temp[0] ^= RCON[i // nk]                # add round constant
        elif nk > 6 and i % nk == 4:                # extra SubWord, AES-256 only
            temp = [SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])

    # Group 4 words into one 16-byte round key.
    return [sum(words[4 * r: 4 * r + 4], []) for r in range(rounds + 1)]


# ---------------------------------------------------------------------------
# 4. The cipher
# ---------------------------------------------------------------------------

class AES:
    """Single-block AES. Combine it with a mode of operation (see modes.py)."""

    block_size = 16
    name = "AES"

    def __init__(self, key: bytes):
        self.key_bits = len(key) * 8
        self.round_keys = expand_key(key)
        self.rounds = len(self.round_keys) - 1
        # Round keys re-packed for the fast T-table path (section 5).
        self._enc_words, self._dec_words = _ttable_round_keys(self.round_keys)

    @staticmethod
    def _log(trace, rnd, step, state):
        if trace is not None:
            trace.append({"round": rnd, "step": step, "state": bytes(state)})

    def encrypt_block(self, block: bytes, trace=None) -> bytes:
        """Encrypt exactly 16 bytes. Pass a list as `trace` to record every step."""
        if len(block) != 16:
            raise ValueError("AES block must be exactly 16 bytes")
        if trace is None:
            return _fast_encrypt(self._enc_words, self.rounds, block)
        rk = self.round_keys
        state = list(block)
        self._log(trace, 0, "Input", state)

        state = add_round_key(state, rk[0])                 # initial whitening
        self._log(trace, 0, "AddRoundKey", state)

        for rnd in range(1, self.rounds):                   # main rounds
            state = sub_bytes(state)
            self._log(trace, rnd, "SubBytes", state)
            state = shift_rows(state)
            self._log(trace, rnd, "ShiftRows", state)
            state = mix_columns(state)
            self._log(trace, rnd, "MixColumns", state)
            state = add_round_key(state, rk[rnd])
            self._log(trace, rnd, "AddRoundKey", state)

        rnd = self.rounds                                   # final round: no MixColumns
        state = sub_bytes(state)
        self._log(trace, rnd, "SubBytes", state)
        state = shift_rows(state)
        self._log(trace, rnd, "ShiftRows", state)
        state = add_round_key(state, rk[rnd])
        self._log(trace, rnd, "AddRoundKey (output)", state)
        return bytes(state)

    def decrypt_block(self, block: bytes, trace=None) -> bytes:
        """Inverse cipher: the same steps, inverted, in reverse order."""
        if len(block) != 16:
            raise ValueError("AES block must be exactly 16 bytes")
        if trace is None:
            return _fast_decrypt(self._dec_words, self.rounds, block)
        rk = self.round_keys
        state = list(block)
        self._log(trace, self.rounds, "Input", state)

        state = add_round_key(state, rk[self.rounds])
        self._log(trace, self.rounds, "AddRoundKey", state)

        for rnd in range(self.rounds - 1, 0, -1):
            state = inv_shift_rows(state)
            self._log(trace, rnd, "InvShiftRows", state)
            state = inv_sub_bytes(state)
            self._log(trace, rnd, "InvSubBytes", state)
            state = add_round_key(state, rk[rnd])
            self._log(trace, rnd, "AddRoundKey", state)
            state = inv_mix_columns(state)
            self._log(trace, rnd, "InvMixColumns", state)

        state = inv_shift_rows(state)
        self._log(trace, 0, "InvShiftRows", state)
        state = inv_sub_bytes(state)
        self._log(trace, 0, "InvSubBytes", state)
        state = add_round_key(state, rk[0])
        self._log(trace, 0, "AddRoundKey (output)", state)
        return bytes(state)


# ---------------------------------------------------------------------------
# 5. Fast path: T-tables
#
# The step-by-step code above allocates a new list for every operation and is
# slow in Python (~200 KB/s). Encrypting a video that way takes minutes.
#
# Real software AES (e.g. older OpenSSL) uses "T-tables": for every byte value
# x we pre-compute the column that SubBytes + MixColumns would produce, so one
# round becomes 16 table lookups and some XORs on 32-bit words. ShiftRows is
# done "for free" by choosing which byte of which column to look up.
#
#     Te0[x] = column (2*S[x], S[x], S[x], 3*S[x])     (one MixColumns column)
#     Te1, Te2, Te3 = Te0 rotated by 1, 2, 3 bytes
#
# It is mathematically the SAME cipher: tests/test_crypto.py checks that both
# paths give identical output. The slow path is kept because it is the one
# you can read and trace in the Crypto Lab.
#
# Fun fact for your presentation: these secret-dependent table lookups are
# exactly what Bernstein's 2005 cache-timing attack exploited. That is one
# concrete reason "don't use home-made AES in production".
# ---------------------------------------------------------------------------

def _word(b0, b1, b2, b3):
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def _ror8(w):
    return ((w >> 8) | (w << 24)) & 0xFFFFFFFF


_TE0 = tuple(_word(MUL2[SBOX[x]], SBOX[x], SBOX[x], MUL3[SBOX[x]]) for x in range(256))
_TE1 = tuple(_ror8(w) for w in _TE0)
_TE2 = tuple(_ror8(w) for w in _TE1)
_TE3 = tuple(_ror8(w) for w in _TE2)

_TD0 = tuple(_word(MUL14[INV_SBOX[x]], MUL9[INV_SBOX[x]], MUL13[INV_SBOX[x]], MUL11[INV_SBOX[x]])
             for x in range(256))
_TD1 = tuple(_ror8(w) for w in _TD0)
_TD2 = tuple(_ror8(w) for w in _TD1)
_TD3 = tuple(_ror8(w) for w in _TD2)


def _to_words(sixteen):
    return [_word(*sixteen[4 * i: 4 * i + 4]) for i in range(4)]


def _ttable_round_keys(round_keys):
    enc = [_to_words(rk) for rk in round_keys]
    # "Equivalent inverse cipher" (FIPS-197 5.3.5): middle round keys get
    # InvMixColumns applied so decryption can use the same table trick.
    nr = len(round_keys) - 1
    dec = [_to_words(round_keys[nr])]
    for r in range(nr - 1, 0, -1):
        dec.append(_to_words(inv_mix_columns(round_keys[r])))
    dec.append(_to_words(round_keys[0]))
    return enc, dec


def _fast_encrypt(rk, rounds, block):
    te0, te1, te2, te3, sb = _TE0, _TE1, _TE2, _TE3, SBOX
    s0, s1, s2, s3 = (int.from_bytes(block[i:i + 4], "big") ^ k
                      for i, k in zip((0, 4, 8, 12), rk[0]))
    for r in range(1, rounds):
        k0, k1, k2, k3 = rk[r]
        s0, s1, s2, s3 = (
            te0[s0 >> 24] ^ te1[(s1 >> 16) & 255] ^ te2[(s2 >> 8) & 255] ^ te3[s3 & 255] ^ k0,
            te0[s1 >> 24] ^ te1[(s2 >> 16) & 255] ^ te2[(s3 >> 8) & 255] ^ te3[s0 & 255] ^ k1,
            te0[s2 >> 24] ^ te1[(s3 >> 16) & 255] ^ te2[(s0 >> 8) & 255] ^ te3[s1 & 255] ^ k2,
            te0[s3 >> 24] ^ te1[(s0 >> 16) & 255] ^ te2[(s1 >> 8) & 255] ^ te3[s2 & 255] ^ k3,
        )
    k0, k1, k2, k3 = rk[rounds]
    out = (
        _word(sb[s0 >> 24], sb[(s1 >> 16) & 255], sb[(s2 >> 8) & 255], sb[s3 & 255]) ^ k0,
        _word(sb[s1 >> 24], sb[(s2 >> 16) & 255], sb[(s3 >> 8) & 255], sb[s0 & 255]) ^ k1,
        _word(sb[s2 >> 24], sb[(s3 >> 16) & 255], sb[(s0 >> 8) & 255], sb[s1 & 255]) ^ k2,
        _word(sb[s3 >> 24], sb[(s0 >> 16) & 255], sb[(s1 >> 8) & 255], sb[s2 & 255]) ^ k3,
    )
    return b"".join(w.to_bytes(4, "big") for w in out)


def _fast_decrypt(dk, rounds, block):
    td0, td1, td2, td3, si = _TD0, _TD1, _TD2, _TD3, INV_SBOX
    s0, s1, s2, s3 = (int.from_bytes(block[i:i + 4], "big") ^ k
                      for i, k in zip((0, 4, 8, 12), dk[0]))
    for r in range(1, rounds):
        k0, k1, k2, k3 = dk[r]
        s0, s1, s2, s3 = (
            td0[s0 >> 24] ^ td1[(s3 >> 16) & 255] ^ td2[(s2 >> 8) & 255] ^ td3[s1 & 255] ^ k0,
            td0[s1 >> 24] ^ td1[(s0 >> 16) & 255] ^ td2[(s3 >> 8) & 255] ^ td3[s2 & 255] ^ k1,
            td0[s2 >> 24] ^ td1[(s1 >> 16) & 255] ^ td2[(s0 >> 8) & 255] ^ td3[s3 & 255] ^ k2,
            td0[s3 >> 24] ^ td1[(s2 >> 16) & 255] ^ td2[(s1 >> 8) & 255] ^ td3[s0 & 255] ^ k3,
        )
    k0, k1, k2, k3 = dk[rounds]
    out = (
        _word(si[s0 >> 24], si[(s3 >> 16) & 255], si[(s2 >> 8) & 255], si[s1 & 255]) ^ k0,
        _word(si[s1 >> 24], si[(s0 >> 16) & 255], si[(s3 >> 8) & 255], si[s2 & 255]) ^ k1,
        _word(si[s2 >> 24], si[(s1 >> 16) & 255], si[(s0 >> 8) & 255], si[s3 & 255]) ^ k2,
        _word(si[s3 >> 24], si[(s2 >> 16) & 255], si[(s1 >> 8) & 255], si[s0 & 255]) ^ k3,
    )
    return b"".join(w.to_bytes(4, "big") for w in out)
