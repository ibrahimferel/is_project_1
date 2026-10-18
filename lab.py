"""
Crypto Lab: pages that show the algorithms working step by step.

Nothing here touches user data. Every key is either typed in by you or freshly
random, so you can experiment safely. DES and RC4 appear ONLY here, never in
the storage path of the application.
"""

import base64
import hashlib
import secrets
import time

from flask import Blueprint, current_app, render_template, request

from crypto.aes import AES
from crypto.des import DES
from crypto.modes import cbc_decrypt, cbc_encrypt, ecb_encrypt, pkcs7_pad, pkcs7_unpad
from crypto.rc4 import ksa, prga

bp = Blueprint("lab", __name__, url_prefix="/lab")


def parse_hex(text: str, allowed_lengths, what: str) -> bytes:
    cleaned = "".join(text.split())
    try:
        value = bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError(f"{what}: use hexadecimal characters 0-9 and a-f only.") from None
    if len(value) not in allowed_lengths:
        bits = " or ".join(str(n * 8) for n in sorted(allowed_lengths))
        raise ValueError(f"{what} must be {bits} bits ({' / '.join(str(n * 2) for n in sorted(allowed_lengths))} hex digits).")
    return value


@bp.app_template_filter("matrix")
def state_matrix(state: bytes):
    """16 bytes -> 4 rows of 4 hex strings, laid out column by column like FIPS-197."""
    return [[f"{state[r + 4 * c]:02x}" for c in range(4)] for r in range(4)]


@bp.app_template_filter("hex32")
def hex32(value):
    return f"{value:08x}"


@bp.app_template_filter("hex48")
def hex48(value):
    return f"{value:012x}"


@bp.get("/")
def index():
    return render_template("lab/index.html")


# --------------------------------------------------------------------- AES

AES_DEFAULT_KEY = "000102030405060708090a0b0c0d0e0f"
AES_DEFAULT_PT = "00112233445566778899aabbccddeeff"   # FIPS-197 Appendix C.1


@bp.route("/aes", methods=["GET", "POST"])
def aes_lab():
    key_hex = request.form.get("key", AES_DEFAULT_KEY)[:200]
    pt_hex = request.form.get("plaintext", AES_DEFAULT_PT)[:200]
    result, error = None, None
    if request.method == "POST":
        try:
            key = parse_hex(key_hex, {16, 24, 32}, "Key")
            pt = parse_hex(pt_hex, {16}, "Plaintext block")
        except ValueError as e:
            error = str(e)
        else:
            cipher = AES(key)
            enc_trace, dec_trace = [], []
            ct = cipher.encrypt_block(pt, enc_trace)
            back = cipher.decrypt_block(ct, dec_trace)
            result = {"ct": ct.hex(), "back": back.hex(), "rounds": cipher.rounds,
                      "key_bits": cipher.key_bits,
                      "round_keys": [bytes(rk) for rk in cipher.round_keys],
                      "enc_trace": enc_trace, "dec_trace": dec_trace}
    return render_template("lab/aes.html", key_hex=key_hex, pt_hex=pt_hex, result=result, error=error)


# --------------------------------------------------------------------- DES

DES_DEFAULT_KEY = "133457799BBCDFF1"
DES_DEFAULT_PT = "0123456789ABCDEF"     # classic textbook example -> 85E813540F0AB405


@bp.route("/des", methods=["GET", "POST"])
def des_lab():
    key_hex = request.form.get("key", DES_DEFAULT_KEY)[:100]
    pt_hex = request.form.get("plaintext", DES_DEFAULT_PT)[:100]
    result, error = None, None
    if request.method == "POST":
        try:
            key = parse_hex(key_hex, {8}, "Key")
            pt = parse_hex(pt_hex, {8}, "Plaintext block")
        except ValueError as e:
            error = str(e)
        else:
            cipher = DES(key)
            enc_trace, dec_trace = [], []
            ct = cipher.encrypt_block(pt, enc_trace)
            back = cipher.decrypt_block(ct, dec_trace)
            result = {"ct": ct.hex(), "back": back.hex(), "subkeys": cipher.round_keys,
                      "enc_trace": enc_trace, "dec_trace": dec_trace}
    return render_template("lab/des.html", key_hex=key_hex, pt_hex=pt_hex, result=result, error=error)


# --------------------------------------------------------------------- RC4

@bp.route("/rc4", methods=["GET", "POST"])
def rc4_lab():
    key_text = request.form.get("key", "Secret")[:64]
    msg1 = request.form.get("msg1", "Transfer 100 to Budi")[:200]
    msg2 = request.form.get("msg2", "Meeting moved to 3pm")[:200]
    result, error = None, None
    if request.method == "POST":
        if not key_text:
            error = "Enter a key."
        else:
            key = key_text.encode()
            p1, p2 = msg1.encode(), msg2.encode()
            s = ksa(key)
            ks = prga(s, max(len(p1), len(p2)))
            c1 = bytes(a ^ b for a, b in zip(p1, ks))
            c2 = bytes(a ^ b for a, b in zip(p2, ks))
            n = min(len(c1), len(c2))
            c_xor = bytes(a ^ b for a, b in zip(c1[:n], c2[:n]))
            p_xor = bytes(a ^ b for a, b in zip(p1[:n], p2[:n]))
            # Attacker knows (or guesses) message 1 and both ciphertexts, but NOT the key:
            recovered = bytes(c ^ p for c, p in zip(c_xor, p1[:n]))
            result = {"s_rows": [s[i:i + 16] for i in range(0, 256, 16)],
                      "keystream": ks.hex(), "c1": c1.hex(), "c2": c2.hex(),
                      "c_xor": c_xor.hex(), "p_xor": p_xor.hex(),
                      "xor_equal": c_xor == p_xor,
                      "recovered": recovered.decode("utf-8", "replace")}
    return render_template("lab/rc4.html", key_text=key_text, msg1=msg1, msg2=msg2,
                           result=result, error=error)


# ----------------------------------------------------------- ECB vs CBC

def _demo_bitmap(width=128, height=128):
    """Draw a simple padlock with a few flat colours and return 24-bit BGR pixels."""
    rows = []
    for y in range(height - 1, -1, -1):          # BMP stores the bottom row first
        row = bytearray()
        for x in range(width):
            colour = (225, 228, 232)                                     # background
            dx, dy = x - 64, y - 58
            ring = dx * dx + dy * dy
            if y <= 58 and 16 * 16 <= ring <= 27 * 27:
                colour = (110, 110, 120)                                 # shackle
            if 34 <= x <= 94 and 58 <= y <= 112:
                colour = (40, 70, 150)                                   # body
                kx, ky = x - 64, y - 78
                if kx * kx + ky * ky <= 49 or (61 <= x <= 67 and 78 <= y <= 98):
                    colour = (240, 200, 40)                              # keyhole
            r, gr, b = colour
            row += bytes((b, gr, r))
        rows.append(bytes(row))
    return b"".join(rows)


def _bmp(width, height, pixels):
    """Wrap raw 24-bit pixels in a minimal BMP header (row size here is a multiple of 4)."""
    header = (b"BM" + (54 + len(pixels)).to_bytes(4, "little") + b"\0\0\0\0"
              + (54).to_bytes(4, "little") + (40).to_bytes(4, "little")
              + width.to_bytes(4, "little") + height.to_bytes(4, "little")
              + (1).to_bytes(2, "little") + (24).to_bytes(2, "little")
              + b"\0" * 4 + len(pixels).to_bytes(4, "little") + b"\0" * 16)
    return "data:image/bmp;base64," + base64.b64encode(header + pixels).decode()


@bp.route("/modes", methods=["GET", "POST"])
def modes_lab():
    text = request.form.get("text", "ATTACK AT DAWN!!" * 3 + "RETREAT AT DUSK!")[:256]
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    cipher = AES(key)

    # 1. The image demo: only the pixel bytes are encrypted, the header is kept
    #    so the browser can still display the result.
    pixels = _demo_bitmap()                    # 128*128*3 = 49152 bytes = 3072 AES blocks
    images = {"plain": _bmp(128, 128, pixels),
              "ecb": _bmp(128, 128, ecb_encrypt(cipher, pixels)),
              "cbc": _bmp(128, 128, cbc_encrypt(cipher, pixels, iv))}

    # 2. The text demo: show each 16-byte block side by side.
    data = pkcs7_pad(text.encode(), 16)
    ecb = ecb_encrypt(cipher, data)
    cbc = cbc_encrypt(cipher, data, iv)
    assert pkcs7_unpad(cbc_decrypt(cipher, cbc, iv), 16) == text.encode()
    seen, blocks = {}, []
    for i in range(0, len(data), 16):
        e = ecb[i:i + 16].hex()
        seen[e] = seen.get(e, 0) + 1
        blocks.append({"index": i // 16, "plain": data[i:i + 16].decode("latin-1"),
                       "ecb": e, "cbc": cbc[i:i + 16].hex()})
    for b in blocks:
        b["repeated"] = seen[b["ecb"]] > 1
    return render_template("lab/modes.html", text=text, key=key.hex(), iv=iv.hex(),
                           images=images, blocks=blocks)


# ------------------------------------------------- hashing vs encryption

@bp.route("/hashing", methods=["GET", "POST"])
def hashing_lab():
    secret = request.form.get("secret", "correct horse battery staple")[:128]
    result = None
    if request.method == "POST":
        iterations = current_app.config["PBKDF2_ITERATIONS"]
        raw = secret.encode()

        sha = hashlib.sha256(raw).hexdigest()

        salts = [secrets.token_bytes(16), secrets.token_bytes(16)]
        t = time.perf_counter()
        pbkdf = [hashlib.pbkdf2_hmac("sha256", raw, s, iterations).hex() for s in salts]
        pbkdf_ms = (time.perf_counter() - t) * 1000 / 2

        key, iv = secrets.token_bytes(32), secrets.token_bytes(16)
        ct = cbc_encrypt(AES(key), pkcs7_pad(raw, 16), iv)
        back = pkcs7_unpad(cbc_decrypt(AES(key), ct, iv), 16).decode()

        result = {"sha": sha, "salts": [s.hex() for s in salts],
                  "pbkdf": pbkdf, "pbkdf_ms": pbkdf_ms, "iterations": iterations,
                  "key": key.hex(), "iv": iv.hex(), "ct": ct.hex(), "back": back}
    return render_template("lab/hashing.html", secret=secret, result=result)
