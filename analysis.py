"""
Comparing AES, DES and RC4 on the data the app really stores.

The assignment asks to "analyse the difference (running time, resulting
ciphertext) between each cipher" and to "download the data multiple times
and measure the running time". Every value is stored three times (one copy
per cipher, see crypto/envelope.py), so the app can measure all three:

  * every upload times the encryption with each cipher,
  * every download or vault view times the decryption with the chosen cipher,
  * the Analysis page can decrypt a file N times with each cipher in a row.

What is timed is ONLY the cryptography (seal / open_sealed: cipher + HMAC),
measured with time.perf_counter(). Disk, database and network time are left
out because they are the same for every cipher and would hide the difference.

The timings table stores the item, cipher, size and duration, never any
content. benchmark.py runs the same comparison on synthetic data from the
command line, for the written report.
"""

import math
import statistics
import time
from collections import Counter

from crypto import envelope


def seal_all_timed(dek: bytes, plaintext: bytes, context: bytes):
    """Seal with every cipher. Returns ({alg: blob}, {alg: seconds})."""
    blobs, seconds = {}, {}
    for alg in envelope.ALGORITHMS:
        start = time.perf_counter()
        blobs[alg] = envelope.seal(dek, plaintext, context, alg)
        seconds[alg] = time.perf_counter() - start
    return blobs, seconds


def open_timed(dek: bytes, blob: bytes, context: bytes):
    """Verify and decrypt one blob. Returns (plaintext, seconds)."""
    start = time.perf_counter()
    plaintext = envelope.open_sealed(dek, blob, context)
    return plaintext, time.perf_counter() - start


def record(conn, user_id, item, alg, op, nbytes, seconds):
    conn.execute("INSERT INTO timings (user_id, item, alg, op, bytes, seconds, created_at) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (user_id, item, alg, op, nbytes, seconds, time.time()))
    conn.commit()


def _summary(rows):
    """Statistics for a list of timing rows of one cipher."""
    if not rows:
        return None
    secs = [r["seconds"] for r in rows]
    total_bytes = sum(r["bytes"] for r in rows)
    return {
        "runs": len(rows),
        "mean_ms": statistics.mean(secs) * 1000,
        "min_ms": min(secs) * 1000,
        "max_ms": max(secs) * 1000,
        "stdev_ms": statistics.stdev(secs) * 1000 if len(secs) > 1 else 0.0,
        # Throughput over all runs together, so tiny values do not dominate.
        "mb_per_s": total_bytes / sum(secs) / 1e6 if sum(secs) > 0 else 0.0,
        "bytes": total_bytes,
    }


def timing_report(conn, user_id):
    """Statistics per cipher overall, and per item (file or profile)."""
    rows = conn.execute("SELECT item, alg, op, bytes, seconds FROM timings WHERE user_id = ?",
                        (user_id,)).fetchall()
    overall = {}
    for op in ("encrypt", "decrypt"):
        overall[op] = {alg: _summary([r for r in rows if r["op"] == op and r["alg"] == alg])
                       for alg in envelope.ALGORITHMS}
    # Speed relative to AES (how many times faster than AES; >1 = faster).
    for op, per_alg in overall.items():
        base = per_alg["aes"]
        for s in per_alg.values():
            if s and base and base["mb_per_s"]:
                s["vs_aes"] = s["mb_per_s"] / base["mb_per_s"]
    per_item = {}
    for item in {r["item"] for r in rows}:
        per_item[item] = {op: {alg: _summary([r for r in rows if r["item"] == item
                                              and r["op"] == op and r["alg"] == alg])
                               for alg in envelope.ALGORITHMS}
                          for op in ("encrypt", "decrypt")}
    return overall, per_item


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: 8.0 means indistinguishable from random bytes."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def describe_blob(head: bytes, stored_len: int, plaintext_len: int):
    """Break a sealed blob into its parts and measure it.

    `head` is the start of the blob (all of it, or the first MB of a large
    file so the page does not read 3 x 20 MB on every view).
    """
    alg = envelope.algorithm_of(head)
    iv_len = envelope.iv_length(alg)
    ct_len = stored_len - 1 - iv_len - envelope.TAG_LEN
    body = head[1 + iv_len:1 + iv_len + ct_len]
    return {
        "alg": alg,
        "label": envelope.LABELS[alg],
        "stored": stored_len,
        "iv_len": iv_len,
        "ct_len": ct_len,
        "padding": ct_len - plaintext_len,
        "overhead": stored_len - plaintext_len,
        "iv_hex": head[1:1 + iv_len].hex(),
        "ct_head": body[:24].hex(),
        "entropy": entropy(body),
        "sampled": len(body) < ct_len,
    }
