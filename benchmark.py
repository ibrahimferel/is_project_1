"""
Command-line cipher comparison for the written report.

Encrypts and decrypts the same data with each cipher, exactly as the app
stores it (crypto/envelope.py: cipher + HMAC-SHA256), several times, and
prints Markdown tables of the running time and the resulting ciphertext.

    python benchmark.py                 # 1 KB, 100 KB, 1 MB; 5 runs each
    python benchmark.py --runs 10 --sizes 1024 1048576 --file my.pdf

The ciphers take turns inside each run (AES, DES, RC4, AES, ...) so that
background load on the machine affects all of them equally.
"""

import argparse
import os
import platform
import statistics
import sys
import time

from analysis import describe_blob, entropy
from crypto import envelope

CONTEXT = b"benchmark"


def human(n):
    return f"{n / 1048576:g} MB" if n >= 1048576 else f"{n / 1024:g} KB" if n >= 1024 else f"{n} B"


def measure(key, data, runs):
    """{alg: {"enc": [seconds...], "dec": [seconds...], "blob": last blob}}"""
    results = {alg: {"enc": [], "dec": []} for alg in envelope.ALGORITHMS}
    for _ in range(runs):
        for alg in envelope.ALGORITHMS:
            start = time.perf_counter()
            blob = envelope.seal(key, data, CONTEXT, alg)
            results[alg]["enc"].append(time.perf_counter() - start)
            start = time.perf_counter()
            if envelope.open_sealed(key, blob, CONTEXT) != data:
                sys.exit(f"{alg}: decryption did not return the original data")
            results[alg]["dec"].append(time.perf_counter() - start)
            results[alg]["blob"] = blob
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1024, 100 * 1024, 1024 * 1024],
                        help="sizes of random test data in bytes")
    parser.add_argument("--file", action="append", default=[], help="also measure a real file")
    args = parser.parse_args()

    key = envelope.generate_key()
    inputs = [(f"random, {human(n)}", os.urandom(n)) for n in args.sizes]
    # Low-entropy data like a real form or document, so the ciphertext's
    # randomness can be compared with a plaintext that has obvious structure.
    record = b"Nama: Budi Santoso | NIK: 3578012345678901 | Alamat: Jl. Merdeka 1, Surabaya\n"
    inputs.append(("repetitive text, 100 KB", (record * (102400 // len(record) + 1))[:102400]))
    for path in args.file:
        with open(path, "rb") as fh:
            inputs.append((f"{os.path.basename(path)}, {human(os.path.getsize(path))}", fh.read()))

    print(f"# Cipher comparison\n\nPython {platform.python_version()} on {platform.machine()} "
          f"({platform.system()}), {args.runs} runs per cipher and size. Times are mean ± standard deviation.\n")

    print("## Running time\n")
    print("| Data | Cipher | Encrypt (ms) | Decrypt (ms) | Decrypt speed | vs AES |")
    print("|---|---|---|---|---|---|")
    all_results = []
    for name, data in inputs:
        res = measure(key, data, args.runs)
        all_results.append((name, data, res))
        aes_speed = len(data) / statistics.mean(res["aes"]["dec"])
        for alg in envelope.ALGORITHMS:
            enc, dec = res[alg]["enc"], res[alg]["dec"]
            sd = lambda xs: statistics.stdev(xs) * 1000 if len(xs) > 1 else 0.0
            speed = len(data) / statistics.mean(dec)
            print(f"| {name} | {envelope.LABELS[alg]} | {statistics.mean(enc) * 1000:.2f} ± {sd(enc):.2f} "
                  f"| {statistics.mean(dec) * 1000:.2f} ± {sd(dec):.2f} | {speed / 1e6:.2f} MB/s "
                  f"| {speed / aes_speed:.2f}x |")

    print("\n## Resulting ciphertext\n")
    print("Stored = 1 version byte + IV/nonce + ciphertext + 32-byte HMAC tag. "
          "Entropy in bits per byte (8 = looks random; "
          "about 7.8 is the most 1 KB of data can show).\n")
    print("| Data | Cipher | Plaintext | Stored | IV | Padding | Overhead | Plaintext entropy "
          "| Ciphertext entropy | First ciphertext bytes |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for name, data, res in all_results:
        for alg in envelope.ALGORITHMS:
            blob = res[alg]["blob"]
            d = describe_blob(blob[:1024 * 1024 + 64], len(blob), len(data))
            print(f"| {name} | {d['label']} | {len(data)} | {d['stored']} | {d['iv_len']} | {d['padding']} "
                  f"| {d['overhead']} | {entropy(data[:1024 * 1024]):.4f} | {d['entropy']:.4f} "
                  f"| `{d['ct_head'][:32]}` |")

    # Same message twice with the same key: random IVs make the ciphertexts differ.
    msg = b"3578012345678901"
    print("\n## Same plaintext, same key, encrypted twice\n")
    print(f"Plaintext: `{msg.decode()}` (a 16-digit NIK)\n")
    print("| Cipher | Ciphertext 1 (IV + ciphertext) | Ciphertext 2 (IV + ciphertext) |")
    print("|---|---|---|")
    for alg in envelope.ALGORITHMS:
        one, two = (envelope.seal(key, msg, CONTEXT, alg)[1:-envelope.TAG_LEN].hex() for _ in range(2))
        print(f"| {envelope.LABELS[alg]} | `{one}` | `{two}` |")


if __name__ == "__main__":
    main()
