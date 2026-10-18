# Cipher comparison

Python 3.9.6 on arm64 (Darwin), 5 runs per cipher and size. Times are mean ± standard deviation.

## Running time

| Data | Cipher | Encrypt (ms) | Decrypt (ms) | Decrypt speed | vs AES |
|---|---|---|---|---|---|
| random, 1 KB | AES-256-CBC | 0.90 ± 0.02 | 0.90 ± 0.01 | 1.14 MB/s | 1.00x |
| random, 1 KB | DES-CBC | 1.56 ± 0.02 | 1.54 ± 0.01 | 0.67 MB/s | 0.59x |
| random, 1 KB | RC4-drop1536 | 0.36 ± 0.01 | 0.35 ± 0.01 | 2.89 MB/s | 2.54x |
| random, 100 KB | AES-256-CBC | 81.74 ± 5.03 | 84.45 ± 8.80 | 1.21 MB/s | 1.00x |
| random, 100 KB | DES-CBC | 144.53 ± 2.41 | 143.50 ± 0.98 | 0.71 MB/s | 0.59x |
| random, 100 KB | RC4-drop1536 | 13.73 ± 1.72 | 13.15 ± 0.63 | 7.79 MB/s | 6.42x |
| random, 1 MB | AES-256-CBC | 828.85 ± 21.68 | 832.90 ± 24.81 | 1.26 MB/s | 1.00x |
| random, 1 MB | DES-CBC | 1487.47 ± 42.59 | 1503.44 ± 49.03 | 0.70 MB/s | 0.55x |
| random, 1 MB | RC4-drop1536 | 132.75 ± 3.72 | 131.72 ± 1.72 | 7.96 MB/s | 6.32x |
| repetitive text, 100 KB | AES-256-CBC | 79.92 ± 1.73 | 80.28 ± 2.01 | 1.28 MB/s | 1.00x |
| repetitive text, 100 KB | DES-CBC | 145.89 ± 1.89 | 144.94 ± 2.79 | 0.71 MB/s | 0.55x |
| repetitive text, 100 KB | RC4-drop1536 | 13.14 ± 0.32 | 13.25 ± 0.38 | 7.73 MB/s | 6.06x |

## Resulting ciphertext

Stored = 1 version byte + IV/nonce + ciphertext + 32-byte HMAC tag. Entropy in bits per byte (8 = looks random; about 7.8 is the most 1 KB of data can show).

| Data | Cipher | Plaintext | Stored | IV | Padding | Overhead | Plaintext entropy | Ciphertext entropy | First ciphertext bytes |
|---|---|---|---|---|---|---|---|---|---|
| random, 1 KB | AES-256-CBC | 1024 | 1089 | 16 | 16 | 65 | 7.7825 | 7.8197 | `ff2599c247722a9a1f5860fa56a5819a` |
| random, 1 KB | DES-CBC | 1024 | 1073 | 8 | 8 | 49 | 7.7825 | 7.8086 | `b3f3853dc3ca5af02a799e0b690ec675` |
| random, 1 KB | RC4-drop1536 | 1024 | 1073 | 16 | 0 | 49 | 7.7825 | 7.8365 | `3f69df57592e179a37889e41f38b5bab` |
| random, 100 KB | AES-256-CBC | 102400 | 102465 | 16 | 16 | 65 | 7.9984 | 7.9983 | `c6a5d98678c31346797df7ddcb852c79` |
| random, 100 KB | DES-CBC | 102400 | 102449 | 8 | 8 | 49 | 7.9984 | 7.9983 | `a2f76f1db3b549b686ebee56a2533b7c` |
| random, 100 KB | RC4-drop1536 | 102400 | 102449 | 16 | 0 | 49 | 7.9984 | 7.9982 | `526f0a0f005df2444d3b33431318b2b9` |
| random, 1 MB | AES-256-CBC | 1048576 | 1048641 | 16 | 16 | 65 | 7.9998 | 7.9998 | `1317235e26f66e53b6f951286829e248` |
| random, 1 MB | DES-CBC | 1048576 | 1048625 | 8 | 8 | 49 | 7.9998 | 7.9998 | `654f11b6926fef15010b8f37146b409e` |
| random, 1 MB | RC4-drop1536 | 1048576 | 1048625 | 16 | 0 | 49 | 7.9998 | 7.9998 | `68f9893405680973891f32e3dceb8a73` |
| repetitive text, 100 KB | AES-256-CBC | 102400 | 102465 | 16 | 16 | 65 | 4.8630 | 7.9982 | `cbed47aa7380700627a315c0316f8698` |
| repetitive text, 100 KB | DES-CBC | 102400 | 102449 | 8 | 8 | 49 | 4.8630 | 7.9984 | `8386c3797d94e244f7433a644be750ab` |
| repetitive text, 100 KB | RC4-drop1536 | 102400 | 102449 | 16 | 0 | 49 | 4.8630 | 7.9980 | `8e6570a7eab9c8db278c8f05ac700d7c` |

## Same plaintext, same key, encrypted twice

Plaintext: `3578012345678901` (a 16-digit NIK)

| Cipher | Ciphertext 1 (IV + ciphertext) | Ciphertext 2 (IV + ciphertext) |
|---|---|---|
| AES-256-CBC | `c652726dab6a58506f91cfc06afe7e4e8f6c5ac1f4a9c663f83873fd493eb7568c3ee98be26ce699990eff8510089699` | `732c2b349d5eaf7199650ed7d4913fb88cce6e85aed0820657694201e611f66361a600c54d7ea60673b3805b033dd3aa` |
| DES-CBC | `b4ba186bd5b17b81670fb1ca4456f8a15c3d6d2a7b7791a731c59cf6c1ba2bc0` | `21d8d23b1bb52897dfdcfac03c8e9b955a11abaf9b41ff4e947d3d0812f3fb75` |
| RC4-drop1536 | `793024c78f8f1d112e68c419fd8a9498f1838d5ca2878e1deba23a467d2e6b89` | `940f854598469e40f321d180336727b78eff9513ae39949b54b7c6dea4354fc0` |
