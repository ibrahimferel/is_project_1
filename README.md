# SecureVault

A small Flask + SQLite web application for learning how cryptography is used in a real system: login with hashed passwords, encrypted personal data, encrypted file storage, and protection against the common web attacks. AES, DES and RC4 are implemented from scratch, and a built-in **Crypto Lab** shows them working step by step.

> **Educational project.** The ciphers are correct (they pass the official test vectors) but they are hand-written Python. Real systems should use audited libraries. Section 4.6 explains exactly why.

---

## 1. Running it

Requirements: Python 3.10+ and Flask (the only dependency).

```bash
pip install -r requirements.txt
python app.py                 # open http://127.0.0.1:8000
python -m unittest -v         # 42 tests: test vectors + attack simulations
python benchmark.py           # AES vs DES vs RC4 timing and ciphertext tables (Markdown)
```

The database (`instance/securevault.sqlite3`) and encrypted files (`instance/encrypted_files/`) are created on first start. Settings live in `config.py`; the most useful environment variables are:

| Variable | Default | Meaning |
|---|---|---|
| `SV_MAX_UPLOAD_MB` | 20 | Upload limit. Every file is encrypted with AES (~1.2 MB/s), DES (~0.7 MB/s) and RC4 (~8 MB/s), so 20 MB takes about 50 s. |
| `SV_PORT` | 8000 | Port to listen on. Not 5000: macOS AirPlay Receiver uses it and returns an empty page. |
| `SV_HTTPS` | 0 | Set to 1 behind HTTPS: enables the `Secure` cookie flag and `__Host-` cookie prefix. |
| `SV_PBKDF2_ITERATIONS` | 600000 | Password hashing work factor. |

## 2. Project structure

```
app.py                 routes, request pipeline, access control
config.py              settings
db.py                  SQLite schema and connection (parameterised queries only)
privacy.py             GDPR / UU PDP classification of every field, profile encryption
lab.py                 Crypto Lab pages (AES/DES/RC4 traces, ECB vs CBC, hashing vs encryption)
analysis.py            AES vs DES vs RC4: timing records, statistics, ciphertext breakdown
benchmark.py           the same comparison from the command line, for the report
crypto/
  aes.py               AES from scratch: GF(2^8) maths, S-box, 4 round operations, key expansion
  des.py               DES from scratch: Feistel network, S-boxes, key schedule
  rc4.py               RC4: KSA and PRGA
  modes.py             PKCS#7 padding, ECB and CBC modes (work with AES and DES)
  envelope.py          AES-CBC / DES-CBC / RC4 + HMAC-SHA256 (encrypt-then-MAC), key wrapping
  passwords.py         PBKDF2 password hashing and key derivation
security/
  sessions.py          server-side sessions and CSRF tokens
  uploads.py           upload allow-list and file-signature checks
templates/, static/    HTML (no JavaScript at all) and one CSS file
tests/                 test_crypto.py (known-answer tests), test_app.py (attack tests)
docs/benchmark-results.md   output of benchmark.py used in the report
```

## 3. How the system works

### 3.1 The key hierarchy (the central idea)

```
password ──PBKDF2 (salt A)──► password hash          stored, used only to CHECK the password
password ──PBKDF2 (salt B)──► KEK (key-encryption key)  never stored, exists only during login
random 256-bit DEK (data-encryption key) ──sealed with KEK──► wrapped_dek   stored
profile fields, files, file names ──sealed with DEK──► 3 ciphertexts (AES, DES, RC4)  stored
```

Each user has their own random DEK. It is stored only in encrypted ("wrapped") form, and the key that unwraps it is derived from the user's password. Consequences worth explaining:

* **Without the password, nobody can decrypt the user's data**, not even someone with full access to the database and disk. This is what makes the requirement "the user must authenticate before their data is decrypted" true cryptographically, not just by an `if` statement.
* Even if an access-control bug let Bob request Alice's file, the server would only hold Bob's DEK in his session, so decryption would fail.
* Changing a password would only need to re-wrap a 32-byte key, not re-encrypt every file (this is called envelope encryption, the same pattern cloud key-management services use).
* Trade-off: a forgotten password means lost data. The registration page says so.

### 3.2 Registration

1. Validate username (`[A-Za-z0-9_]{3,32}`) and password (10 to 128 characters, not equal to the username).
2. `password_hash = PBKDF2(password, random salt, 600000)`.
3. Generate a random DEK, derive the KEK from the password with a second salt, store `wrapped_dek = seal(KEK, DEK)`.

### 3.3 Login: User → Login → Password verification → Authentication → Data access

```
POST /login
  1. CSRF token check                         (all POST requests)
  2. SELECT user with a parameterised query
  3. verify_password() with constant-time compare
       unknown user -> verify against a dummy hash anyway (same timing, same message)
  4. KEK = PBKDF2(password, kek_salt); DEK = unwrap(KEK, wrapped_dek)
  5. Delete the old session, create a new one holding user_id + DEK (server memory only)
  6. Redirect to /dashboard
```

### 3.4 Storing and retrieving a file

Upload: check the category's extension allow-list and the file's real signature → generate a random 128-bit file ID → seal the file bytes three times with the DEK, once per cipher → write `instance/encrypted_files/<id>.aes.bin`, `<id>.des.bin` and `<id>.rc4.bin` → store the metadata (original name, type, size), also sealed with each cipher, in the `files` table (`meta_ciphertext`, `meta_des`, `meta_rc4`). Each encryption is timed and recorded in `timings`.

Download: the session must be logged in → the file ID must match `^[0-9a-f]{32}$` → `SELECT ... WHERE id = ? AND user_id = ?` → pick the copy from `?alg=aes|des|rc4` (AES by default) → verify the HMAC, decrypt with the session's DEK (timed) → send as an attachment.

## 4. Cryptography

### 4.1 AES (crypto/aes.py)

Everything is built from first principles. Bytes are elements of GF(2^8); `xtime`, `gf_mul` and `gf_inverse` implement that arithmetic, and the S-box is **computed** (inverse in GF(2^8) followed by the affine transform) rather than pasted as a table. The four round operations are separate, readable functions:

| Operation | What it does | Purpose |
|---|---|---|
| SubBytes | each byte → `SBOX[byte]` | the only non-linear step (confusion) |
| ShiftRows | row *r* rotated left by *r* | spreads bytes across columns |
| MixColumns | each column × fixed matrix in GF(2^8) | every output byte depends on all 4 input bytes (diffusion) |
| AddRoundKey | state XOR round key | mixes in the key; XOR is its own inverse |

`expand_key` produces 11/13/15 round keys for AES-128/192/256 using RotWord, SubWord and Rcon. Decryption applies the inverse operations in reverse order.

**Performance note.** The step-by-step version runs at about 200 KB/s. For file storage, `encrypt_block` switches to a T-table version (section 5 of `aes.py`) that precomputes SubBytes + ShiftRows + MixColumns per byte value, the same trick classic C implementations use. It is the same cipher, and `test_traced_and_fast_paths_agree` checks both paths give identical results on random inputs. The Crypto Lab always uses the readable path.

### 4.2 DES (crypto/des.py) — broken, used only for the required comparison copy

A 16-round Feistel network: `L_i = R_(i-1)`, `R_i = L_(i-1) XOR f(R_(i-1), K_i)`, with `f = P(S-boxes(E(R) XOR K))`. Decryption is the same function with the round keys reversed, so `f` never needs to be invertible. The final permutation is computed as the inverse of IP to rule out typos. DES is broken because its key is only 56 bits.

Like AES, DES has a readable bit-by-bit path (used by the lab trace) and a fast table path used for stored data: IP/FP as 8 byte-lookups, the E expansion as a 1-bit rotation, and S-boxes + P merged into 8 "SP" tables, all computed from the standard tables. The fast path is about 11x faster (0.06 → 0.7 MB/s) and a test checks both give identical output.

### 4.3 RC4 (crypto/rc4.py) — broken, used only for the required comparison copy

KSA shuffles `S = [0..255]` using the key; PRGA keeps swapping and outputs `S[(S[i] + S[j]) mod 256]` as keystream, which is XORed with the data. The lab demonstrates the classic failure: with a reused key, `C1 XOR C2 = P1 XOR P2`, so knowing one message reveals the other. For stored data each message therefore gets its own key, `HMAC(rc4_key, random nonce)`, and the first 1536 keystream bytes are discarded (RC4-drop1536, RFC 4345) because they are the most biased.

### 4.4 Modes of operation (crypto/modes.py)

* **ECB**: each block encrypted independently, so equal plaintext blocks give equal ciphertext blocks. The lab encrypts a picture of a padlock and the outline remains visible in the ECB version.
* **CBC**: each block is XORed with the previous ciphertext block before encryption, and the first with a random IV. Equal blocks no longer look equal, and the same file encrypted twice looks completely different.

Both modes work with AES (16-byte blocks) and DES (8-byte blocks). PKCS#7 padding fills the last block.

### 4.5 Authenticated encryption (crypto/envelope.py)

CBC alone gives confidentiality, not integrity: an attacker could flip bits or exploit padding errors (a padding-oracle attack). So every value is sealed as

```
version | IV/nonce | ciphertext | HMAC-SHA256(version | context | IV | ciphertext)

0x01  AES-256-CBC    16-byte IV     (the primary copy the app reads by default)
0x02  DES-CBC         8-byte IV
0x03  RC4-drop1536   16-byte nonce
```

The assignment requires all stored data to be encrypted with AES, RC4 and DES, so `seal_all` produces one sealed copy per cipher and all three are stored. Each copy decrypts on its own (the vault can show the profile from any copy, and every file can be downloaded from any copy). Block ciphers use CBC, never ECB.

* **Encrypt-then-MAC**: the tag is verified (constant-time) before any decryption happens.
* **Separate keys** for each cipher and for each cipher's HMAC, all derived from the DEK with HMAC. The version byte is inside the MAC, so a blob cannot be relabelled as another cipher.
* **Context binding**: the MAC includes a label such as `profile|user:7|field:nik`. A ciphertext copied into another field, record or user fails verification.
* One generic `DecryptionError` for every failure, so an attacker learns nothing about why.

SHA-256, HMAC and PBKDF2 come from Python's standard library (`hashlib`, `hmac`); the project implements the ciphers, not the hash functions. Random values come from `secrets`, the operating system's cryptographically secure generator, never from `random`.

### 4.6 Which algorithms are fit for real use

| Algorithm | Verdict | Used for |
|---|---|---|
| AES-256-CBC + HMAC-SHA256 | Modern construction (AES-GCM is the usual modern choice) | all stored data (primary copy) |
| PBKDF2-HMAC-SHA256, 600k iterations | Acceptable (Argon2id preferred for new systems) | passwords, KEK |
| SHA-256, HMAC-SHA256 | Modern | inside HMAC/PBKDF2 |
| AES-ECB | Insecure mode | lab only |
| DES-CBC + HMAC | Broken (56-bit key) | second copy of all stored data (assignment requirement), lab |
| 3DES | Deprecated (64-bit block, Sweet32) | not used |
| RC4-drop1536 + HMAC | Broken (biased keystream, RFC 7465) | third copy of all stored data (assignment requirement), lab |

**Why not use this AES in production?** Its output is correct, but: (1) table lookups indexed by secret bytes take different times depending on CPU cache state, the side channel exploited by Bernstein's 2005 cache-timing attack, and Python offers no way to make this constant-time; (2) Python cannot reliably erase keys from memory; (3) it is slow; (4) it has not been independently audited. Production code would use `cryptography`'s AES-GCM and `argon2-cffi`. Saying this clearly is part of a good security presentation, not a weakness of the project.

### 4.7 Comparing the three ciphers (analysis.py, benchmark.py)

The assignment asks to analyse the running time and the resulting ciphertext of each cipher, downloading the data several times.

* **In the app**: the **Analysis** page (`/analysis`, after login) shows, per cipher, every recorded encryption (at upload) and decryption (each download or vault view), with mean, standard deviation, min, max and MB/s, overall and per file. "Run benchmark" decrypts a chosen file N times (1-10) with each cipher in turn. It also breaks each copy of a file into IV, ciphertext, padding and HMAC overhead, shows the first ciphertext bytes and their entropy, and lists the stored size of every profile field per cipher.
* **From the command line**: `python benchmark.py [--runs N] [--file path]` prints the same comparison as Markdown tables on 1 KB / 100 KB / 1 MB of random data and 100 KB of repetitive text. The results used in the report are in `docs/benchmark-results.md`.

Only the cryptography (cipher + HMAC) is timed with `time.perf_counter()`; disk and network time are the same for every cipher and would hide the difference. Summary of the measurements (Apple Silicon, Python 3.9):

| | AES-256-CBC | DES-CBC | RC4-drop1536 |
|---|---|---|---|
| Speed (1 MB) | ~1.25 MB/s | ~0.70 MB/s (0.56x AES) | ~8 MB/s (6.3x AES) |
| IV / nonce | 16 B | 8 B | 16 B |
| Padding | 1-16 B | 1-8 B | none (length leaks exactly) |
| Stored overhead (version + IV + padding + HMAC) | 50-65 B | 42-49 B | always 49 B |
| Ciphertext entropy (100 KB text, plaintext 4.86) | 7.998 | 7.998 | 7.998 |

Why: RC4 does one swap and one XOR per byte. DES does 16 rounds on 8-byte blocks, so twice as many block operations per byte as AES (14 rounds on 16-byte blocks), and its bit permutations are costly in software. With AES-NI hardware instructions real AES is usually the fastest of the three, so the ranking reflects this pure-Python implementation. All three ciphertexts look random (entropy ≈ 8 bits/byte even for very repetitive input) and differ completely from each other and between two encryptions of the same value (random IV/nonce). Speed is not security: only AES is acceptable.

## 5. Password hashing vs encryption

| | Hashing (passwords) | Encryption (files, personal data) |
|---|---|---|
| Direction | one-way | reversible with the key |
| Why | the server only needs to check a password, never to read it | the user needs their data back |
| If the database leaks | attacker must guess passwords one by one, slowly | useless without the key |
| Key | none; a salt (public, random per user) | secret key |

PBKDF2 adds a random salt (so identical passwords have different hashes and precomputed tables are useless) and 600,000 iterations (so each guess is slow). The lab page *Hashing vs encryption* shows both side by side.

## 6. Privacy classification (GDPR and UU PDP)

All profile fields and all files are encrypted. `privacy.py` documents the classification of each, shown on the **Privacy** page:

| Data | GDPR | UU PDP (UU 27/2022) |
|---|---|---|
| Full name | personal data, Art. 4(1) | umum, Pasal 4(3)(a) |
| NIK | personal data; national ID numbers, Art. 87 | umum (identifying), Pasal 4(3)(f) |
| Date of birth | personal data | umum; can reveal data anak (spesifik, Pasal 4(2)(e)) |
| Phone, address | personal data | umum, Pasal 4(3)(f) |
| Religion | **special category**, Art. 9 | umum, Pasal 4(3)(d) |
| Health information | **special category**, Art. 9 | **spesifik**, Pasal 4(2)(a) |
| Bank account | personal data, high risk | **spesifik** (keuangan pribadi), Pasal 4(2)(f) |
| ID card image | many fields at once; face photo is biometric data when processed for identification (Art. 4(14), Recital 51) | biometrik is spesifik, Pasal 4(2)(b) |

Relevant obligations: GDPR Art. 5(1)(f) and Art. 32 (security of processing, naming encryption), Art. 34(3)(a) (encrypted data need not be notified to individuals after a breach); UU PDP Pasal 35 (controller must secure the data) and Pasal 46 (breach notification within 3 × 24 hours). Data minimisation (GDPR Art. 5(1)(c)) is why every field is optional. What is *not* encrypted (username, IDs, timestamps, approximate file size) is listed on the Privacy page too. This summary is for an educational project and is not legal advice.

## 7. Attacks and defences

Every row has a test in `tests/test_app.py` that performs the attack.

| Attack | Defence | Where |
|---|---|---|
| SQL injection | Every query uses `?` placeholders; SQL text and data are sent separately. No string-built SQL anywhere. | `db.py`, all `execute()` calls |
| Brute-force login | Slow PBKDF2 (600k iterations) per guess; same error message and timing for unknown users. No lockout (see section 8) | `app.py login()` |
| Session hijacking | 256-bit random session ID; `HttpOnly`, `SameSite=Strict`, `Secure` (with HTTPS); new ID at login and logout (anti-fixation); 15 min idle and 8 h absolute timeout; session data and DEK only in server memory | `security/sessions.py`, `app.py` |
| CSRF | Per-session secret token in every form, checked with a constant-time compare on every POST, including login; plus `SameSite=Strict` | `app.py load_session()` |
| XSS | Jinja2 auto-escaping of every value; the app uses no JavaScript; messages chosen from a fixed list, never echoed from the URL | templates |
| Insecure uploads | Category-based extension allow-list; magic-byte / ZIP-structure check; MIME type from our table, not the client; size limit; stored encrypted under a random name; always downloaded as an attachment | `security/uploads.py` |
| Path traversal | User filenames never touch the filesystem; file IDs must match `^[0-9a-f]{32}$`; resolved path must stay inside the storage folder | `app.py storage_path()` |
| Unauthorized file access / other users' files (IDOR) | `WHERE id = ? AND user_id = ?` on every file operation; 404 instead of 403 so file IDs cannot be probed; per-user keys make other users' files undecryptable anyway | `app.py owned_file_or_404()` |
| Tampering with stored data | HMAC verified before decryption; context binding blocks ciphertext swapping | `crypto/envelope.py` |

## 8. Known limitations (good material for the "future work" section)

* Sessions live in memory: a server restart logs everyone out, and the app must run as a single process.
* HTTPS is not provided by the app itself; in deployment it belongs in a reverse proxy (e.g. Nginx with Let's Encrypt). Without HTTPS, the session cookie can be stolen on the network.
* Behind a reverse proxy, `request.remote_addr` is the proxy's address; Werkzeug's `ProxyFix` would be needed for per-IP rate limiting.
* The registration form reveals whether a username is taken; there is no account recovery and no password-change page (envelope encryption would make one easy to add).
* Upload validation checks file structure but does not scan for macros or malware.
* There is no login rate limit or account lockout, and no security headers (CSP, HSTS, `nosniff`, `X-Frame-Options`, `Cache-Control: no-store`); both were left out to keep the project focused on the assignment and would be the first additions in production.
* Python cannot guarantee keys are wiped from memory.
* Keeping DES and RC4 copies (required by the assignment) adds weak ciphertexts next to the AES one. Each copy uses its own key derived from the DEK, so breaking the DES copy reveals that copy's data but not the DEK; still, a real system would store only the AES copy.
* The timings table reveals each file's exact size and when it was downloaded.

## 9. Suggested demo order

1. Register, log in, save a NIK, then open the SQLite file (e.g. with DB Browser for SQLite) to show only ciphertext.
2. Upload a KTP image; show the three random `.aes.bin` / `.des.bin` / `.rc4.bin` files on disk and that they are unreadable; download it from each copy.
3. Open **Analysis**, run a 5-round benchmark and explain the timing and ciphertext tables.
4. Log in as a second user and request the first user's file URL: 404.
5. Try `' OR '1'='1` as a username; enter a wrong password six times.
6. Crypto Lab: the AES rounds for the FIPS-197 example, then the ECB padlock picture.
7. Run `python -m unittest -v` and walk through the attack tests.
