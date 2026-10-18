# SecureVault

A small Flask + SQLite web application for learning how cryptography is used in a real system: login with hashed passwords, encrypted personal data, encrypted file storage, and protection against the common web attacks. AES, DES and RC4 are implemented from scratch, and a built-in **Crypto Lab** shows them working step by step.

> **Educational project.** The ciphers are correct (they pass the official test vectors) but they are hand-written Python. Real systems should use audited libraries. Section 4.6 explains exactly why.

---

## 1. Running it

Requirements: Python 3.10+ and Flask (the only dependency).

```bash
pip install -r requirements.txt
python app.py                 # open http://127.0.0.1:5000
python -m unittest -v         # 37 tests: test vectors + attack simulations
```

The database (`instance/securevault.sqlite3`) and encrypted files (`instance/encrypted_files/`) are created on first start. Settings live in `config.py`; the most useful environment variables are:

| Variable | Default | Meaning |
|---|---|---|
| `SV_MAX_UPLOAD_MB` | 20 | Upload limit. Pure-Python AES encrypts about 0.75 MB/s, so 20 MB takes about 25 s. |
| `SV_HTTPS` | 0 | Set to 1 behind HTTPS: enables the `Secure` cookie flag, `__Host-` cookie prefix and HSTS. |
| `SV_PBKDF2_ITERATIONS` | 600000 | Password hashing work factor. |

## 2. Project structure

```
app.py                 routes, request pipeline, access control
config.py              settings
db.py                  SQLite schema and connection (parameterised queries only)
privacy.py             GDPR / UU PDP classification of every field, profile encryption
lab.py                 Crypto Lab pages (AES/DES/RC4 traces, ECB vs CBC, hashing vs encryption)
crypto/
  aes.py               AES from scratch: GF(2^8) maths, S-box, 4 round operations, key expansion
  des.py               DES from scratch: Feistel network, S-boxes, key schedule
  rc4.py               RC4: KSA and PRGA
  modes.py             PKCS#7 padding, ECB and CBC modes (work with AES and DES)
  envelope.py          AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC), key wrapping
  passwords.py         PBKDF2 password hashing and key derivation
security/
  sessions.py          server-side sessions and CSRF tokens
  ratelimit.py         brute-force protection
  uploads.py           upload allow-list and file-signature checks
  headers.py           Content-Security-Policy and other security headers
templates/, static/    HTML (no JavaScript at all) and one CSS file
tests/                 test_crypto.py (known-answer tests), test_app.py (attack tests)
```

## 3. How the system works

### 3.1 The key hierarchy (the central idea)

```
password ──PBKDF2 (salt A)──► password hash          stored, used only to CHECK the password
password ──PBKDF2 (salt B)──► KEK (key-encryption key)  never stored, exists only during login
random 256-bit DEK (data-encryption key) ──sealed with KEK──► wrapped_dek   stored
profile fields, files, file names ──sealed with DEK──► ciphertext          stored
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
  2. Brute-force check: too many failures?    -> HTTP 429
  3. SELECT user with a parameterised query
  4. verify_password() with constant-time compare
       unknown user -> verify against a dummy hash anyway (same timing, same message)
  5. KEK = PBKDF2(password, kek_salt); DEK = unwrap(KEK, wrapped_dek)
  6. Delete the old session, create a new one holding user_id + DEK (server memory only)
  7. Redirect to /dashboard
```

### 3.4 Storing and retrieving a file

Upload: check the category's extension allow-list and the file's real signature → generate a random 128-bit file ID → `seal(DEK, file bytes)` → write to `instance/encrypted_files/<id>.bin` → store the encrypted metadata (original name, type, size) in the `files` table.

Download: the session must be logged in → the file ID must match `^[0-9a-f]{32}$` → `SELECT ... WHERE id = ? AND user_id = ?` → verify the HMAC, decrypt with the session's DEK → send as an attachment.

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

### 4.2 DES (crypto/des.py) — educational only

A 16-round Feistel network: `L_i = R_(i-1)`, `R_i = L_(i-1) XOR f(R_(i-1), K_i)`, with `f = P(S-boxes(E(R) XOR K))`. Decryption is the same function with the round keys reversed, so `f` never needs to be invertible. The final permutation is computed as the inverse of IP to rule out typos. DES is broken because its key is only 56 bits.

### 4.3 RC4 (crypto/rc4.py) — educational only

KSA shuffles `S = [0..255]` using the key; PRGA keeps swapping and outputs `S[(S[i] + S[j]) mod 256]` as keystream, which is XORed with the data. The lab demonstrates the classic failure: with a reused key, `C1 XOR C2 = P1 XOR P2`, so knowing one message reveals the other.

### 4.4 Modes of operation (crypto/modes.py)

* **ECB**: each block encrypted independently, so equal plaintext blocks give equal ciphertext blocks. The lab encrypts a picture of a padlock and the outline remains visible in the ECB version.
* **CBC**: each block is XORed with the previous ciphertext block before encryption, and the first with a random IV. Equal blocks no longer look equal, and the same file encrypted twice looks completely different.

Both modes work with AES (16-byte blocks) and DES (8-byte blocks). PKCS#7 padding fills the last block.

### 4.5 Authenticated encryption (crypto/envelope.py)

CBC alone gives confidentiality, not integrity: an attacker could flip bits or exploit padding errors (a padding-oracle attack). So every value is sealed as

```
version | IV | AES-256-CBC ciphertext | HMAC-SHA256(version | context | IV | ciphertext)
```

* **Encrypt-then-MAC**: the tag is verified (constant-time) before any decryption happens.
* **Separate keys** for AES and HMAC, both derived from the DEK with HMAC.
* **Context binding**: the MAC includes a label such as `profile|user:7|field:nik`. A ciphertext copied into another field, record or user fails verification.
* One generic `DecryptionError` for every failure, so an attacker learns nothing about why.

SHA-256, HMAC and PBKDF2 come from Python's standard library (`hashlib`, `hmac`); the project implements the ciphers, not the hash functions. Random values come from `secrets`, the operating system's cryptographically secure generator, never from `random`.

### 4.6 Which algorithms are fit for real use

| Algorithm | Verdict | Used for |
|---|---|---|
| AES-256-CBC + HMAC-SHA256 | Modern construction (AES-GCM is the usual modern choice) | all stored data |
| PBKDF2-HMAC-SHA256, 600k iterations | Acceptable (Argon2id preferred for new systems) | passwords, KEK |
| SHA-256, HMAC-SHA256 | Modern | inside HMAC/PBKDF2 |
| AES-ECB | Insecure mode | lab only |
| DES | Broken (56-bit key) | lab only |
| 3DES | Deprecated (64-bit block, Sweet32) | not used |
| RC4 | Broken (biased keystream, RFC 7465) | lab only |

**Why not use this AES in production?** Its output is correct, but: (1) table lookups indexed by secret bytes take different times depending on CPU cache state, the side channel exploited by Bernstein's 2005 cache-timing attack, and Python offers no way to make this constant-time; (2) Python cannot reliably erase keys from memory; (3) it is slow; (4) it has not been independently audited. Production code would use `cryptography`'s AES-GCM and `argon2-cffi`. Saying this clearly is part of a good security presentation, not a weakness of the project.

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
| Brute-force login | Max 5 failures per username and 20 per IP in 15 minutes (HTTP 429); slow PBKDF2; same error message and timing for unknown users | `security/ratelimit.py`, `app.py login()` |
| Session hijacking | 256-bit random session ID; `HttpOnly`, `SameSite=Strict`, `Secure` (with HTTPS); new ID at login and logout (anti-fixation); 15 min idle and 8 h absolute timeout; session data and DEK only in server memory | `security/sessions.py`, `app.py` |
| CSRF | Per-session secret token in every form, checked with a constant-time compare on every POST, including login; plus `SameSite=Strict` | `app.py load_session()` |
| XSS | Jinja2 auto-escaping of every value; CSP `script-src 'none'` (the app uses no JavaScript); messages chosen from a fixed list, never echoed from the URL | templates, `security/headers.py` |
| Insecure uploads | Category-based extension allow-list; magic-byte / ZIP-structure check; MIME type from our table, not the client; size limit; stored encrypted under a random name; always downloaded as an attachment with `nosniff` | `security/uploads.py` |
| Path traversal | User filenames never touch the filesystem; file IDs must match `^[0-9a-f]{32}$`; resolved path must stay inside the storage folder | `app.py storage_path()` |
| Unauthorized file access / other users' files (IDOR) | `WHERE id = ? AND user_id = ?` on every file operation; 404 instead of 403 so file IDs cannot be probed; per-user keys make other users' files undecryptable anyway | `app.py owned_file_or_404()` |
| Tampering with stored data | HMAC verified before decryption; context binding blocks ciphertext swapping | `crypto/envelope.py` |
| Clickjacking, caching of personal data | `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Cache-Control: no-store` | `security/headers.py` |

## 8. Known limitations (good material for the "future work" section)

* Sessions live in memory: a server restart logs everyone out, and the app must run as a single process.
* HTTPS is not provided by the app itself; in deployment it belongs in a reverse proxy (e.g. Nginx with Let's Encrypt). Without HTTPS, the session cookie can be stolen on the network.
* Behind a reverse proxy, `request.remote_addr` is the proxy's address; Werkzeug's `ProxyFix` would be needed for per-IP rate limiting.
* The registration form reveals whether a username is taken; there is no account recovery and no password-change page (envelope encryption would make one easy to add).
* Upload validation checks file structure but does not scan for macros or malware.
* Account lockout can be abused to lock someone out temporarily.
* Python cannot guarantee keys are wiped from memory.

## 9. Suggested demo order

1. Register, log in, save a NIK, then open the SQLite file (e.g. with DB Browser for SQLite) to show only ciphertext.
2. Upload a KTP image; show the random `.bin` name on disk and that the file is unreadable.
3. Log in as a second user and request the first user's file URL: 404.
4. Try `' OR '1'='1` as a username; enter a wrong password six times.
5. Crypto Lab: the AES rounds for the FIPS-197 example, then the ECB padlock picture.
6. Run `python -m unittest -v` and walk through the attack tests.
