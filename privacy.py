"""
Which user data is personal data, and why we encrypt it.

Legal references (summarised for an educational project, not legal advice):

GDPR (EU Regulation 2016/679)
  * Art. 4(1)  "personal data": any information relating to an identified or
               identifiable natural person.
  * Art. 9     special categories: racial/ethnic origin, political opinions,
               religious or philosophical beliefs, trade-union membership,
               genetic data, biometric data used to identify a person,
               health data, sex life or sexual orientation.
  * Art. 10    criminal convictions and offences.
  * Art. 87    national identification numbers.
  * Art. 5(1)(c) data minimisation, 5(1)(f) integrity and confidentiality.
  * Art. 32    security of processing, naming encryption as an example measure.
  * Art. 34(3)(a) a breach need not be communicated to the affected people if
               the data was rendered unintelligible, e.g. by encryption.

UU PDP (Indonesia, UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi)
  * Pasal 4(2) data pribadi yang bersifat SPESIFIK: kesehatan, biometrik,
               genetika, catatan kejahatan, data anak, keuangan pribadi,
               and other data defined by law.
  * Pasal 4(3) data pribadi yang bersifat UMUM: nama lengkap, jenis kelamin,
               kewarganegaraan, agama, status perkawinan, and data that can be
               combined to identify a person.
  * Pasal 35   the controller must protect and ensure the security of the
               personal data it processes (technical and operational measures).
  * Pasal 46   data breaches must be notified (within 3 x 24 hours).

Interesting difference for your presentation: religion is a SPECIAL category
under GDPR Art. 9 but a GENERAL category under UU PDP Pasal 4(3). This app
treats it as sensitive and encrypts it either way.

Design decision: every field below is encrypted with the user's own key,
once with each cipher (AES, DES and RC4), as the assignment requires.
Classification is still important because it tells you what MUST be
protected, what needs extra care (consent, minimisation), and what to report
if a breach happens.
"""

import re
from datetime import date

import analysis
from crypto import envelope

# Column holding each cipher's copy of a field (constants, safe to put in SQL).
COLUMNS = {"aes": "ciphertext", "des": "ciphertext_des", "rc4": "ciphertext_rc4"}

# Each field: key, label, HTML input type, max length, and its classification.
FIELDS = [
    {
        "key": "full_name", "label": "Full name", "input": "text", "max": 100,
        "gdpr": "Personal data, Art. 4(1): direct identifier",
        "uupdp": "Umum, Pasal 4(3)(a): nama lengkap",
        "why": "Identifies the person directly; the starting point for most other misuse.",
    },
    {
        "key": "nik", "label": "National ID number (NIK)", "input": "text", "max": 16,
        "gdpr": "Personal data; national identification number, Art. 87",
        "uupdp": "Umum, Pasal 4(3)(f): identifies a person; high misuse risk",
        "why": "A unique, permanent identifier that is hard to change and is used "
               "to open accounts and loans, so a leak enables identity fraud.",
    },
    {
        "key": "birth_date", "label": "Date of birth", "input": "date", "max": 10,
        "gdpr": "Personal data, Art. 4(1)",
        "uupdp": "Umum (identifying in combination); reveals if the person is a child "
                 "(data anak is Spesifik, Pasal 4(2)(e))",
        "why": "Combined with a name it identifies a person and is a common "
               "security question / verification factor.",
    },
    {
        "key": "phone", "label": "Phone number", "input": "text", "max": 20,
        "gdpr": "Personal data, Art. 4(1)",
        "uupdp": "Umum, Pasal 4(3)(f): contact identifier",
        "why": "Used for OTPs and account recovery; enables spam, phishing and SIM-swap attacks.",
    },
    {
        "key": "address", "label": "Home address", "input": "textarea", "max": 300,
        "gdpr": "Personal data, Art. 4(1)",
        "uupdp": "Umum, Pasal 4(3)(f)",
        "why": "Reveals where the person lives, which is a physical safety risk.",
    },
    {
        "key": "religion", "label": "Religion", "input": "text", "max": 50,
        "gdpr": "SPECIAL category, Art. 9 (religious beliefs)",
        "uupdp": "Umum, Pasal 4(3)(d): agama",
        "why": "Can lead to discrimination; GDPR treats it as specially protected.",
    },
    {
        "key": "health_notes", "label": "Health information", "input": "textarea", "max": 500,
        "gdpr": "SPECIAL category, Art. 9 (data concerning health)",
        "uupdp": "SPESIFIK, Pasal 4(2)(a): data dan informasi kesehatan",
        "why": "Highly sensitive; disclosure can cause discrimination at work or by insurers.",
    },
    {
        "key": "bank_account", "label": "Bank account number", "input": "text", "max": 34,
        "gdpr": "Personal data, high risk (financial)",
        "uupdp": "SPESIFIK, Pasal 4(2)(f): data keuangan pribadi",
        "why": "Direct financial harm and fraud if leaked.",
    },
]

FIELD_KEYS = [f["key"] for f in FIELDS]

# Classification of uploaded files (shown on the Privacy page).
FILE_CLASSIFICATION = [
    ("ID card image (KTP / passport)",
     "Contains many fields at once: NIK, name, birth date, address, religion, "
     "marital status and a face photo. Under GDPR a photo becomes biometric "
     "data (Art. 9) when processed to identify someone (Art. 4(14), Recital 51); "
     "under UU PDP biometric data is Spesifik (Pasal 4(2)(b)). The single most "
     "sensitive file type in this app."),
    ("PDF / Word documents", "May contain any personal data (contracts, CVs, medical letters)."),
    ("Spreadsheets", "Often hold lists of many people or financial data (aggregation risk)."),
    ("Videos", "May show faces and voices, which are personal and possibly biometric data."),
]

# Data that is NOT encrypted, and why (be honest about this in your report).
NOT_ENCRYPTED = [
    ("Username", "Needed to find the account at login before any key exists. "
                 "Users should choose a username that is not their real name (pseudonym)."),
    ("Password", "Not encrypted at all: only a salted PBKDF2 hash is stored."),
    ("File ID, owner ID, upload timestamp", "Needed for access control and listing. "
                                            "The file's name, type and size are encrypted."),
    ("Encrypted file size on disk", "Ciphertext length reveals the approximate file size "
                                    "(exactly, for RC4, which adds no padding)."),
    ("Timing measurements", "For the cipher comparison the app records how long each encryption "
                            "and decryption took and the size of the data, never its content."),
]

_NIK_RE = re.compile(r"^\d{16}$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9 \-]{6,19}$")
_BANK_RE = re.compile(r"^[0-9A-Za-z \-]{5,34}$")


def validate_profile(form):
    """Return (values, errors). Empty values mean "delete this field"."""
    values, errors = {}, {}
    for f in FIELDS:
        v = (form.get(f["key"]) or "").strip()
        if len(v) > f["max"]:
            errors[f["key"]] = f"At most {f['max']} characters."
        elif v:
            if f["key"] == "nik" and not _NIK_RE.match(v):
                errors["nik"] = "NIK must be exactly 16 digits."
            elif f["key"] == "phone" and not _PHONE_RE.match(v):
                errors["phone"] = "Use digits, spaces or dashes, optionally starting with +."
            elif f["key"] == "bank_account" and not _BANK_RE.match(v):
                errors["bank_account"] = "Use letters, digits, spaces or dashes (5-34 characters)."
            elif f["key"] == "birth_date":
                try:
                    if date.fromisoformat(v) > date.today():
                        errors["birth_date"] = "Date of birth cannot be in the future."
                except ValueError:
                    errors["birth_date"] = "Use the format YYYY-MM-DD."
        values[f["key"]] = v
    return values, errors


def field_context(user_id: int, key: str) -> bytes:
    return f"profile|user:{user_id}|field:{key}".encode()


def load_profile(conn, user_id: int, dek: bytes, alg: str = "aes"):
    """Decrypt the profile from one cipher's copy, timing the decryption."""
    rows = conn.execute(f"SELECT field, {COLUMNS[alg]} AS blob FROM profile_fields "
                        "WHERE user_id = ?", (user_id,)).fetchall()
    profile, nbytes, seconds = {}, 0, 0.0
    for row in rows:
        if row["field"] in FIELD_KEYS:
            plain, spent = analysis.open_timed(dek, row["blob"], field_context(user_id, row["field"]))
            profile[row["field"]] = plain.decode("utf-8")
            nbytes, seconds = nbytes + len(plain), seconds + spent
    if profile:
        analysis.record(conn, user_id, "profile", alg, "decrypt", nbytes, seconds)
    return profile


def stored_sizes(conn, user_id: int):
    """Plaintext-free view for the analysis page: ciphertext size per field and cipher."""
    rows = conn.execute("SELECT field, length(ciphertext) AS aes, length(ciphertext_des) AS des, "
                        "length(ciphertext_rc4) AS rc4 FROM profile_fields WHERE user_id = ?",
                        (user_id,)).fetchall()
    labels = {f["key"]: f["label"] for f in FIELDS}
    return [dict(row, label=labels.get(row["field"], row["field"])) for row in rows]


def save_profile(conn, user_id: int, dek: bytes, values, now: float):
    nbytes, seconds = 0, dict.fromkeys(envelope.ALGORITHMS, 0.0)
    for key, value in values.items():
        if value:
            data = value.encode("utf-8")
            blobs, spent = analysis.seal_all_timed(dek, data, field_context(user_id, key))
            nbytes += len(data)
            for alg in seconds:
                seconds[alg] += spent[alg]
            conn.execute(
                "INSERT INTO profile_fields (user_id, field, ciphertext, ciphertext_des, ciphertext_rc4, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(user_id, field) DO UPDATE SET ciphertext = excluded.ciphertext, "
                "ciphertext_des = excluded.ciphertext_des, ciphertext_rc4 = excluded.ciphertext_rc4, "
                "updated_at = excluded.updated_at",
                (user_id, key, blobs["aes"], blobs["des"], blobs["rc4"], now),
            )
        else:
            conn.execute("DELETE FROM profile_fields WHERE user_id = ? AND field = ?", (user_id, key))
    conn.commit()
    if nbytes:
        for alg, spent in seconds.items():
            analysis.record(conn, user_id, "profile", alg, "encrypt", nbytes, spent)
