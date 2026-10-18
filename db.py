"""
SQLite database access.

SQL INJECTION DEFENCE: every query in this project uses placeholders (?) and
passes user input separately as parameters, e.g.

    conn.execute("SELECT * FROM users WHERE username = ?", (username,))

The database receives the SQL text and the data separately, so input such as
    ' OR '1'='1
is treated as a literal string to compare, never as SQL code. Building SQL
with f-strings or + would let that input change the query. There is no
string-built SQL anywhere in the code (search for "execute(" to check).
"""

import os
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,      -- pbkdf2_sha256$iter$salt$hash (one-way)
    kek_salt        BLOB    NOT NULL,      -- salt for deriving the key-encryption key
    kek_iterations  INTEGER NOT NULL,
    wrapped_dek     BLOB    NOT NULL,      -- user's data key, encrypted with the KEK
    created_at      REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS profile_fields (
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    field       TEXT    NOT NULL,          -- e.g. 'nik' (the name is not secret)
    ciphertext  BLOB    NOT NULL,          -- the value is always encrypted
    updated_at  REAL    NOT NULL,
    PRIMARY KEY (user_id, field)
);

CREATE TABLE IF NOT EXISTS files (
    id               TEXT    PRIMARY KEY,  -- random 128-bit hex, also the file name on disk
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    meta_ciphertext  BLOB    NOT NULL,     -- encrypted JSON: original name, type, size
    created_at       REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);

CREATE TABLE IF NOT EXISTS login_failures (
    key  TEXT NOT NULL,                    -- 'user:<name>' or 'ip:<address>'
    ts   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_failures_key ON login_failures(key, ts);
"""


def connect(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    """One connection per request, stored on flask.g."""
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app(app):
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    with connect(app.config["DATABASE"]) as conn:
        conn.executescript(SCHEMA)
    app.teardown_appcontext(close_db)
