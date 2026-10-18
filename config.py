"""
Application settings. Values can be overridden with environment variables.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # SQLite database file and the folder holding encrypted uploads.
    # Both are outside the /static folder, so the web server never serves them directly.
    DATABASE = os.environ.get("SV_DATABASE", os.path.join(BASE_DIR, "instance", "securevault.sqlite3"))
    STORAGE_DIR = os.environ.get("SV_STORAGE_DIR", os.path.join(BASE_DIR, "instance", "encrypted_files"))

    # Maximum upload size. Pure-Python AES runs at roughly 0.5-1 MB/s, so a
    # 20 MB video takes ~20-40 seconds to encrypt. Raise it if you are patient.
    MAX_CONTENT_LENGTH = int(os.environ.get("SV_MAX_UPLOAD_MB", "20")) * 1024 * 1024

    # Set SV_HTTPS=1 when the app runs behind HTTPS. It enables the Secure cookie
    # flag and the __Host- cookie prefix. Leave it off for http://localhost.
    HTTPS = os.environ.get("SV_HTTPS", "0") == "1"

    # PBKDF2 work factor (OWASP recommendation for PBKDF2-HMAC-SHA256).
    PBKDF2_ITERATIONS = int(os.environ.get("SV_PBKDF2_ITERATIONS", "600000"))

    # Sessions: logged out after 15 minutes of inactivity or 8 hours in total.
    SESSION_IDLE_SECONDS = 15 * 60
    SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60

    # Password policy (NIST SP 800-63B favours length over complexity rules).
    PASSWORD_MIN_LENGTH = 10
    PASSWORD_MAX_LENGTH = 128
