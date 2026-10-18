"""
Brute-force protection for the login form.

Every failed login is recorded twice in the `login_failures` table:
  * under the submitted username  ("user:alice")  -> stops guessing one account
  * under the client IP address   ("ip:1.2.3.4")  -> stops one machine trying
                                                     many accounts
If a key has too many failures inside the time window, login is refused until
the oldest failure falls out of the window.

Details worth explaining:
* Failures are counted for usernames that do NOT exist too, so the lockout
  message does not reveal which usernames are real.
* A successful login clears the counter for that username.
* Trade-off: an attacker can deliberately lock someone out (a small denial of
  service). Real systems add CAPTCHAs or progressive delays; a short lock
  window is a reasonable compromise for this project.
* Combined with the slow PBKDF2 hash, online guessing is limited to a handful
  of attempts per window.
"""

import time


def _keys(username: str, ip: str):
    return [("user:" + username.lower()[:64], "user"), ("ip:" + ip, "ip")]


def seconds_until_allowed(conn, username: str, ip: str, cfg) -> int:
    """0 if login may be attempted, otherwise how long to wait."""
    now = time.time()
    window = cfg["LOGIN_WINDOW_SECONDS"]
    limits = {"user": cfg["LOGIN_MAX_FAILURES_PER_USER"], "ip": cfg["LOGIN_MAX_FAILURES_PER_IP"]}
    wait = 0
    for key, kind in _keys(username, ip):
        rows = conn.execute(
            "SELECT ts FROM login_failures WHERE key = ? AND ts > ? ORDER BY ts",
            (key, now - window),
        ).fetchall()
        if len(rows) >= limits[kind]:
            # Allowed again once enough old failures have expired.
            oldest_relevant = rows[len(rows) - limits[kind]]["ts"]
            wait = max(wait, int(oldest_relevant + window - now) + 1)
    return wait


def record_failure(conn, username: str, ip: str):
    now = time.time()
    conn.executemany("INSERT INTO login_failures (key, ts) VALUES (?, ?)",
                     [(key, now) for key, _ in _keys(username, ip)])
    conn.commit()


def clear_user(conn, username: str):
    conn.execute("DELETE FROM login_failures WHERE key = ?", ("user:" + username.lower()[:64],))
    conn.commit()


def purge_old(conn, window: int):
    conn.execute("DELETE FROM login_failures WHERE ts < ?", (time.time() - window,))
    conn.commit()
