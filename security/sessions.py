"""
Server-side sessions (written by hand instead of using Flask's default).

Why not Flask's built-in session?
Flask's default session is a *signed cookie*: the data lives in the browser.
Signing stops tampering but does NOT hide the content. We must keep the user's
decrypted data key (DEK) somewhere during the session, and it must never
leave the server. So the browser only gets a random session ID, and all
session data stays in server memory.

Protections against session hijacking / fixation
------------------------------------------------
* Session ID = 32 random bytes from the CSPRNG: impossible to guess.
* Cookie flags (set in app.py): HttpOnly (JavaScript cannot read it, so XSS
  cannot steal it), SameSite=Strict (not sent on cross-site requests),
  Secure (only over HTTPS, when enabled).
* A NEW session ID is issued at login and logout (stops session fixation:
  an attacker cannot plant an ID before login and reuse it after).
* Idle timeout and absolute timeout limit how long a stolen ID is useful.
* The store is keyed by SHA-256(session ID), so even a dump of the store
  does not contain usable cookie values.
* Sessions live only in RAM: restarting the server logs everyone out and
  wipes every DEK from memory. For a single-process student project this is
  a feature; a multi-server deployment would need a shared store.
"""

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Session:
    csrf_token: str
    created: float
    last_seen: float
    user_id: Optional[int] = None
    username: Optional[str] = None
    dek: Optional[bytes] = field(default=None, repr=False)   # never print the key


def _digest(sid: str) -> str:
    return hashlib.sha256(sid.encode("ascii", "ignore")).hexdigest()


class SessionStore:
    def __init__(self, idle_timeout: int, absolute_timeout: int):
        self.idle_timeout = idle_timeout
        self.absolute_timeout = absolute_timeout
        self._sessions = {}
        self._lock = threading.Lock()

    def create(self, user_id=None, username=None, dek=None):
        """Return (session_id, Session). The ID goes into the cookie."""
        sid = secrets.token_urlsafe(32)
        now = time.time()
        sess = Session(csrf_token=secrets.token_urlsafe(32), created=now, last_seen=now,
                       user_id=user_id, username=username, dek=dek)
        with self._lock:
            self._purge_expired(now)
            self._sessions[_digest(sid)] = sess
        return sid, sess

    def get(self, sid: str) -> Optional[Session]:
        if not sid or len(sid) > 100:
            return None
        now = time.time()
        with self._lock:
            key = _digest(sid)
            sess = self._sessions.get(key)
            if sess is None:
                return None
            if self._expired(sess, now):
                del self._sessions[key]
                return None
            sess.last_seen = now
            return sess

    def destroy(self, sid: str):
        if sid:
            with self._lock:
                self._sessions.pop(_digest(sid), None)

    def _expired(self, sess: Session, now: float) -> bool:
        return (now - sess.last_seen > self.idle_timeout
                or now - sess.created > self.absolute_timeout)

    def _purge_expired(self, now: float):
        for key in [k for k, s in self._sessions.items() if self._expired(s, now)]:
            del self._sessions[key]
