"""
SecureVault: a small Flask app that demonstrates cryptography, authentication,
secure file storage and privacy protection.

Request pipeline (every request):
    1. load_session()   find the server-side session from the cookie, or create
                        an anonymous one
    2. CSRF check       every POST must carry the session's CSRF token
    3. the route        login_required routes also need a logged-in session
    4. finish()         set the session cookie and the security headers

Run:  python app.py      then open http://127.0.0.1:5000
"""

import hmac
import io
import json
import logging
import os
import re
import secrets
import time
from functools import wraps

from flask import (Flask, abort, g, redirect, render_template, request,
                   send_file, url_for)

import db
import privacy
from config import Config
from crypto import envelope, passwords
from security import ratelimit, uploads
from security.headers import apply_security_headers
from security.sessions import SessionStore

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# Fixed messages selected by a short code in the URL (?msg=saved). User input is
# never echoed from the URL into the page.
MESSAGES = {
    "registered": "Account created. Log in to continue.",
    "saved": "Personal data saved (encrypted).",
    "uploaded": "File uploaded and encrypted.",
    "deleted": "File deleted.",
    "logged_out": "You have been logged out.",
}

security_log = logging.getLogger("securevault.security")


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)
    db.init_app(app)

    sessions = SessionStore(app.config["SESSION_IDLE_SECONDS"], app.config["SESSION_ABSOLUTE_SECONDS"])
    cookie_name = "__Host-sid" if app.config["HTTPS"] else "sid"
    iterations = app.config["PBKDF2_ITERATIONS"]
    # Hash of a random password, used when a username does not exist so that
    # "unknown user" and "wrong password" take the same time (no user enumeration).
    dummy_hash = passwords.hash_password(secrets.token_urlsafe(16), iterations)

    # ------------------------------------------------------------------ helpers

    def start_new_session(user_id=None, username=None, dek=None):
        """Throw away the current session and issue a fresh ID (anti-fixation)."""
        sessions.destroy(getattr(g, "sid", None))
        g.sid, g.sess = sessions.create(user_id, username, dek)
        g.set_cookie = True

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.sess.user_id is None or g.sess.dek is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapper

    def storage_path(file_id: str) -> str:
        """Path of an encrypted file on disk, with a path-traversal guard.

        file_id was already checked against ^[0-9a-f]{32}$, so it cannot contain
        "/" or "..". The commonpath check is defence in depth.
        """
        base = os.path.realpath(app.config["STORAGE_DIR"])
        path = os.path.realpath(os.path.join(base, file_id + ".bin"))
        if os.path.commonpath([base, path]) != base:
            abort(404)
        return path

    def file_context(user_id, file_id, part):
        return f"file-{part}|user:{user_id}|id:{file_id}".encode()

    def list_files(conn, user_id, dek):
        rows = conn.execute("SELECT id, meta_ciphertext, created_at FROM files "
                            "WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
        files = []
        for row in rows:
            meta = json.loads(envelope.open_sealed(dek, row["meta_ciphertext"],
                                                   file_context(user_id, row["id"], "meta")))
            meta.update(id=row["id"], created_at=row["created_at"])
            files.append(meta)
        return files

    def render_dashboard(conn, status=200, **extra):
        s = g.sess
        ctx = dict(fields=privacy.FIELDS,
                   profile=privacy.load_profile(conn, s.user_id, s.dek),
                   files=list_files(conn, s.user_id, s.dek),
                   categories=uploads.CATEGORIES,
                   profile_errors={}, upload_error=None,
                   message=MESSAGES.get(request.args.get("msg", "")))
        ctx.update(extra)
        return render_template("dashboard.html", **ctx), status

    # ------------------------------------------------------- request pipeline

    @app.before_request
    def load_session():
        if request.endpoint == "static":
            return
        g.set_cookie = False
        g.sid = request.cookies.get(cookie_name)
        g.sess = sessions.get(g.sid)
        if g.sess is None:
            g.sid, g.sess = sessions.create()
            g.set_cookie = True

        # CSRF: a POST must include the secret token that was put into our own
        # forms. Another website can make the browser send a POST to us, but it
        # cannot read our pages, so it cannot know the token.
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not hmac.compare_digest(sent.encode(), g.sess.csrf_token.encode()):
                security_log.warning("CSRF token mismatch from %s on %s", request.remote_addr, request.path)
                abort(400)

    @app.after_request
    def finish(response):
        if getattr(g, "set_cookie", False):
            response.set_cookie(cookie_name, g.sid,
                                httponly=True,                 # not readable by JavaScript
                                secure=app.config["HTTPS"],    # HTTPS only (when enabled)
                                samesite="Strict",             # not sent on cross-site requests
                                path="/")                      # no max_age: dies with the browser
        return apply_security_headers(response, app.config["HTTPS"])

    @app.template_filter("timestamp")
    def format_timestamp(ts):
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))

    @app.context_processor
    def template_globals():
        sess = getattr(g, "sess", None)
        return {"csrf_token": sess.csrf_token if sess else "",
                "current_user": sess.username if sess else None,
                "max_upload_mb": app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)}

    # ---------------------------------------------------------- auth routes

    @app.get("/")
    def index():
        return redirect(url_for("dashboard" if g.sess.user_id else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            min_len, max_len = app.config["PASSWORD_MIN_LENGTH"], app.config["PASSWORD_MAX_LENGTH"]
            if not USERNAME_RE.match(username):
                error = "Username: 3-32 characters, letters, digits or underscore."
            elif not min_len <= len(password) <= max_len:
                error = f"Password must be {min_len}-{max_len} characters long."
            elif password.lower() == username.lower():
                error = "Password must not be the same as the username."
            elif password != confirm:
                error = "The two passwords do not match."
            else:
                conn = db.get_db()
                if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                    error = "That username is not available."
                else:
                    # 1. one-way hash for checking the password at login
                    password_hash = passwords.hash_password(password, iterations)
                    # 2. random data key, wrapped with a key derived from the password
                    kek_salt = secrets.token_bytes(16)
                    kek = passwords.derive_key(password, kek_salt, iterations)
                    dek = envelope.generate_key()
                    wrapped = envelope.wrap_key(kek, dek, username)
                    conn.execute(
                        "INSERT INTO users (username, password_hash, kek_salt, kek_iterations, "
                        "wrapped_dek, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (username, password_hash, kek_salt, iterations, wrapped, time.time()))
                    conn.commit()
                    security_log.info("New account registered: %s", username)
                    return redirect(url_for("login", msg="registered"))
        return render_template("register.html", error=error), (400 if error else 200)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.sess.user_id:
            return redirect(url_for("dashboard"))
        message = MESSAGES.get(request.args.get("msg", ""))
        if request.method == "GET":
            return render_template("login.html", message=message)

        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")[:app.config["PASSWORD_MAX_LENGTH"]]
        ip = request.remote_addr or "unknown"
        conn = db.get_db()
        ratelimit.purge_old(conn, app.config["LOGIN_WINDOW_SECONDS"])

        # Step 1: brute-force check (before doing any expensive work)
        wait = ratelimit.seconds_until_allowed(conn, username, ip, app.config)
        if wait:
            security_log.warning("Login blocked (rate limit) for %r from %s", username, ip)
            minutes = max(1, round(wait / 60))
            return render_template("login.html", error=f"Too many failed attempts. "
                                   f"Try again in about {minutes} minute(s)."), 429

        # Step 2: password verification (parameterised query; constant-time compare)
        user = None
        if USERNAME_RE.match(username):
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        password_ok = passwords.verify_password(password, user["password_hash"] if user else dummy_hash)

        if user is None or not password_ok:
            ratelimit.record_failure(conn, username, ip)
            security_log.warning("Failed login for %r from %s", username, ip)
            # Same message for "no such user" and "wrong password".
            return render_template("login.html", error="Invalid username or password."), 401

        # Step 3: unlock the user's data key with the password-derived key
        kek = passwords.derive_key(password, user["kek_salt"], user["kek_iterations"])
        try:
            dek = envelope.unwrap_key(kek, user["wrapped_dek"], user["username"])
        except envelope.DecryptionError:
            security_log.error("Wrapped key for %r failed integrity check", username)
            abort(500)

        # Step 4: authenticated session with a NEW session ID
        ratelimit.clear_user(conn, username)
        start_new_session(user["id"], user["username"], dek)
        security_log.info("Successful login for %r from %s", user["username"], ip)
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout():
        start_new_session()   # old session (and the DEK in it) is deleted from memory
        return redirect(url_for("login", msg="logged_out"))

    # ---------------------------------------------------- private data routes

    @app.get("/dashboard")
    @login_required
    def dashboard():
        return render_dashboard(db.get_db())

    @app.post("/profile")
    @login_required
    def save_profile():
        conn = db.get_db()
        values, errors = privacy.validate_profile(request.form)
        if errors:
            # Re-show what the user typed so they can fix it; nothing is saved.
            return render_dashboard(conn, 400, profile_errors=errors, profile=values)
        privacy.save_profile(conn, g.sess.user_id, g.sess.dek, values, time.time())
        return redirect(url_for("dashboard", msg="saved"))

    @app.post("/files")
    @login_required
    def upload_file():
        conn = db.get_db()
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            return render_dashboard(conn, 400, upload_error="Choose a file to upload.")
        data = uploaded.read()
        try:
            name, mime = uploads.validate(request.form.get("category", ""), uploaded.filename, data)
        except uploads.UploadRejected as e:
            security_log.warning("Upload rejected for user %s: %s", g.sess.user_id, e)
            return render_dashboard(conn, 400, upload_error=str(e))

        uid, dek = g.sess.user_id, g.sess.dek
        file_id = secrets.token_hex(16)               # random name: never the user's filename
        meta = {"name": name, "mime": mime, "size": len(data),
                "category": request.form["category"]}
        sealed_file = envelope.seal(dek, data, file_context(uid, file_id, "data"))
        sealed_meta = envelope.seal(dek, json.dumps(meta).encode(), file_context(uid, file_id, "meta"))

        path = storage_path(file_id)
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(sealed_file)
        os.replace(tmp, path)                          # atomic: no half-written files
        try:
            conn.execute("INSERT INTO files (id, user_id, meta_ciphertext, created_at) "
                         "VALUES (?, ?, ?, ?)", (file_id, uid, sealed_meta, time.time()))
            conn.commit()
        except Exception:
            os.remove(path)
            raise
        return redirect(url_for("dashboard", msg="uploaded"))

    def owned_file_or_404(file_id):
        """Access control: the file must exist AND belong to the logged-in user.

        Returns 404 (not 403) for other users' files so attackers cannot even
        learn that a file ID exists.
        """
        if not FILE_ID_RE.fullmatch(file_id):
            abort(404)
        row = db.get_db().execute("SELECT * FROM files WHERE id = ? AND user_id = ?",
                                  (file_id, g.sess.user_id)).fetchone()
        if row is None:
            security_log.warning("User %s requested file %s they do not own", g.sess.user_id, file_id)
            abort(404)
        return row

    @app.get("/files/<file_id>")
    @login_required
    def download_file(file_id):
        row = owned_file_or_404(file_id)
        uid, dek = g.sess.user_id, g.sess.dek
        try:
            with open(storage_path(file_id), "rb") as fh:
                data = envelope.open_sealed(dek, fh.read(), file_context(uid, file_id, "data"))
            meta = json.loads(envelope.open_sealed(dek, row["meta_ciphertext"],
                                                   file_context(uid, file_id, "meta")))
        except (OSError, envelope.DecryptionError):
            security_log.error("File %s is missing or failed its integrity check", file_id)
            abort(500)
        return send_file(io.BytesIO(data), mimetype=meta["mime"], as_attachment=True,
                         download_name=meta["name"], max_age=0)

    @app.post("/files/<file_id>/delete")
    @login_required
    def delete_file(file_id):
        owned_file_or_404(file_id)
        conn = db.get_db()
        conn.execute("DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, g.sess.user_id))
        conn.commit()
        try:
            os.remove(storage_path(file_id))
        except FileNotFoundError:
            pass
        return redirect(url_for("dashboard", msg="deleted"))

    # --------------------------------------------------------- info pages

    @app.get("/privacy")
    def privacy_page():
        return render_template("privacy.html", fields=privacy.FIELDS,
                               file_classes=privacy.FILE_CLASSIFICATION,
                               not_encrypted=privacy.NOT_ENCRYPTED)

    from lab import bp as lab_bp
    app.register_blueprint(lab_bp)

    # ------------------------------------------------------- error pages

    @app.errorhandler(400)
    def bad_request(_e):
        return render_template("error.html", title="Request rejected",
                               text="The form was missing its security token or it expired. "
                                    "Go back, reload the page and try again."), 400

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", title="Not found",
                               text="This page or file does not exist."), 404

    @app.errorhandler(413)
    def too_large(_e):
        return render_template("error.html", title="File too large",
                               text=f"Uploads are limited to "
                                    f"{app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB."), 413

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("error.html", title="Something went wrong",
                               text="The server could not complete the request. "
                                    "Details were written to the server log."), 500

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    # debug=False: the Werkzeug debugger allows running code from the browser.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
