"""
SecureVault: a small Flask app that demonstrates cryptography, authentication,
secure file storage and privacy protection.

Request pipeline (every request):
    1. load_session()   find the server-side session from the cookie, or create
                        an anonymous one
    2. CSRF check       every POST must carry the session's CSRF token
    3. the route        login_required routes also need a logged-in session
    4. finish()         set the session cookie and the security headers

Run:  python app.py      then open http://127.0.0.1:8000
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

import analysis
import db
import privacy
from config import Config
from crypto import envelope, passwords
from security import uploads
from security.sessions import SessionStore

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
ALGORITHMS = envelope.ALGORITHMS
META_COLUMNS = {"aes": "meta_ciphertext", "des": "meta_des", "rc4": "meta_rc4"}
MAX_BENCHMARK_ROUNDS = 10

# Fixed messages selected by a short code in the URL (?msg=saved). User input is
# never echoed from the URL into the page.
MESSAGES = {
    "registered": "Account created. Log in to continue.",
    "saved": "Personal data saved (encrypted).",
    "uploaded": "File uploaded and encrypted.",
    "deleted": "File deleted.",
    "logged_out": "You have been logged out.",
    "benchmarked": "Benchmark finished: the file was decrypted with every cipher.",
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

    def storage_path(file_id: str, alg: str) -> str:
        """Path of one cipher's encrypted copy of a file, with a path-traversal guard.

        file_id was already checked against ^[0-9a-f]{32}$ and alg is one of
        ALGORITHMS, so neither can contain "/" or "..". The commonpath check is
        defence in depth.
        """
        if alg not in ALGORITHMS:
            abort(404)
        base = os.path.realpath(app.config["STORAGE_DIR"])
        path = os.path.realpath(os.path.join(base, f"{file_id}.{alg}.bin"))
        if os.path.commonpath([base, path]) != base:
            abort(404)
        return path

    def file_context(user_id, file_id, part):
        return f"file-{part}|user:{user_id}|id:{file_id}".encode()

    def list_files(conn, user_id, dek):
        rows = conn.execute("SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC",
                            (user_id,)).fetchall()
        files = []
        for row in rows:
            meta = json.loads(envelope.open_sealed(dek, row["meta_ciphertext"],
                                                   file_context(user_id, row["id"], "meta")))
            meta.update(id=row["id"], created_at=row["created_at"])
            files.append(meta)
        return files

    def chosen_alg(default="aes"):
        alg = request.values.get("alg", default)
        if alg not in ALGORITHMS:
            abort(404)
        return alg

    def render_dashboard(conn, status=200, **extra):
        s = g.sess
        view_alg = chosen_alg()
        ctx = dict(fields=privacy.FIELDS,
                   view_alg=view_alg, algorithms=ALGORITHMS, alg_labels=envelope.LABELS,
                   profile=privacy.load_profile(conn, s.user_id, s.dek, view_alg),
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
        return response

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

        # Step 1: password verification (parameterised query; constant-time compare)
        user = None
        if USERNAME_RE.match(username):
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        password_ok = passwords.verify_password(password, user["password_hash"] if user else dummy_hash)

        if user is None or not password_ok:
            security_log.warning("Failed login for %r from %s", username, ip)
            # Same message for "no such user" and "wrong password".
            return render_template("login.html", error="Invalid username or password."), 401

        # Step 2: unlock the user's data key with the password-derived key
        kek = passwords.derive_key(password, user["kek_salt"], user["kek_iterations"])
        try:
            dek = envelope.unwrap_key(kek, user["wrapped_dek"], user["username"])
        except envelope.DecryptionError:
            security_log.error("Wrapped key for %r failed integrity check", username)
            abort(500)

        # Step 3: authenticated session with a NEW session ID
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
        # One complete encrypted copy per cipher (AES, DES, RC4), each timed.
        sealed_files, seconds = analysis.seal_all_timed(dek, data, file_context(uid, file_id, "data"))
        sealed_meta = envelope.seal_all(dek, json.dumps(meta).encode(), file_context(uid, file_id, "meta"))

        written = []
        try:
            for alg in ALGORITHMS:
                path = storage_path(file_id, alg)
                tmp = path + ".tmp"
                with open(tmp, "wb") as fh:
                    fh.write(sealed_files[alg])
                os.replace(tmp, path)                  # atomic: no half-written files
                written.append(path)
            conn.execute("INSERT INTO files (id, user_id, meta_ciphertext, meta_des, meta_rc4, created_at) "
                         "VALUES (?, ?, ?, ?, ?, ?)", (file_id, uid, sealed_meta["aes"],
                                                       sealed_meta["des"], sealed_meta["rc4"], time.time()))
            conn.commit()
        except Exception:
            for path in written:
                os.remove(path)
            raise
        for alg, spent in seconds.items():
            analysis.record(conn, uid, file_id, alg, "encrypt", len(data), spent)
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

    def decrypt_file(row, alg):
        """Decrypt one cipher's copy of a file and its metadata, timing the file decryption."""
        uid, dek, file_id = g.sess.user_id, g.sess.dek, row["id"]
        try:
            with open(storage_path(file_id, alg), "rb") as fh:
                blob = fh.read()
            data, seconds = analysis.open_timed(dek, blob, file_context(uid, file_id, "data"))
            meta = json.loads(envelope.open_sealed(dek, row[META_COLUMNS[alg]],
                                                   file_context(uid, file_id, "meta")))
        except (OSError, envelope.DecryptionError):
            security_log.error("File %s (%s copy) is missing or failed its integrity check", file_id, alg)
            abort(500)
        analysis.record(db.get_db(), uid, file_id, alg, "decrypt", len(data), seconds)
        return data, meta

    @app.get("/files/<file_id>")
    @login_required
    def download_file(file_id):
        row = owned_file_or_404(file_id)
        data, meta = decrypt_file(row, chosen_alg())
        return send_file(io.BytesIO(data), mimetype=meta["mime"], as_attachment=True,
                         download_name=meta["name"], max_age=0)

    @app.post("/files/<file_id>/delete")
    @login_required
    def delete_file(file_id):
        owned_file_or_404(file_id)
        conn = db.get_db()
        conn.execute("DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, g.sess.user_id))
        conn.execute("DELETE FROM timings WHERE item = ? AND user_id = ?", (file_id, g.sess.user_id))
        conn.commit()
        for alg in ALGORITHMS:
            try:
                os.remove(storage_path(file_id, alg))
            except FileNotFoundError:
                pass
        return redirect(url_for("dashboard", msg="deleted"))

    # ------------------------------------------------- cipher comparison

    @app.get("/analysis")
    @login_required
    def analysis_page():
        conn = db.get_db()
        uid = g.sess.user_id
        files = list_files(conn, uid, g.sess.dek)
        overall, per_item = analysis.timing_report(conn, uid)

        # Ciphertext comparison for one file: each copy split into its parts.
        selected = next((f for f in files if f["id"] == request.args.get("file")), files[0] if files else None)
        blobs = []
        if selected:
            for alg in ALGORITHMS:
                path = storage_path(selected["id"], alg)
                try:
                    with open(path, "rb") as fh:
                        head = fh.read(1024 * 1024)
                    blobs.append(analysis.describe_blob(head, os.path.getsize(path), selected["size"]))
                except OSError:
                    security_log.error("File %s (%s copy) is missing", selected["id"], alg)
        return render_template("analysis.html", files=files, selected=selected, blobs=blobs,
                               overall=overall, per_item=per_item, algorithms=ALGORITHMS,
                               alg_labels=envelope.LABELS, profile_sizes=privacy.stored_sizes(conn, uid),
                               max_rounds=MAX_BENCHMARK_ROUNDS,
                               message=MESSAGES.get(request.args.get("msg", "")))

    @app.post("/analysis/run")
    @login_required
    def run_benchmark():
        """"Download" a file N times with every cipher, so timings can be compared.

        The ciphers take turns (AES, DES, RC4, AES, ...) so a slow moment on
        the machine affects all three equally.
        """
        row = owned_file_or_404(request.form.get("file_id", ""))
        rounds = request.form.get("rounds", "")
        rounds = max(1, min(int(rounds), MAX_BENCHMARK_ROUNDS)) if rounds.isdigit() else 3
        for _ in range(rounds):
            for alg in ALGORITHMS:
                decrypt_file(row, alg)
        return redirect(url_for("analysis_page", file=row["id"], msg="benchmarked"))

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
    # Not 5000: on macOS the AirPlay Receiver already listens there and answers
    # with an empty 403 page.
    create_app().run(host="127.0.0.1", port=int(os.environ.get("SV_PORT", "8000")), debug=False)
