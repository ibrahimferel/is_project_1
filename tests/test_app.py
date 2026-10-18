"""
Attack tests: each test plays the attacker against the running application
(through Flask's test client) and checks that the defence holds.
"""

import io
import logging
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
import zipfile

from app import create_app

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"PRIVATE-PIXELS" * 10
PASSWORD = "a long test password"

logging.disable(logging.CRITICAL)   # keep test output readable


def csrf_from(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.app = create_app({
            "DATABASE": os.path.join(self.tmp, "test.sqlite3"),
            "STORAGE_DIR": os.path.join(self.tmp, "files"),
            "PBKDF2_ITERATIONS": 1000,          # fast for tests only
            "TESTING": True,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    # ---- helpers
    def token(self, client=None, path="/login"):
        return csrf_from((client or self.client).get(path).get_data(as_text=True))

    def register(self, username, password=PASSWORD, client=None):
        c = client or self.client
        return c.post("/register", data={"csrf_token": self.token(c, "/register"), "username": username,
                                         "password": password, "confirm": password})

    def login(self, username, password=PASSWORD, client=None):
        c = client or self.client
        return c.post("/login", data={"csrf_token": self.token(c), "username": username, "password": password})

    def user(self, name):
        c = self.app.test_client()
        self.register(name, client=c)
        self.assertEqual(self.login(name, client=c).status_code, 302)
        return c

    def upload(self, client, name, data, category="id_card"):
        return client.post("/files", content_type="multipart/form-data", data={
            "csrf_token": self.token(client, "/dashboard"), "category": category,
            "file": (io.BytesIO(data), name)})

    def file_ids(self, client):
        return re.findall(r"/files/([0-9a-f]{32})\"", client.get("/dashboard").get_data(as_text=True))

    def raw_db(self):
        conn = sqlite3.connect(self.app.config["DATABASE"])
        dump = "\n".join(conn.iterdump())
        conn.close()
        return dump


class AppTest(BaseCase):
    # ---- authentication
    def test_password_is_hashed_not_stored(self):
        self.register("alice")
        dump = self.raw_db()
        self.assertNotIn(PASSWORD, dump)
        self.assertIn("pbkdf2_sha256$", dump)

    def test_login_flow_and_data_access(self):
        self.assertEqual(self.client.get("/dashboard").status_code, 302)   # not logged in
        self.register("alice")
        self.assertEqual(self.login("alice").status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_same_error_for_unknown_user_and_wrong_password(self):
        self.register("alice")
        a = self.login("alice", "wrong password!!").get_data(as_text=True)
        b = self.login("nobody", "wrong password!!").get_data(as_text=True)
        self.assertIn("Invalid username or password", a)
        self.assertIn("Invalid username or password", b)

    # ---- SQL injection
    def test_sql_injection_login_fails(self):
        self.register("alice")
        for payload in ["alice' --", "' OR '1'='1", "alice'; DROP TABLE users; --"]:
            r = self.login(payload, "' OR '1'='1")
            self.assertEqual(r.status_code, 401)
        self.assertEqual(self.login("alice").status_code, 302)   # table still exists

    def test_sql_metacharacters_are_stored_as_data(self):
        c = self.user("alice")
        name = "O'Brien\"); DROP TABLE users; --"
        c.post("/profile", data={"csrf_token": self.token(c, "/dashboard"), "full_name": name})
        self.assertIn("O&#39;Brien", c.get("/dashboard").get_data(as_text=True))

    # ---- brute force
    def test_lockout_after_repeated_failures(self):
        self.register("alice")
        for _ in range(5):
            self.assertEqual(self.login("alice", "wrong password!!").status_code, 401)
        self.assertEqual(self.login("alice").status_code, 429)   # even the right password

    # ---- CSRF
    def test_post_without_or_with_wrong_csrf_token_is_rejected(self):
        c = self.user("alice")
        self.assertEqual(c.post("/profile", data={"full_name": "x"}).status_code, 400)
        self.assertEqual(c.post("/profile", data={"csrf_token": "guess", "full_name": "x"}).status_code, 400)
        self.assertEqual(self.client.post("/login", data={"username": "a", "password": "b"}).status_code, 400)

    # ---- session security
    def test_cookie_flags_and_session_rotation(self):
        r = self.client.get("/login")
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        before = self.client.get_cookie("sid").value
        self.register("alice")
        self.login("alice")
        after = self.client.get_cookie("sid").value
        self.assertNotEqual(before, after)                       # no session fixation

    def test_stolen_cookie_is_useless_after_logout(self):
        self.register("alice")
        self.login("alice")
        stolen = self.client.get_cookie("sid").value
        self.client.post("/logout", data={"csrf_token": self.token(self.client, "/dashboard")})
        attacker = self.app.test_client()
        attacker.set_cookie("sid", stolen)
        self.assertEqual(attacker.get("/dashboard").status_code, 302)

    # ---- XSS
    def test_stored_xss_is_escaped_and_csp_is_set(self):
        c = self.user("alice")
        c.post("/profile", data={"csrf_token": self.token(c, "/dashboard"),
                                 "full_name": "<script>alert(1)</script>"})
        r = c.get("/dashboard")
        html = r.get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("script-src 'none'", r.headers["Content-Security-Policy"])

    # ---- data at rest
    def test_personal_data_is_encrypted_in_database(self):
        c = self.user("alice")
        c.post("/profile", data={"csrf_token": self.token(c, "/dashboard"), "nik": "3578012345678901"})
        self.assertIn("3578012345678901", c.get("/dashboard").get_data(as_text=True))
        self.assertNotIn("3578012345678901", self.raw_db())

    def test_file_is_encrypted_on_disk_and_decrypted_on_download(self):
        c = self.user("alice")
        self.assertEqual(self.upload(c, "ktp.png", PNG).status_code, 302)
        file_id = self.file_ids(c)[0]
        stored = os.listdir(self.app.config["STORAGE_DIR"])
        self.assertEqual(stored, [file_id + ".bin"])            # random name, not ktp.png
        with open(os.path.join(self.app.config["STORAGE_DIR"], stored[0]), "rb") as fh:
            self.assertNotIn(b"PRIVATE-PIXELS", fh.read())
        self.assertNotIn("ktp.png", self.raw_db())               # filename encrypted too
        r = c.get(f"/files/{file_id}")
        self.assertEqual(r.data, PNG)
        self.assertIn("attachment", r.headers["Content-Disposition"])

    def test_tampered_file_is_refused(self):
        c = self.user("alice")
        self.upload(c, "ktp.png", PNG)
        file_id = self.file_ids(c)[0]
        path = os.path.join(self.app.config["STORAGE_DIR"], file_id + ".bin")
        with open(path, "rb") as fh:
            data = bytearray(fh.read())
        data[40] ^= 0xFF                                   # attacker edits the stored file
        with open(path, "wb") as fh:
            fh.write(bytes(data))
        self.assertEqual(c.get(f"/files/{file_id}").status_code, 500)

    # ---- insecure uploads
    def test_dangerous_or_disguised_uploads_are_rejected(self):
        c = self.user("alice")
        cases = [("shell.php", b"<?php system($_GET['c']); ?>", "document"),
                 ("photo.jpg", b"<html><script>alert(1)</script></html>", "id_card"),
                 ("photo.php.png", b"<?php echo 1; ?>", "id_card"),
                 ("report.docx", b"PK\x03\x04 not really a zip", "document"),
                 ("sheet.xlsx", PNG, "spreadsheet")]
        for name, data, cat in cases:
            self.assertEqual(self.upload(c, name, data, cat).status_code, 400, name)
        self.assertEqual(os.listdir(self.app.config["STORAGE_DIR"]), [])

    def test_real_docx_is_accepted(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", "<w:document/>")
        c = self.user("alice")
        self.assertEqual(self.upload(c, "cv.docx", buf.getvalue(), "document").status_code, 302)

    # ---- path traversal
    def test_path_traversal_is_blocked(self):
        c = self.user("alice")
        for path in ["/files/../app.py", "/files/..%2f..%2fapp.py", "/files/%2e%2e%2fconfig.py",
                     "/files/..%5c..%5capp.py", "/files/" + "a" * 32]:
            self.assertEqual(c.get(path).status_code, 404, path)
        # A traversal filename is only ever used as a display name.
        self.upload(c, "../../../../etc/passwd.png", PNG)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{32}\.bin", n)
                            for n in os.listdir(self.app.config["STORAGE_DIR"])))

    # ---- access control between users (IDOR)
    def test_users_cannot_access_each_others_files(self):
        alice, bob = self.user("alice"), self.user("bob")
        self.upload(alice, "ktp.png", PNG)
        file_id = self.file_ids(alice)[0]
        self.assertEqual(bob.get(f"/files/{file_id}").status_code, 404)
        r = bob.post(f"/files/{file_id}/delete", data={"csrf_token": self.token(bob, "/dashboard")})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(alice.get(f"/files/{file_id}").status_code, 200)   # still there

    def test_security_headers(self):
        h = self.client.get("/login").headers
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Cache-Control"], "no-store")


class LabTest(BaseCase):
    def test_lab_pages_render(self):
        for page in ["/lab/", "/lab/modes", "/privacy"]:
            self.assertEqual(self.client.get(page).status_code, 200, page)
        for page, form in [("/lab/aes", {}), ("/lab/des", {}), ("/lab/rc4", {}), ("/lab/hashing", {}),
                           ("/lab/modes", {"text": "x"})]:
            form["csrf_token"] = self.token(self.client, page)
            r = self.client.post(page, data=form)
            self.assertEqual(r.status_code, 200, page)
        html = self.client.post("/lab/aes", data={"csrf_token": self.token(self.client, "/lab/aes")}).get_data(as_text=True)
        self.assertIn("69c4e0d86a7b0430d8cdb78070b4c55a", html)


if __name__ == "__main__":
    unittest.main()
