"""
HTTP security headers added to every response.

Content-Security-Policy (CSP) is the second line of defence against XSS.
The first line is Jinja2 auto-escaping (every {{ value }} in a template is
HTML-escaped). This app uses no JavaScript at all, so the CSP can say
script-src 'none': even if someone managed to inject a <script> tag, the
browser would refuse to run it.
"""

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'none'",           # no JavaScript anywhere
    "style-src 'self'",            # only /static/style.css, no inline styles
    "img-src 'self' data:",        # data: is needed for the ECB/CBC demo images
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",          # forms can only submit to this site
    "frame-ancestors 'none'",      # cannot be embedded in an iframe (clickjacking)
])


def apply_security_headers(response, https_enabled: bool):
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"     # browser must trust our Content-Type
    h["X-Frame-Options"] = "DENY"               # older browsers' clickjacking protection
    h["Referrer-Policy"] = "no-referrer"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    # Pages contain decrypted personal data: never store them in any cache.
    h["Cache-Control"] = "no-store"
    if https_enabled:
        # Tell browsers to use HTTPS only for this site for one year.
        h["Strict-Transport-Security"] = "max-age=31536000"
    return response
