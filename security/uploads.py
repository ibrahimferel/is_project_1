"""
Upload validation: decide whether an uploaded file is acceptable.

Never trust what the browser says about a file. The filename and the
Content-Type header are chosen by the client and can be anything. So:

1. Allow-list of extensions per category (not a block-list of bad ones).
2. Check the file's real content ("magic bytes" / file signature) matches
   the extension. A PHP script renamed to photo.jpg fails this check.
3. The MIME type we store and later send back comes from OUR table, not
   from the client.
4. Size limit (enforced by Flask's MAX_CONTENT_LENGTH -> HTTP 413).

Other defences live in app.py:
* The original filename is NEVER used as a path on disk (path traversal).
  Files are stored as <random 128-bit id>.bin in a folder outside /static.
* Stored files are encrypted, so the server never "serves" or executes them.
* Downloads always use Content-Disposition: attachment plus
  X-Content-Type-Options: nosniff, so a malicious HTML/SVG file cannot run
  as a page on our site (stored XSS through uploads).

Limitation to mention: a structurally valid DOC/XLS can still contain
malicious macros. Malware scanning (e.g. ClamAV) is out of scope.
"""

import io
import os
import unicodedata
import zipfile

OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"   # legacy MS Office (.doc, .xls)
ZIP_MAGIC = b"PK\x03\x04"                         # .docx/.xlsx are ZIP files


def _is_jpeg(d): return d[:3] == b"\xFF\xD8\xFF"
def _is_png(d): return d[:8] == b"\x89PNG\r\n\x1a\n"
def _is_pdf(d): return d[:5] == b"%PDF-"
def _is_ole(d): return d[:8] == OLE_MAGIC
def _is_mp4_family(d): return len(d) > 12 and d[4:8] == b"ftyp"   # mp4 / mov
def _is_webm(d): return d[:4] == b"\x1A\x45\xDF\xA3"


def _ooxml_has(d, required_member):
    """A .docx / .xlsx is a ZIP archive containing specific XML files.

    Only the list of names is read; nothing is decompressed (no zip-bomb risk).
    """
    if d[:4] != ZIP_MAGIC:
        return False
    try:
        names = set(zipfile.ZipFile(io.BytesIO(d)).namelist())
    except zipfile.BadZipFile:
        return False
    return "[Content_Types].xml" in names and required_member in names


def _is_docx(d): return _ooxml_has(d, "word/document.xml")
def _is_xlsx(d): return _ooxml_has(d, "xl/workbook.xml")


# extension -> (MIME type we will send back, content check)
FILE_TYPES = {
    "jpg":  ("image/jpeg", _is_jpeg),
    "jpeg": ("image/jpeg", _is_jpeg),
    "png":  ("image/png", _is_png),
    "pdf":  ("application/pdf", _is_pdf),
    "doc":  ("application/msword", _is_ole),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", _is_docx),
    "xls":  ("application/vnd.ms-excel", _is_ole),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", _is_xlsx),
    "mp4":  ("video/mp4", _is_mp4_family),
    "mov":  ("video/quicktime", _is_mp4_family),
    "webm": ("video/webm", _is_webm),
}

# Category -> label and allowed extensions. The category also matters for
# privacy: an ID card image is the most sensitive file type (see privacy.py).
CATEGORIES = {
    "id_card":     ("ID card image (KTP / passport)", ("jpg", "jpeg", "png", "pdf")),
    "document":    ("Document (PDF / Word)", ("pdf", "doc", "docx")),
    "spreadsheet": ("Spreadsheet (Excel)", ("xls", "xlsx")),
    "video":       ("Video", ("mp4", "mov", "webm")),
}


class UploadRejected(ValueError):
    pass


def clean_filename(name: str) -> str:
    """A display-safe version of the original filename.

    Used only for showing the name and as the download name, never as a path.
    Removes directory parts ("../../etc/passwd" -> "passwd") and control chars.
    """
    name = unicodedata.normalize("NFC", name or "")
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C").strip(" .")
    return name[:150] or "file"


def validate(category: str, filename: str, data: bytes):
    """Return (clean_name, mime_type) or raise UploadRejected with a reason."""
    if category not in CATEGORIES:
        raise UploadRejected("Choose a file category.")
    if not data:
        raise UploadRejected("The file is empty.")
    name = clean_filename(filename)
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    label, allowed = CATEGORIES[category]
    if ext not in allowed:
        raise UploadRejected(f"{label} must be one of: {', '.join(allowed)}.")
    mime, content_check = FILE_TYPES[ext]
    if not content_check(data):
        raise UploadRejected(f"The file content does not look like a real .{ext} file.")
    return name, mime
