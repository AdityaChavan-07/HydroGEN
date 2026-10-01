import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = DATA_DIR / "papers.sqlite3"
MAX_PDF_BYTES = 8 * 1024 * 1024


def load_env_file():
    env_path = BASE_DIR / ".env"
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


load_env_file()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=MAX_PDF_BYTES + 512 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

DATA_DIR.mkdir(mode=0o750, exist_ok=True)
UPLOAD_DIR.mkdir(mode=0o750, exist_ok=True)


def db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db_connection() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS papers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                size_bytes INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_account (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL
            )
            """
        )
        if db.execute("SELECT 1 FROM admin_account WHERE id = 1").fetchone() is None:
            password = os.environ.get("ADMIN_PASSWORD")
            if not password or len(password) < 12:
                raise RuntimeError(
                    "Set ADMIN_PASSWORD to a password of at least 12 characters before first start."
                )
            db.execute(
                "INSERT INTO admin_account (id, password_hash) VALUES (1, ?)",
                (generate_password_hash(password),),
            )


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def require_csrf():
    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token")
    return bool(expected and provided and secrets.compare_digest(expected, provided))


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify(error="Admin authentication required."), 401
        if request.method != "GET" and not require_csrf():
            return jsonify(error="Invalid CSRF token."), 403
        return view(*args, **kwargs)

    return wrapped


def paper_json(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "name": row["original_name"],
        "sizeLabel": f"{row['size_bytes'] / 1024:.0f} KB" if row["size_bytes"] < 1024 * 1024 else f"{row['size_bytes'] / (1024 * 1024):.1f} MB",
        "date": row["uploaded_at"][:10],
        "readUrl": f"/papers/{row['id']}/read",
    }


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
    return response


@app.get("/")
def index():
    csrf_token()
    return render_template("index.html")


@app.get("/api/auth/status")
def auth_status():
    return jsonify(authenticated=bool(session.get("is_admin")), csrfToken=csrf_token())


@app.post("/api/login")
def login():
    if not request.is_json:
        return jsonify(error="JSON is required."), 400
    password = str(request.json.get("password", ""))
    with db_connection() as db:
        account = db.execute("SELECT password_hash FROM admin_account WHERE id = 1").fetchone()
    if not account or not check_password_hash(account["password_hash"], password):
        return jsonify(error="Invalid admin credentials."), 401
    session.clear()
    session["is_admin"] = True
    csrf_token()
    return jsonify(authenticated=True, csrfToken=session["csrf_token"])


@app.post("/api/logout")
@admin_required
def logout():
    session.clear()
    return jsonify(authenticated=False)


@app.get("/api/papers")
def papers():
    with db_connection() as db:
        rows = db.execute("SELECT * FROM papers ORDER BY uploaded_at DESC, id DESC").fetchall()
    return jsonify(papers=[paper_json(row) for row in rows])


@app.post("/api/papers")
@admin_required
def upload_paper():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    file = request.files.get("file")
    if not title or len(title) > 160:
        return jsonify(error="A paper title up to 160 characters is required."), 400
    if len(description) > 500:
        return jsonify(error="Description must be 500 characters or fewer."), 400
    if not file or not file.filename:
        return jsonify(error="Choose a PDF file."), 400
    original_name = secure_filename(file.filename)
    if not original_name.lower().endswith(".pdf"):
        return jsonify(error="Only PDF research papers are accepted."), 400
    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)
    if size > MAX_PDF_BYTES:
        return jsonify(error="PDF must be 8 MB or smaller."), 413
    signature = file.stream.read(5)
    file.stream.seek(0)
    if signature != b"%PDF-":
        return jsonify(error="The uploaded file is not a valid PDF."), 400

    stored_name = f"{secrets.token_hex(20)}.pdf"
    destination = UPLOAD_DIR / stored_name
    file.save(destination)
    uploaded_at = datetime.now(timezone.utc).isoformat()
    try:
        with db_connection() as db:
            cursor = db.execute(
                "INSERT INTO papers (title, description, original_name, stored_name, size_bytes, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)",
                (title, description, original_name, stored_name, size, uploaded_at),
            )
            paper_id = cursor.lastrowid
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    with db_connection() as db:
        row = db.execute("SELECT * FROM papers WHERE id = ?", (paper_id,)).fetchone()
    return jsonify(paper=paper_json(row)), 201


@app.get("/papers/<int:paper_id>/read")
def read_paper(paper_id):
    with db_connection() as db:
        row = db.execute("SELECT * FROM papers WHERE id = ?", (paper_id,)).fetchone()
    if not row:
        return jsonify(error="Paper not found."), 404
    path = UPLOAD_DIR / row["stored_name"]
    if not path.is_file():
        return jsonify(error="Paper file is unavailable."), 404
    return send_file(path, mimetype="application/pdf", as_attachment=False, download_name=row["original_name"])


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="Upload is too large."), 413


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
else:
    init_db()
