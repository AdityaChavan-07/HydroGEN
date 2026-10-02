import io
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import psycopg2
import psycopg2.extras
from flask import Flask, jsonify, render_template, request, send_file, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
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

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Set DATABASE_URL to a Postgres connection string (e.g. from Neon or Supabase).")
# Some providers still hand out postgres:// which psycopg2 accepts, but normalise anyway.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

IS_RENDER = bool(os.environ.get("RENDER"))  # Render sets RENDER=true automatically

secret_key = os.environ.get("FLASK_SECRET_KEY")
if not secret_key:
    if IS_RENDER:
        raise RuntimeError("Set FLASK_SECRET_KEY in the Render environment.")
    secret_key = secrets.token_hex(32)  # local dev only

app = Flask(__name__)
app.config.update(
    SECRET_KEY=secret_key,
    MAX_CONTENT_LENGTH=MAX_PDF_BYTES + 512 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


@contextmanager
def db_cursor():
    """One short-lived connection per use; commits on success, rolls back on error."""
    connection = psycopg2.connect(
        DATABASE_URL,
        connect_timeout=15,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    try:
        with connection:
            with connection.cursor() as cursor:
                yield cursor
    finally:
        connection.close()


def init_db():
    with db_cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS papers (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                original_name TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL,
                content BYTEA NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_account (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL
            )
            """
        )
        cur.execute("SELECT 1 FROM admin_account WHERE id = 1")
        if cur.fetchone() is None:
            password = os.environ.get("ADMIN_PASSWORD")
            if not password or len(password) < 12:
                raise RuntimeError(
                    "Set ADMIN_PASSWORD to a password of at least 12 characters before first start."
                )
            cur.execute(
                "INSERT INTO admin_account (id, password_hash) VALUES (1, %s) ON CONFLICT (id) DO NOTHING",
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
    size = row["size_bytes"]
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "name": row["original_name"],
        "sizeLabel": f"{size / 1024:.0f} KB" if size < 1024 * 1024 else f"{size / (1024 * 1024):.1f} MB",
        "date": row["uploaded_at"][:10],
        "readUrl": f"/papers/{row['id']}/read",
    }


# Never select the BYTEA column when listing.
PAPER_COLUMNS = "id, title, description, original_name, size_bytes, uploaded_at"


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'self'"
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.get("/healthz")
def healthz():
    return "ok", 200  # no DB hit, so uptime pings stay cheap


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
    with db_cursor() as cur:
        cur.execute("SELECT password_hash FROM admin_account WHERE id = 1")
        account = cur.fetchone()
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
    with db_cursor() as cur:
        cur.execute(f"SELECT {PAPER_COLUMNS} FROM papers ORDER BY uploaded_at DESC, id DESC")
        rows = cur.fetchall()
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

    data = file.stream.read(MAX_PDF_BYTES + 1)
    if len(data) > MAX_PDF_BYTES:
        return jsonify(error="PDF must be 8 MB or smaller."), 413
    if not data.startswith(b"%PDF-"):
        return jsonify(error="The uploaded file is not a valid PDF."), 400

    uploaded_at = datetime.now(timezone.utc).isoformat()
    with db_cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO papers (title, description, original_name, size_bytes, uploaded_at, content)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING {PAPER_COLUMNS}
            """,
            (title, description, original_name, len(data), uploaded_at, psycopg2.Binary(data)),
        )
        row = cur.fetchone()
    return jsonify(paper=paper_json(row)), 201


@app.get("/papers/<int:paper_id>/read")
def read_paper(paper_id):
    with db_cursor() as cur:
        cur.execute("SELECT original_name, content FROM papers WHERE id = %s", (paper_id,))
        row = cur.fetchone()
    if not row:
        return jsonify(error="Paper not found."), 404
    return send_file(
        io.BytesIO(bytes(row["content"])),
        mimetype="application/pdf",
        as_attachment=False,
        download_name=row["original_name"],
    )


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(error="Upload is too large."), 413


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
