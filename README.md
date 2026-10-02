# Secure ATT Research Paper Library

This project adds a local Flask backend for the research-paper section.

## Security behavior

- Admin password is read only from `ADMIN_PASSWORD` on first startup and stored as a Werkzeug password hash in SQLite.
- Admin upload endpoints require a server session and CSRF token.
- Readers can list and read PDFs but there are no edit or delete endpoints.
- Uploads are stored outside the template/static directory with random server-side filenames.
- The server checks the `.pdf` extension, PDF magic header, and an 8 MB size limit.
- Session cookies are HTTP-only and SameSite=Lax.

This is suitable for local use. For public production deployment, use HTTPS, set `COOKIE_SECURE=1`, set a strong persistent `FLASK_SECRET_KEY`, put the app behind a production WSGI server/reverse proxy, and add backups/access logging.

## Run locally

```bash
cd /home/ubuntu/energy-demand-secure
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export ADMIN_PASSWORD='replace-with-a-strong-password-at-least-12-chars'
export FLASK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Open `http://127.0.0.1:5000/`.

The first startup creates `data/papers.sqlite3` and stores only a password hash. Do not commit `.env`, the SQLite database, or uploaded PDFs to source control.

If the database already exists, changing `ADMIN_PASSWORD` will not change the password; reset the database only if you intentionally want to recreate the admin account.
