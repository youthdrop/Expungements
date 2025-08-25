# Expungements GUI (Flask) — with Login

A clean, black-and-white web app to enroll participants and manage expungement cases and notes. Includes email/password login.

## Features
- **Login required** for all screens (email + password via Flask-Login)
- **Participant enrollment**: first name, last name, phone, email, DOB
- **Multiple cases per participant**: case number, charges, date of conviction
- **Checklist per case**: petition completed, interview completed, revenue & recovery contacted, declaration completed, social bio completed, court case filed
- **Ongoing case notes**: per case with date/time, method (participant called, staff called, meeting, court support), and details
- **Monochrome UI**

## Local Setup (SQLite)
```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install -r requirements.txt
```

### Seed your first admin user
Set two env vars and import the app once (creates DB + user):
```bash
export ADMIN_EMAIL="you@example.org"
export ADMIN_PASSWORD="set-a-strong-password"
python3 -c "import app"            # prints which DB is in use
```

### Run
```bash
# Make sure local DATABASE_URL is NOT set so SQLite is used
unset DATABASE_URL
FLASK_APP=app.py python3 -m flask run
```
Open http://127.0.0.1:5000 — Sign in with the seeded admin.

## Deploy on Railway (Postgres)
1. Push this folder to a **GitHub repo**.
2. In Railway → New Project → **Deploy from GitHub Repo**.
3. Add **PostgreSQL** plugin.
4. In **Variables** set:
   - `DATABASE_URL` = the Postgres URL from Railway
   - `ADMIN_EMAIL` and `ADMIN_PASSWORD` (for first boot seeding)
   - (optional) `SECRET_KEY` = strong random string
5. Start command is handled by `Procfile`: `gunicorn app:app`.

The app auto-creates tables on boot. No migrations necessary for this starter.

## Notes
- Locally we recommend SQLite. On Railway you’ll use Postgres automatically via `DATABASE_URL`.
- Requirements include `psycopg2-binary` **only on Linux** so your Mac won’t try to build it.
- On startup the app logs which DB it is using.
