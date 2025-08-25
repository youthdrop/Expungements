# Expungements (Flask)

Black & white expungement tracker with:
- Email/password **login**
- **Admin-only** `/register` to add users
- Global login guard
- Participants → Cases → Notes
- **Reports** page with date filters and **Download CSV**
- SQLite locally, Postgres on Railway

## Local (SQLite)
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

# seed first admin (once)
unset DATABASE_URL
export ADMIN_EMAIL="you@example.org"
export ADMIN_PASSWORD="a-strong-password"
python -c "import app"

# run
FLASK_APP=app.py python -m flask run
