# reset_admin.py
from app import app, db, User

def ensure_admin(email: str, password: str):
    with app.app_context():
        u = User.query.filter_by(email=email).first()
        if not u:
            u = User(email=email)
            db.session.add(u)
            print(f"Creating new admin: {email}")
        else:
            print(f"Updating existing admin: {email}")
        u.set_password(password)
        db.session.commit()
        print(f"✅ Admin ready: {email} / {password}")

if __name__ == "__main__":
    ensure_admin("admin@example.com", "newpassword123")
