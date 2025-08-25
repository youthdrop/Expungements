import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- App & DB Config ----------
def _normalize_db_url(raw: str) -> str:
    if raw.startswith("postgres://"):
        return raw.replace("postgres://", "postgresql://", 1)
    return raw

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///app.db"
else:
    DATABASE_URL = _normalize_db_url(DATABASE_URL)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

db = SQLAlchemy(app)

# Login manager
login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- Models ----------
def seed_admin_user():
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")
    if admin_email and admin_password:
        if not User.query.filter_by(email=admin_email).first():
            u = User(email=admin_email)
            u.set_password(admin_password)
            u.is_admin = True
            db.session.add(u)
            db.session.commit()
            app.logger.info("Seeded admin user: %s", admin_email)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Participant(db.Model):
    __tablename__ = "participants"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(50))
    email = db.Column(db.String(120))
    dob = db.Column(db.Date)
    cases = db.relationship("Case", back_populates="participant", cascade="all, delete-orphan")

class Case(db.Model):
    __tablename__ = "cases"
    id = db.Column(db.Integer, primary_key=True)
    participant_id = db.Column(db.Integer, db.ForeignKey("participants.id"), nullable=False)
    case_number = db.Column(db.String(100), nullable=False)
    charges = db.Column(db.Text)
    date_of_conviction = db.Column(db.Date)

    # checklist
    petition_completed = db.Column(db.Boolean, default=False)
    interview_completed = db.Column(db.Boolean, default=False)
    revenue_recovery_contacted = db.Column(db.Boolean, default=False)
    declaration_completed = db.Column(db.Boolean, default=False)
    social_bio_completed = db.Column(db.Boolean, default=False)
    court_case_filed = db.Column(db.Boolean, default=False)

    participant = db.relationship("Participant", back_populates="cases")
    notes = db.relationship("CaseNote", back_populates="case", cascade="all, delete-orphan", order_by="CaseNote.note_date.desc()")

class CaseNote(db.Model):
    __tablename__ = "case_notes"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    note_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    method_of_contact = db.Column(db.String(50))  # participant_called, staff_called, meeting, court_support
    content = db.Column(db.Text, nullable=False)

    case = db.relationship("Case", back_populates="notes")

with app.app_context():
    db.create_all()
    seed_admin_user()
    app.logger.info("Database: %s", app.config["SQLALCHEMY_DATABASE_URI"])

# ---------- Helpers ----------
def parse_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None

# ---------- Routes ----------

from flask import request

@app.before_request
def login_guard_before_request():
    # Allow unauthenticated access only to login, static files, and health
    open_endpoints = {"login", "static", "health"}
    if request.endpoint in open_endpoints or request.endpoint is None:
        return
    if not current_user.is_authenticated:
        return redirect(url_for("login"))


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("participants_list"))
    return redirect(url_for("login"))

# Auth
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter(db.func.lower(User.email) == email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Welcome back.", "success")
            return redirect(url_for("participants_list"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Signed out.", "success")
    return redirect(url_for("login"))

# Participants
@app.route("/participants")
@login_required
def participants_list():
    q = request.args.get("q", "").strip()
    query = Participant.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(
                Participant.first_name.ilike(like),
                Participant.last_name.ilike(like),
                Participant.email.ilike(like),
                Participant.phone.ilike(like),
            )
        )
    participants = query.order_by(Participant.last_name.asc(), Participant.first_name.asc()).all()
    return render_template("participants_list.html", participants=participants, q=q)

@app.route("/participants/new", methods=["GET", "POST"])
@login_required
def participant_new():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        dob_str = request.form.get("dob", "").strip()
        dob = parse_date(dob_str)

        if not first_name or not last_name:
            flash("First and last name are required.", "error")
            return redirect(request.url)

        p = Participant(first_name=first_name, last_name=last_name, phone=phone, email=email, dob=dob)
        db.session.add(p)
        db.session.commit()
        flash("Participant enrolled.", "success")
        return redirect(url_for("participant_detail", participant_id=p.id))

    return render_template("participant_form.html")

@app.route("/participants/<int:participant_id>")
@login_required
def participant_detail(participant_id):
    p = Participant.query.get_or_404(participant_id)
    return render_template("participant_detail.html", p=p)

# Cases
@app.route("/participants/<int:participant_id>/cases/new", methods=["GET", "POST"])
@login_required
def case_new(participant_id):
    p = Participant.query.get_or_404(participant_id)
    if request.method == "POST":
        case_number = request.form.get("case_number", "").strip()
        charges = request.form.get("charges", "").strip()
        date_of_conviction = parse_date(request.form.get("date_of_conviction", "").strip())

        if not case_number:
            flash("Case number is required.", "error")
            return redirect(request.url)

        c = Case(
            participant=p,
            case_number=case_number,
            charges=charges,
            date_of_conviction=date_of_conviction,
            petition_completed=bool(request.form.get("petition_completed")),
            interview_completed=bool(request.form.get("interview_completed")),
            revenue_recovery_contacted=bool(request.form.get("revenue_recovery_contacted")),
            declaration_completed=bool(request.form.get("declaration_completed")),
            social_bio_completed=bool(request.form.get("social_bio_completed")),
            court_case_filed=bool(request.form.get("court_case_filed")),
        )
        db.session.add(c)
        db.session.commit()
        flash("Case created.", "success")
        return redirect(url_for("case_detail", case_id=c.id))

    return render_template("case_form.html", participant=p, case=None)

@app.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id):
    c = Case.query.get_or_404(case_id)
    return render_template("case_detail.html", c=c)

@app.route("/cases/<int:case_id>/update", methods=["POST"])
@login_required
def case_update(case_id):
    c = Case.query.get_or_404(case_id)
    c.case_number = request.form.get("case_number", "").strip() or c.case_number
    c.charges = request.form.get("charges", "").strip()
    c.date_of_conviction = parse_date(request.form.get("date_of_conviction", "").strip())

    # Checklist
    c.petition_completed = bool(request.form.get("petition_completed"))
    c.interview_completed = bool(request.form.get("interview_completed"))
    c.revenue_recovery_contacted = bool(request.form.get("revenue_recovery_contacted"))
    c.declaration_completed = bool(request.form.get("declaration_completed"))
    c.social_bio_completed = bool(request.form.get("social_bio_completed"))
    c.court_case_filed = bool(request.form.get("court_case_filed"))

    db.session.commit()
    flash("Case updated.", "success")
    return redirect(url_for("case_detail", case_id=case_id))

@app.route("/cases/<int:case_id>/notes", methods=["POST"])
@login_required
def case_add_note(case_id):
    c = Case.query.get_or_404(case_id)
    method_of_contact = request.form.get("method_of_contact", "").strip()
    content = request.form.get("content", "").strip()
    nd = request.form.get("note_date", "").strip()

    if not content:
        flash("Note content is required.", "error")
        return redirect(url_for("case_detail", case_id=case_id))

    note_dt = None
    if nd:
        for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d"):
            try:
                note_dt = datetime.strptime(nd, fmt)
                break
            except ValueError:
                continue
    if not note_dt:
        note_dt = datetime.utcnow()

    note = CaseNote(case=c, note_date=note_dt, method_of_contact=method_of_contact, content=content)
    db.session.add(note)
    db.session.commit()
    flash("Note added.", "success")
    return redirect(url_for("case_detail", case_id=case_id))

# Health
@app.route("/health")
def health():
    return "ok", 200


# Admin-only user registration
@app.route("/register", methods=["GET", "POST"])
@login_required
def register():
    if not getattr(current_user, "is_admin", False):
        flash("Admins only.", "error")
        return redirect(url_for("participants_list"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(request.url)
        if User.query.filter(db.func.lower(User.email) == email).first():
            flash("That email is already in use.", "error")
            return redirect(request.url)
        u = User(email=email)
        u.set_password(password)
        u.is_admin = bool(request.form.get("is_admin"))
        db.session.add(u)
        db.session.commit()
        flash("User created.", "success")
        return redirect(url_for("participants_list"))
    return render_template("register.html")


# ---------- Reports ----------
@app.route("/reports")
@login_required
def reports():
    # Parse date filters (YYYY-MM-DD)
    from_str = request.args.get("from", "").strip()
    to_str = request.args.get("to", "").strip()
    date_from = None
    date_to = None
    if from_str:
        try:
            date_from = datetime.strptime(from_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid 'from' date; use YYYY-MM-DD.", "error")
    if to_str:
        try:
            date_to = datetime.strptime(to_str, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid 'to' date; use YYYY-MM-DD.", "error")

    # Counts
    total_participants = db.session.query(db.func.count(Participant.id)).scalar()

    # Cases filtered by date_of_conviction when a range is given
    cases_query = Case.query
    if date_from:
        cases_query = cases_query.filter(Case.date_of_conviction >= date_from)
    if date_to:
        cases_query = cases_query.filter(Case.date_of_conviction <= date_to)
    cases_filtered = cases_query.all()
    count_cases_filtered = len(cases_filtered)
    count_cases_total = db.session.query(db.func.count(Case.id)).scalar()

    # Notes filtered by note_date
    notes_query = CaseNote.query
    if date_from:
        notes_query = notes_query.filter(CaseNote.note_date >= datetime.combine(date_from, datetime.min.time()))
    if date_to:
        notes_query = notes_query.filter(CaseNote.note_date <= datetime.combine(date_to, datetime.max.time()))
    count_notes_filtered = notes_query.count()
    count_notes_total = db.session.query(db.func.count(CaseNote.id)).scalar()

    # Checklist rollups over the filtered cases
    checklist = {
        "petition_completed": sum(1 for c in cases_filtered if c.petition_completed),
        "interview_completed": sum(1 for c in cases_filtered if c.interview_completed),
        "revenue_recovery_contacted": sum(1 for c in cases_filtered if c.revenue_recovery_contacted),
        "declaration_completed": sum(1 for c in cases_filtered if c.declaration_completed),
        "social_bio_completed": sum(1 for c in cases_filtered if c.social_bio_completed),
        "court_case_filed": sum(1 for c in cases_filtered if c.court_case_filed),
    }

    return render_template(
        "reports.html",
        from_str=from_str,
        to_str=to_str,
        total_participants=total_participants,
        count_cases_total=count_cases_total,
        count_cases_filtered=count_cases_filtered,
        count_notes_total=count_notes_total,
        count_notes_filtered=count_notes_filtered,
        checklist=checklist,
        cases=cases_filtered,
    )

@app.route("/reports/csv")
@login_required
def reports_csv():
    # Same filter logic
    from_str = request.args.get("from", "").strip()
    to_str = request.args.get("to", "").strip()
    date_from = None
    date_to = None
    if from_str:
        try:
            date_from = datetime.strptime(from_str, "%Y-%m-%d").date()
        except ValueError:
            pass
    if to_str:
        try:
            date_to = datetime.strptime(to_str, "%Y-%m-%d").date()
        except ValueError:
            pass

    cases_query = Case.query.join(Participant, Case.participant_id == Participant.id)
    if date_from:
        cases_query = cases_query.filter(Case.date_of_conviction >= date_from)
    if date_to:
        cases_query = cases_query.filter(Case.date_of_conviction <= date_to)
    rows = cases_query.add_columns(
        Participant.first_name, Participant.last_name, Participant.email, Participant.phone
    ).all()

    # Build CSV
    import csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Participant First Name","Participant Last Name","Participant Email","Participant Phone",
        "Case Number","Date of Conviction","Charges",
        "Petition Completed","Interview Completed","R&R Contacted","Declaration Completed","Social Bio Completed","Court Case Filed",
        "Notes Count"
    ])
    for row in rows:
        c = row[0]
        p_first, p_last, p_email, p_phone = row[1], row[2], row[3], row[4]
        notes_count = CaseNote.query.filter_by(case_id=c.id).count()
        writer.writerow([
            p_first, p_last, p_email or "", p_phone or "",
            c.case_number, c.date_of_conviction or "", (c.charges or "").replace("\n"," ").replace("\r"," "),
            "Yes" if c.petition_completed else "No",
            "Yes" if c.interview_completed else "No",
            "Yes" if c.revenue_recovery_contacted else "No",
            "Yes" if c.declaration_completed else "No",
            "Yes" if c.social_bio_completed else "No",
            "Yes" if c.court_case_filed else "No",
            notes_count
        ])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv"
    filename = "cases_report.csv"
    if from_str or to_str:
        filename = f"cases_report_{from_str or 'start'}_{to_str or 'end'}.csv"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp

# ---------- Error Handlers ----------
@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", content="<h2>Not Found</h2><p>The item you requested was not found.</p>"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("base.html", content="<h2>Server Error</h2><p>Something went wrong.</p>"), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
