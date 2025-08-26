
import os
from datetime import datetime, date
from typing import Optional

from flask import (
    Flask, render_template, request, redirect, url_for, flash, send_file, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    current_user, logout_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, func, case as sa_case

# -----------------------------------------------------------------------------
# App config
# -----------------------------------------------------------------------------
def _build_db_uri() -> str:
    uri = (
        os.getenv("SQLALCHEMY_DATABASE_URI")
        or os.getenv("DATABASE_URL")  # Railway/Heroku style
        or "sqlite:///app.db"
    )
    # Normalize old postgres:// URLS to postgresql://
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    return uri

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-fallback-key')
app.config['SQLALCHEMY_DATABASE_URI'] = _build_db_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Participant(db.Model):
    __tablename__ = "participants"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255))
    phone = db.Column(db.String(64))
    dob = db.Column(db.Date)
    status = db.Column(db.String(64), default="active", nullable=False)  # active, expungement granted, expungement denied, non response
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    cases = db.relationship("Case", backref="participant", lazy=True, cascade="all, delete-orphan")

    @property
    def name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()
    @property
    def full_name(self) -> str:
        # alias so old templates using p.full_name keep working
        return self.name

class Case(db.Model):
    __tablename__ = "cases"
    id = db.Column(db.Integer, primary_key=True)
    participant_id = db.Column(db.Integer, db.ForeignKey("participants.id"), nullable=False)

    case_number = db.Column(db.String(120), nullable=False, index=True)
    charges = db.Column(db.Text)
    date_of_conviction = db.Column(db.Date)

    # Checklist
    petition_completed = db.Column(db.Boolean, default=False, nullable=False)
    interview_completed = db.Column(db.Boolean, default=False, nullable=False)
    revenue_recovery_contacted = db.Column(db.Boolean, default=False, nullable=False)
    declaration_completed = db.Column(db.Boolean, default=False, nullable=False)
    social_bio_completed = db.Column(db.Boolean, default=False, nullable=False)
    court_case_filed = db.Column(db.Boolean, default=False, nullable=False)

    notes = db.relationship("CaseNote", backref="case", lazy=True, cascade="all, delete-orphan")


class CaseNote(db.Model):
    __tablename__ = "case_notes"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    method = db.Column(db.String(64))  # participant called, staff called, meeting, court support
    content = db.Column(db.Text)


# -----------------------------------------------------------------------------
# Login manager
# -----------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def ensure_admin_from_env():
    """Create/update an admin user from ADMIN_EMAIL / ADMIN_PASSWORD env vars."""
    email = os.getenv("ADMIN_EMAIL")
    pwd   = os.getenv("ADMIN_PASSWORD")
    if not email or not pwd:
        return
    with app.app_context():
        db.create_all()
        u = User.query.filter_by(email=email).first()
        if not u:
            u = User(email=email, is_admin=True)
            db.session.add(u)
        u.set_password(pwd)
        db.session.commit()

@app.before_request
def _seed_admin_on_each_request():
    try:
        ensure_admin_from_env()
    except Exception as e:
        # Don’t crash the app if seeding fails
        print("ensure_admin_from_env error:", e)



# -----------------------------------------------------------------------------
# Basic routes
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("participants"))
    return redirect(url_for("login"))

@app.route("/health")
def health():
    return {"status": "ok"}, 200


# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("participants"))
        flash("Invalid credentials.", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
@login_required
def register():
    # Only admins can add users
    if not current_user.is_admin:
        flash("Only admins can add users.", "error")
        return redirect(url_for("participants"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        is_admin = bool(request.form.get("is_admin"))
        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "error")
            return render_template("register.html")
        u = User(email=email, is_admin=is_admin)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("User created.", "success")
        return redirect(url_for("participants"))
    return render_template("register.html")


# -----------------------------------------------------------------------------
# Participants
# -----------------------------------------------------------------------------
@app.route("/participants")
@login_required
def participants():
    q = (request.args.get("q") or "").strip()
    query = Participant.query
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Participant.first_name.ilike(like),
                Participant.last_name.ilike(like),
                Participant.email.ilike(like),
                Participant.phone.ilike(like),
            )
        )
    people = query.order_by(Participant.last_name.asc(), Participant.first_name.asc()).all()

    # Keep compatibility with existing template variable names
    return render_template("participants_list.html",
                           items=people, participants=people, q=q)

# Alias so older templates using url_for("participants_list") still work
app.add_url_rule("/participants", endpoint="participants_list", view_func=participants)

@app.route("/participants/new", methods=["GET", "POST"])
@login_required
def participant_new():
    if request.method == "POST":
        first = (request.form.get("first_name") or "").strip()
        last  = (request.form.get("last_name") or "").strip()
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone") or "").strip()
        dob_raw = (request.form.get("dob") or "").strip()
        status = (request.form.get("status") or "active").strip()

        if not first or not last:
            flash("First and last name are required.", "error")
            return render_template("participant_form.html")

        dob_val = None
        if dob_raw:
            try:
                dob_val = datetime.strptime(dob_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid date of birth (use YYYY-MM-DD).", "error")
                return render_template("participant_form.html")

        p = Participant(
            first_name=first, last_name=last, email=email or None,
            phone=phone or None, dob=dob_val, status=status or "active"
        )
        db.session.add(p)
        db.session.commit()
        flash("Participant enrolled.", "success")
        return redirect(url_for("participants"))

    return render_template("participant_form.html")

@app.route("/participant/<int:participant_id>")
@login_required
def participant_detail(participant_id: int):
    p = db.session.get(Participant, participant_id)
    if not p:
        flash("Participant not found.", "error")
        return redirect(url_for("participants"))

    cases = Case.query.filter_by(participant_id=p.id).order_by(Case.id.desc()).all()
    notes_by_case = {
        c.id: CaseNote.query.filter_by(case_id=c.id).order_by(CaseNote.timestamp.desc()).all()
        for c in cases
    }
    return render_template(
        "participant_detail.html",
        participant=p,   # keep for newer templates
        p=p,             # alias for older templates expecting `p`
        cases=cases,
        notes_by_case=notes_by_case
    )
@app.route("/cases/<int:case_id>")
@login_required
def case_view(case_id: int):
    c = db.session.get(Case, case_id)
    if not c:
        flash("Case not found.", "error")
        return redirect(url_for("participants"))
    p = db.session.get(Participant, c.participant_id)
    notes = (
        CaseNote.query.filter_by(case_id=c.id)
        .order_by(CaseNote.timestamp.desc())
        .all()
    )
    return render_template(
        "case_detail.html",
        case=c, c=c,               # provide both names for template compatibility
        participant=p, p=p,
        notes=notes
    )
# Reuse case_view for case_detail links from the template
if "case_detail" not in app.view_functions:
    app.add_url_rule("/cases/<int:case_id>", endpoint="case_detail", view_func=case_view, methods=["GET"])


@app.route("/participant/<int:participant_id>/delete", methods=["POST"])
@login_required
def participant_delete(participant_id: int):
    p = db.session.get(Participant, participant_id)
    if not p:
        flash("Participant not found.", "error")
        return redirect(url_for("participants"))
    db.session.delete(p)
    db.session.commit()
    flash("Participant deleted.", "success")
    return redirect(url_for("participants"))


# -----------------------------------------------------------------------------
# Cases & Notes
# -----------------------------------------------------------------------------
@app.route("/participant/<int:participant_id>/cases/new", methods=["GET", "POST"])
@login_required
def case_new(participant_id: int):
    p = db.session.get(Participant, participant_id)
    if not p:
        flash("Participant not found.", "error")
        return redirect(url_for("participants"))

    if request.method == "POST":
        case_number = (request.form.get("case_number") or "").strip()
        charges = (request.form.get("charges") or "").strip()
        date_raw = (request.form.get("date_of_conviction") or "").strip()
        if not case_number:
            flash("Case number is required.", "error")
            return render_template("case_form.html", participant=p)

        date_val = None
        if date_raw:
            try:
                date_val = datetime.strptime(date_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid conviction date (use YYYY-MM-DD).", "error")
                return render_template("case_form.html", participant=p)

        c = Case(
            participant_id=p.id, case_number=case_number, charges=charges or None,
            date_of_conviction=date_val
        )
        db.session.add(c)
        db.session.commit()
        flash("Case added.", "success")
        return redirect(url_for("participant_detail", participant_id=p.id))

    return render_template("case_form.html", participant=p)

@app.route("/cases/<int:case_id>/update", methods=["POST"])
@login_required
def case_update(case_id: int):
    c = db.session.get(Case, case_id)
    if not c:
        flash("Case not found.", "error")
        return redirect(url_for("participants"))

    # Update checklist booleans
    for field in [
        "petition_completed", "interview_completed", "revenue_recovery_contacted",
        "declaration_completed", "social_bio_completed", "court_case_filed"
    ]:
        setattr(c, field, bool(request.form.get(field)))

    # Update other fields if supplied
    charges = (request.form.get("charges") or "").strip()
    if charges:
        c.charges = charges
    date_raw = (request.form.get("date_of_conviction") or "").strip()
    if date_raw:
        try:
            c.date_of_conviction = datetime.strptime(date_raw, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid conviction date (use YYYY-MM-DD).", "error")

    db.session.commit()
    flash("Case updated.", "success")
    return redirect(url_for("participant_detail", participant_id=c.participant_id))

@app.route("/cases/<int:case_id>/notes", methods=["POST"])
@login_required
def case_add_note(case_id: int):
    c = db.session.get(Case, case_id)
    if not c:
        flash("Case not found.", "error")
        return redirect(url_for("participants"))

    method = (request.form.get("method") or "").strip()
    content = (request.form.get("content") or "").strip()
    when_raw = (request.form.get("timestamp") or "").strip()  # HTML datetime-local

    if not method and not content:
        flash("Note content is required.", "error")
        return redirect(url_for("participant_detail", participant_id=c.participant_id))

    ts = datetime.utcnow()
    if when_raw:
        try:
            # datetime-local: YYYY-MM-DDTHH:MM
            ts = datetime.strptime(when_raw, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Invalid note date/time. Using now.", "error")

    note = CaseNote(case_id=c.id, method=method or None, content=content, timestamp=ts)
    db.session.add(note)
    db.session.commit()
    flash("Note added.", "success")
    return redirect(url_for("participant_detail", participant_id=c.participant_id))


# -----------------------------------------------------------------------------
# Reports
# -----------------------------------------------------------------------------
@app.route("/reports")
@login_required
def reports_home():
    # ----- read filters from query -----
    from_str = (request.args.get("from") or "").strip()
    to_str   = (request.args.get("to") or "").strip()

    # parse dates (inclusive)
    date_from = None
    date_to   = None
    try:
        if from_str:
            date_from = datetime.strptime(from_str, "%Y-%m-%d").date()
    except ValueError:
        flash("Invalid From date. Use YYYY-MM-DD.", "error")
    try:
        if to_str:
            date_to = datetime.strptime(to_str, "%Y-%m-%d").date()
    except ValueError:
        flash("Invalid To date. Use YYYY-MM-DD.", "error")

    # ----- build filtered queries -----
    # Filter cases by conviction date (if provided)
    case_query = Case.query
    if date_from:
        case_query = case_query.filter(Case.date_of_conviction >= date_from)
    if date_to:
        case_query = case_query.filter(Case.date_of_conviction <= date_to)

    # Filter notes by timestamp (if provided)
    note_query = CaseNote.query
    if date_from:
        note_query = note_query.filter(
            CaseNote.timestamp >= datetime.combine(date_from, datetime.min.time())
        )
    if date_to:
        note_query = note_query.filter(
            CaseNote.timestamp <= datetime.combine(date_to, datetime.max.time())
        )

    # ----- totals & filtered counts (names match the template) -----
    total_participants    = Participant.query.count()
    count_cases_total     = Case.query.count()
    count_cases_filtered  = case_query.count()
    count_notes_total     = CaseNote.query.count()
    count_notes_filtered  = note_query.count()

    # ----- checklist sums over the *filtered* cases -----
    checklist_row = (
        case_query.with_entities(
            func.sum(sa_case((Case.petition_completed == True, 1), else_=0)).label("petition_completed"),
            func.sum(sa_case((Case.interview_completed == True, 1), else_=0)).label("interview_completed"),
            func.sum(sa_case((Case.revenue_recovery_contacted == True, 1), else_=0)).label("revenue_recovery_contacted"),
            func.sum(sa_case((Case.declaration_completed == True, 1), else_=0)).label("declaration_completed"),
            func.sum(sa_case((Case.social_bio_completed == True, 1), else_=0)).label("social_bio_completed"),
            func.sum(sa_case((Case.court_case_filed == True, 1), else_=0)).label("court_case_filed"),
        ).first()
    )

    checklist = {
        "petition_completed":             int(checklist_row.petition_completed or 0) if checklist_row else 0,
        "interview_completed":            int(checklist_row.interview_completed or 0) if checklist_row else 0,
        "revenue_recovery_contacted":     int(checklist_row.revenue_recovery_contacted or 0) if checklist_row else 0,
        "declaration_completed":          int(checklist_row.declaration_completed or 0) if checklist_row else 0,
        "social_bio_completed":           int(checklist_row.social_bio_completed or 0) if checklist_row else 0,
        "court_case_filed":               int(checklist_row.court_case_filed or 0) if checklist_row else 0,
    }

    # ----- filtered case list for the table -----
    cases = (
        case_query
        .order_by(Case.date_of_conviction.desc(), Case.id.desc())
        .all()
    )

    # ----- render with EXACT names your template uses -----
    return render_template(
        "reports.html",
        from_str=from_str,
        to_str=to_str,
        total_participants=total_participants,
        count_cases_filtered=count_cases_filtered,
        count_cases_total=count_cases_total,
        count_notes_filtered=count_notes_filtered,
        count_notes_total=count_notes_total,
        checklist=checklist,
        cases=cases,
    )

# Optional CSV download
@app.route("/reports/csv")
@login_required
def reports_csv():
    import csv, io
    from flask import make_response

    # query the database for participants + cases
    rows = (
        Case.query
        .join(Participant, Participant.id == Case.participant_id)
        .with_entities(
            Participant.id, Participant.first_name, Participant.last_name, Participant.status,
            Case.id, Case.case_number, Case.charges, Case.date_of_conviction,
            Case.petition_completed, Case.interview_completed, Case.revenue_recovery_contacted,
            Case.declaration_completed, Case.social_bio_completed, Case.court_case_filed,
        )
        .order_by(Participant.last_name.asc(), Participant.first_name.asc(), Case.id.asc())
        .all()
    )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "participant_id","participant_name","status",
        "case_id","case_number","charges","date_of_conviction",
        "petition_completed","interview_completed","revenue_recovery_contacted",
        "declaration_completed","social_bio_completed","court_case_filed"
    ])
    for r in rows:
        (pid, fn, ln, status,
         cid, cnum, charges, doc,
         pet, inter, rev, decl, bio, filed) = r
        writer.writerow([
            pid, f"{fn or ''} {ln or ''}".strip(), status or "",
            cid, cnum or "", charges or "",
            (doc.isoformat() if doc else ""),
            int(bool(pet)), int(bool(inter)), int(bool(rev)),
            int(bool(decl)), int(bool(bio)), int(bool(filed)),
        ])

    resp = make_response(buf.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = 'attachment; filename=reports.csv'
    return resp



# -----------------------------------------------------------------------------
# Table setup
# -----------------------------------------------------------------------------
@app.before_request
def _ensure_tables():
    # First request will create tables if they don't exist (safe if they do)
    db.create_all()


# -----------------------------------------------------------------------------
# Run (dev)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)))
