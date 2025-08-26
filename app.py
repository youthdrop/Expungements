import os
from datetime import datetime, date
from typing import Optional

from flask import (
    Flask, render_template, request, redirect, url_for, flash, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    current_user, logout_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_  # for filters

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev-fallback-key")

# -----------------------------------------------------------------------------
# App / Config
# -----------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# DB: prefer env var; default to local sqlite (stored in ./instance/app.db)
db_uri = os.environ.get("SQLALCHEMY_DATABASE_URI") or os.environ.get("DATABASE_URL")
if not db_uri:
    db_uri = "sqlite:///app.db"
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# --- ensure admin from env on boot ---
import os

def ensure_admin_from_env():
    email = os.getenv("ADMIN_EMAIL")
    pwd   = os.getenv("ADMIN_PASSWORD")
    if not email or not pwd:
        return
    with app.app_context():
        u = User.query.filter_by(email=email).first()
        if not u:
            u = User(email=email, is_admin=True)
            db.session.add(u)
        u.set_password(pwd)
        db.session.commit()

# call once at startup
ensure_admin_from_env()

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Participant(db.Model):
    __tablename__ = "participants"
    id = db.Column(db.Integer, primary_key=True)

    first_name = db.Column(db.String(120), nullable=False)
    last_name  = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255))
    phone = db.Column(db.String(50))
    dob   = db.Column(db.Date)

    # status: active, expungement_granted, expungement_denied, non_response
    status = db.Column(db.String(40), default="active", nullable=False)

    cases = db.relationship("Case", back_populates="participant",
                            cascade="all, delete-orphan", order_by="Case.created_at.desc()")

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()


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

    status = db.Column(db.String(40), default="active", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)

    participant = db.relationship("Participant", back_populates="cases")
    notes = db.relationship("CaseNote", back_populates="case",
                            cascade="all, delete-orphan", order_by="CaseNote.timestamp.desc()")


class CaseNote(db.Model):
    __tablename__ = "case_notes"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)

    method = db.Column(db.String(40))  # 'participant called', 'staff called', 'meeting', 'court support'
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    case = db.relationship("Case", back_populates="notes")


# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return db.session.get(User, int(user_id))


@app.route("/register", methods=["GET", "POST"])
@login_required
def register():
    # keep simple; hide behind admin
    if not current_user.is_admin:
        flash("Only admins can add users.", "error")
        return redirect(url_for("participants"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        is_admin = bool(request.form.get("is_admin"))
        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("That email is already registered.", "error")
            return render_template("register.html")
        u = User(email=email, is_admin=is_admin)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("User created.", "success")
        return redirect(url_for("participants"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("participants"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


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

    # match your template name and possible variable names
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
            first_name=first, last_name=last, email=email,
            phone=phone, dob=dob_val, status=status or "active"
        )
        db.session.add(p)
        db.session.commit()
        flash("Participant created.", "success")
        return redirect(url_for("participant_detail", participant_id=p.id))

    return render_template("participant_form.html")


@app.route("/participants/<int:participant_id>")
@login_required
def participant_detail(participant_id: int):
    p = Participant.query.get_or_404(participant_id)
    cases = Case.query.filter_by(participant_id=p.id).order_by(Case.created_at.desc()).all()
    c_latest = cases[0] if cases else None  # present as 'c' for templates that expect it
    return render_template("participant_detail.html", p=p, cases=cases, c=c_latest)


@app.route("/participants/<int:participant_id>/delete", methods=["POST"])
@login_required
def participant_delete(participant_id: int):
    p = Participant.query.get_or_404(participant_id)
    db.session.delete(p)
    db.session.commit()
    flash("Participant deleted.", "success")
    return redirect(url_for("participants"))


# -----------------------------------------------------------------------------
# Cases
# -----------------------------------------------------------------------------
@app.route("/participants/<int:participant_id>/cases/new", methods=["GET", "POST"])
@login_required
def case_new(participant_id: int):
    p = Participant.query.get_or_404(participant_id)
    if request.method == "POST":
        case_number = (request.form.get("case_number") or "").strip()
        charges = (request.form.get("charges") or "").strip()
        doc_raw = (request.form.get("date_of_conviction") or "").strip()
        status = (request.form.get("status") or "active").strip()

        if not case_number:
            flash("Case number is required.", "error")
            return render_template("case_form.html", participant=p)

        doc_val = None
        if doc_raw:
            try:
                doc_val = datetime.strptime(doc_raw, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid date of conviction (use YYYY-MM-DD).", "error")
                return render_template("case_form.html", participant=p)

        c = Case(
            participant_id=p.id,
            case_number=case_number,
            charges=charges,
            date_of_conviction=doc_val,
            petition_completed=bool(request.form.get("petition_completed")),
            interview_completed=bool(request.form.get("interview_completed")),
            revenue_recovery_contacted=bool(request.form.get("revenue_recovery_contacted")),
            declaration_completed=bool(request.form.get("declaration_completed")),
            social_bio_completed=bool(request.form.get("social_bio_completed")),
            court_case_filed=bool(request.form.get("court_case_filed")),
            status=status or "active",
        )
        db.session.add(c)
        db.session.commit()
        flash("Case added.", "success")
        return redirect(url_for("participant_detail", participant_id=p.id))

    return render_template("case_form.html", participant=p)


@app.route("/cases/<int:case_id>", methods=["GET"])
@login_required
def case_view(case_id: int):
    c = Case.query.get_or_404(case_id)
    p = c.participant
    return render_template("case_detail.html", p=p, c=c)


@app.route("/cases/<int:case_id>/update", methods=["POST"])
@login_required
def case_update(case_id: int):
    c = Case.query.get_or_404(case_id)

    c.case_number = (request.form.get("case_number") or c.case_number).strip()
    c.charges = request.form.get("charges", c.charges)
    doc_raw = request.form.get("date_of_conviction") or ""
    if doc_raw:
        try:
            c.date_of_conviction = datetime.strptime(doc_raw, "%Y-%m-%d").date()
        except ValueError:
            flash("Invalid date of conviction (use YYYY-MM-DD).", "error")

    c.status = (request.form.get("status") or c.status).strip() or c.status

    c.petition_completed = bool(request.form.get("petition_completed"))
    c.interview_completed = bool(request.form.get("interview_completed"))
    c.revenue_recovery_contacted = bool(request.form.get("revenue_recovery_contacted"))
    c.declaration_completed = bool(request.form.get("declaration_completed"))
    c.social_bio_completed = bool(request.form.get("social_bio_completed"))
    c.court_case_filed = bool(request.form.get("court_case_filed"))

    db.session.commit()
    flash("Case updated.", "success")
    return redirect(url_for("participant_detail", participant_id=c.participant_id))


# -----------------------------------------------------------------------------
# Notes
# -----------------------------------------------------------------------------
@app.route("/cases/<int:case_id>/notes", methods=["POST"])
@login_required
def case_add_note(case_id: int):
    c = Case.query.get_or_404(case_id)
    method = (request.form.get("method") or "").strip()
    content = (request.form.get("content") or "").strip()
    when_raw = (request.form.get("timestamp") or "").strip()

    if not content:
        flash("Note content is required.", "error")
        return redirect(url_for("participant_detail", participant_id=c.participant_id))

    ts = datetime.utcnow()
    if when_raw:
        try:
            # HTML datetime-local => YYYY-MM-DDTHH:MM
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

    # Totals
    total_p = Participant.query.count()
    total_c = Case.query.count()
    total_n = CaseNote.query.count()

    # Checklist aggregate across all cases
    from sqlalchemy import func, case as sa_case
    checklist_counts = db.session.query(
        func.count(Case.id).label("total_cases"),
        func.sum(sa_case((Case.petition_completed == True, 1), else_=0)).label("petition_completed"),
        func.sum(sa_case((Case.interview_completed == True, 1), else_=0)).label("interview_completed"),
        func.sum(sa_case((Case.revenue_recovery_contacted == True, 1), else_=0)).label("revenue_recovery_contacted"),
        func.sum(sa_case((Case.declaration_completed == True, 1), else_=0)).label("declaration_completed"),
        func.sum(sa_case((Case.social_bio_completed == True, 1), else_=0)).label("social_bio_completed"),
        func.sum(sa_case((Case.court_case_filed == True, 1), else_=0)).label("court_case_filed"),
    ).one()

    checklist = {
        "total_cases": checklist_counts.total_cases or 0,
        "petition_completed": checklist_counts.petition_completed or 0,
        "interview_completed": checklist_counts.interview_completed or 0,
        "revenue_recovery_contacted": checklist_counts.revenue_recovery_contacted or 0,
        "declaration_completed": checklist_counts.declaration_completed or 0,
        "social_bio_completed": checklist_counts.social_bio_completed or 0,
        "court_case_filed": checklist_counts.court_case_filed or 0,
    }

    # Participant status distribution
    status_rows = db.session.query(Participant.status, func.count(Participant.id)).group_by(Participant.status).all()
    status_counts = {(s or "Unknown"): c for s, c in status_rows}
    for key in ["active", "expungement granted", "expungement denied", "non response", "Unknown"]:
        status_counts.setdefault(key, 0)

    return render_template("reports.html",
                           total_p=total_p, total_c=total_c, total_n=total_n,
                           checklist=checklist, status_counts=status_counts)
    


# Optional CSV download (keep if your reports.html links to it)
@app.route("/reports/csv")
@login_required
def reports_csv():
    import csv, io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "participant_id","participant_name","status",
        "case_id","case_number","charges","date_of_conviction",
        "petition_completed","interview_completed","revenue_recovery_contacted",
        "declaration_completed","social_bio_completed","court_case_filed",
        "notes_count"
    ])
    rows = (
        db.session.query(
            Participant.id, Participant.first_name, Participant.last_name, Participant.status,
            Case.id, Case.case_number, Case.charges, Case.date_of_conviction,
            Case.petition_completed, Case.interview_completed, Case.revenue_recovery_contacted,
            Case.declaration_completed, Case.social_bio_completed, Case.court_case_filed
        )
        .join(Case, Case.participant_id == Participant.id)
        .all()
    )
    for r in rows:
        pid, fn, ln, pstatus, cid, cnum, charges, doc, pc, ic, rrc, dc, sbc, ccf = r
        notes_count = CaseNote.query.filter_by(case_id=cid).count()
        w.writerow([
            pid, f"{fn} {ln}".strip(), pstatus,
            cid, cnum, (charges or "").replace("\n", " ").strip(),
            doc.isoformat() if doc else "",
            int(pc), int(ic), int(rrc), int(dc), int(sbc), int(ccf),
            notes_count
        ])
    buf.seek(0)
    from io import BytesIO
    data = BytesIO(buf.getvalue().encode("utf-8"))
    return send_file(data, mimetype="text/csv", as_attachment=True, download_name="expungements_report.csv")

# Keep a second endpoint name for templates using url_for('reports')
app.add_url_rule("/reports", endpoint="reports", view_func=reports_home)


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
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5001)))
