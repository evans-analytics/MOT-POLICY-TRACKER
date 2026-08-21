from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, session
import sqlite3
from datetime import datetime, timedelta
import io
import os
import csv
import shutil
import re
import secrets
import hmac
from contextlib import contextmanager
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from services.ai_extraction import extract_policy_from_pdf

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
DB_PATH = os.getenv("POLICY_DB_PATH", "policy_tracker.db")
UPLOAD_FOLDER = os.getenv("POLICY_UPLOAD_FOLDER", "policy_documents")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))
ALLOWED_DOCUMENT_EXTENSIONS = {"pdf", "jpg", "jpeg", "png"}
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", "development-only-change-me"),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": f"File too large. Maximum size is {MAX_UPLOAD_MB} MB."}), 413

def allowed_file(filename, extensions=ALLOWED_DOCUMENT_EXTENSIONS):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in extensions

def valid_file_signature(file_bytes, filename):
    extension = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    signatures = {
        "pdf": file_bytes.startswith(b"%PDF-"),
        "png": file_bytes.startswith(b"\x89PNG\r\n\x1a\n"),
        "jpg": file_bytes.startswith(b"\xff\xd8\xff"),
        "jpeg": file_bytes.startswith(b"\xff\xd8\xff"),
    }
    return signatures.get(extension, False)

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}

@app.before_request
def validate_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken", "")
    expected_token = session.get("csrf_token", "")
    if not expected_token or not submitted_token or not hmac.compare_digest(submitted_token, expected_token):
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": "Invalid CSRF token."}), 400
        return "Invalid CSRF token", 400
    return None

def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped_view

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped_view(*args, **kwargs):
            if session.get("role") not in roles:
                return jsonify({"error": "You do not have permission to perform this action."}), 403
            return view(*args, **kwargs)
        return wrapped_view
    return decorator

@contextmanager
def transaction():
    conn = connect_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# ─── Database Setup ───────────────────────────────────────────────────────────

def init_db():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            client_id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT,
            phone TEXT,
            email TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_number TEXT,
            policy_type TEXT,
            start_date TEXT,
            end_date TEXT,
            status TEXT,
            client_id INTEGER,
            FOREIGN KEY (client_id) REFERENCES clients(client_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_log (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER,
            shelf_location TEXT,
            checked_out_by TEXT,
            date_checked_out TEXT,
            date_returned TEXT,
            FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS renewal_history (
            renewal_id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER NOT NULL,
            previous_start_date TEXT,
            previous_end_date TEXT,
            new_start_date TEXT,
            new_end_date TEXT,
            renewed_at TEXT NOT NULL,
            FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS policy_documents (
            document_id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notification_log (
            notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER NOT NULL,
            channel TEXT NOT NULL,
            reminder_days INTEGER NOT NULL,
            sent_at TEXT NOT NULL,
            FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Viewer',
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS claims (
            claim_id INTEGER PRIMARY KEY AUTOINCREMENT,
            claim_number TEXT NOT NULL UNIQUE,
            policy_id INTEGER NOT NULL,
            date_reported TEXT NOT NULL,
            claim_type TEXT NOT NULL,
            amount_claimed REAL,
            amount_approved REAL,
            adjuster TEXT,
            status TEXT NOT NULL DEFAULT 'Reported',
            settlement_date TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_movements (
            movement_id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id INTEGER NOT NULL,
            shelf_location TEXT,
            checked_out_by TEXT,
            checked_out_at TEXT NOT NULL,
            returned_at TEXT,
            notes TEXT,
            FOREIGN KEY (policy_id) REFERENCES policies(policy_id)
        )
    """)
    policy_columns = {row[1] for row in cursor.execute("PRAGMA table_info(policies)")}
    if "deleted_at" not in policy_columns:
        try:
            cursor.execute("ALTER TABLE policies ADD COLUMN deleted_at TEXT")
        except sqlite3.OperationalError as error:
            if "duplicate column name" not in str(error).lower():
                raise
    for column, column_type in {
        "premium": "REAL",
        "currency": "TEXT",
        "sum_insured": "REAL",
        "deductible": "REAL",
        "broker": "TEXT",
        "underwriter": "TEXT",
        "description": "TEXT",
        "created_at": "TEXT",
        "updated_at": "TEXT",
    }.items():
        if column not in policy_columns:
            cursor.execute(f"ALTER TABLE policies ADD COLUMN {column} {column_type}")
    admin_username = os.getenv("ADMIN_USERNAME", "").strip()
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    if admin_username and admin_password:
        existing_admin = cursor.execute(
            "SELECT user_id FROM users WHERE username=?", (admin_username,)
        ).fetchone()
        if not existing_admin:
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (admin_username, generate_password_hash(admin_password), "Admin",
                 datetime.now().isoformat(timespec="seconds"))
            )
    conn.commit()
    conn.close()

# ─── Core Functions ───────────────────────────────────────────────────────────

def log_audit(policy_id, action, details=""):
    conn = connect_db()
    conn.execute(
        "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
        (policy_id, action, details, datetime.now().isoformat(timespec="seconds"))
    )
    conn.commit()
    conn.close()

def validate_policy_data(full_name, phone, email, policy_number, policy_type,
                         start_date, end_date, status, policy_id=None,
                         premium=None, sum_insured=None, deductible=None):
    required_values = {
        "full name": full_name,
        "phone": phone,
        "policy number": policy_number,
        "policy type": policy_type,
        "start date": start_date,
        "end date": end_date,
    }
    missing = [label for label, value in required_values.items() if not str(value or "").strip()]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")

    try:
        start = datetime.strptime(start_date, "%Y-%m-%d").date()
        end = datetime.strptime(end_date, "%Y-%m-%d").date()
    except (TypeError, ValueError) as error:
        raise ValueError("Dates must use the YYYY-MM-DD format.") from error
    if end < start:
        raise ValueError("End date cannot be earlier than the start date.")
    if status not in {"Active", "Expired"}:
        raise ValueError("Status must be Active or Expired.")
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address.")
    for label, value in (("premium", premium), ("sum insured", sum_insured), ("deductible", deductible)):
        if value not in (None, ""):
            try:
                if float(value) < 0:
                    raise ValueError
            except (TypeError, ValueError) as error:
                raise ValueError(f"{label.title()} must be a non-negative number.") from error

    conn = connect_db()
    duplicate = conn.execute(
        "SELECT policy_id FROM policies WHERE policy_number=? AND deleted_at IS NULL AND policy_id IS NOT ?",
        (policy_number.strip(), policy_id)
    ).fetchone()
    conn.close()
    if duplicate:
        raise ValueError(f"Policy number '{policy_number}' already exists.")

def get_effective_status(start_date, end_date, stored_status):
    """Return the user-facing lifecycle status calculated from policy dates."""
    if stored_status != "Active":
        return stored_status
    try:
        today = datetime.today().date()
        end = datetime.strptime(end_date, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return stored_status
    if end < today:
        return "Expired"
    if end <= today + timedelta(days=30):
        return "Expiring Soon"
    return "Active"

def search_by_client_name(name):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            clients.full_name,
            clients.phone,
            policies.policy_number,
            policies.policy_type,
            policies.status,
            file_log.shelf_location,
            clients.client_id,
            policies.policy_id,
            policies.end_date
        FROM policies
        JOIN clients ON policies.client_id = clients.client_id
        JOIN file_log ON policies.policy_id = file_log.policy_id
        WHERE policies.deleted_at IS NULL AND clients.full_name LIKE ?
    """, (f"%{name}%",))
    results = cursor.fetchall()
    conn.close()
    return [
        (*row[:4], get_effective_status(row[7], row[8], row[4]), *row[5:])
        for row in results
    ]

def add_client_and_policy(full_name, phone, email, policy_number, policy_type, start_date, end_date, status, shelf_location,
                          premium=None, currency="", sum_insured=None, deductible=None,
                          broker="", underwriter="", description=""):
    validate_policy_data(full_name, phone, email, policy_number, policy_type,
                         start_date, end_date, status, premium=premium,
                         sum_insured=sum_insured, deductible=deductible)
    with transaction() as conn:
        cursor = conn.cursor()
        client = None
        if email.strip():
            client = cursor.execute(
                "SELECT client_id FROM clients WHERE lower(trim(email))=lower(trim(?))",
                (email,)
            ).fetchone()
        if not client and phone.strip():
            client = cursor.execute(
                "SELECT client_id FROM clients WHERE phone=?", (phone,)
            ).fetchone()
        if client:
            client_id = client[0]
            cursor.execute(
                "UPDATE clients SET full_name=?, phone=?, email=? WHERE client_id=?",
                (full_name, phone, email, client_id)
            )
        else:
            cursor.execute("INSERT INTO clients (full_name, phone, email) VALUES (?, ?, ?)",
                           (full_name, phone, email))
            client_id = cursor.lastrowid
        cursor.execute("""
            INSERT INTO policies (policy_number, policy_type, start_date, end_date, status, client_id,
                                  premium, currency, sum_insured, deductible, broker, underwriter, description,
                                  created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (policy_number, policy_type, start_date, end_date, status, client_id,
              premium or None, currency, sum_insured or None, deductible or None,
              broker, underwriter, description, datetime.now().isoformat(timespec="seconds"),
              datetime.now().isoformat(timespec="seconds")))
        policy_id = cursor.lastrowid
        cursor.execute("INSERT INTO file_log (policy_id, shelf_location) VALUES (?, ?)",
                       (policy_id, shelf_location))
        cursor.execute(
            "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (policy_id, "created", f"Policy {policy_number} created", datetime.now().isoformat(timespec="seconds"))
        )
    return policy_id

def get_all_policies(search_query="", status="", policy_type="", expiry_window=""):
    conn = connect_db()
    cursor = conn.cursor()
    conditions = ["policies.deleted_at IS NULL"]
    parameters = []
    if search_query:
        conditions.append("(clients.full_name LIKE ? OR clients.phone LIKE ? OR policies.policy_number LIKE ?)")
        parameters.extend([f"%{search_query}%"] * 3)
    if status:
        conditions.append("policies.status = ?")
        parameters.append(status)
    if policy_type:
        conditions.append("policies.policy_type = ?")
        parameters.append(policy_type)
    if expiry_window in {"7", "30", "60"}:
        conditions.append("policies.status = 'Active' AND policies.end_date BETWEEN ? AND ?")
        parameters.extend([str(datetime.today().date()), str(datetime.today().date() + timedelta(days=int(expiry_window)))])
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    cursor.execute("""
        SELECT 
            clients.full_name,
            clients.phone,
            policies.policy_number,
            policies.policy_type,
            policies.status,
            file_log.shelf_location,
            clients.client_id,
            policies.policy_id,
            policies.end_date
        FROM policies
        JOIN clients ON policies.client_id = clients.client_id
        JOIN file_log ON policies.policy_id = file_log.policy_id
        """ + where_clause + " ORDER BY clients.full_name ASC", parameters)
    results = cursor.fetchall()
    conn.close()
    return [
        (*row[:4], get_effective_status(row[7], row[8], row[4]), *row[5:])
        for row in results
    ]

def get_dashboard_stats():
    conn = connect_db()
    cursor = conn.cursor()
    policies = cursor.execute(
        "SELECT start_date, end_date, status FROM policies WHERE deleted_at IS NULL"
    ).fetchall()
    financials = cursor.execute(
        "SELECT COALESCE(SUM(premium), 0), COALESCE(SUM(sum_insured), 0) "
        "FROM policies WHERE deleted_at IS NULL"
    ).fetchone()
    claims = cursor.execute(
        "SELECT COUNT(*) FROM claims WHERE status NOT IN ('Closed', 'Rejected')"
    ).fetchone()[0]
    conn.close()
    statuses = [get_effective_status(row[0], row[1], row[2]) for row in policies]
    return {
        "total": len(statuses),
        "active": statuses.count("Active"),
        "expired": statuses.count("Expired"),
        "expiring_soon": statuses.count("Expiring Soon"),
        "open_claims": claims,
        "total_premium": financials[0],
        "total_exposure": financials[1],
    }

def get_dashboard_analytics():
    conn = connect_db()
    type_rows = conn.execute(
        "SELECT policy_type, COUNT(*) FROM policies WHERE deleted_at IS NULL GROUP BY policy_type ORDER BY COUNT(*) DESC"
    ).fetchall()
    status_rows = conn.execute(
        "SELECT start_date, end_date, status FROM policies WHERE deleted_at IS NULL"
    ).fetchall()
    conn.close()
    statuses = [get_effective_status(row[0], row[1], row[2]) for row in status_rows]
    return {
        "policy_types": [{"label": row[0] or "Unclassified", "count": row[1]} for row in type_rows],
        "statuses": [
            {"label": label, "count": statuses.count(label)}
            for label in ("Active", "Expiring Soon", "Expired")
        ],
    }

def get_renewal_history(policy_id):
    conn = connect_db()
    rows = conn.execute(
        "SELECT previous_start_date, previous_end_date, new_start_date, new_end_date, renewed_at "
        "FROM renewal_history WHERE policy_id=? ORDER BY renewed_at DESC", (policy_id,)
    ).fetchall()
    conn.close()
    return rows

def get_policy_documents(policy_id):
    conn = connect_db()
    rows = conn.execute(
        "SELECT document_id, filename, uploaded_at FROM policy_documents WHERE policy_id=? ORDER BY uploaded_at DESC",
        (policy_id,)
    ).fetchall()
    conn.close()
    return rows

def get_due_reminders():
    conn = connect_db()
    today = datetime.today().date()
    rows = conn.execute(
        "SELECT policies.policy_id, clients.full_name, clients.email, policies.policy_number, policies.end_date "
        "FROM policies JOIN clients ON policies.client_id=clients.client_id "
        "WHERE policies.deleted_at IS NULL AND policies.status='Active' AND policies.end_date BETWEEN ? AND ?",
        (str(today), str(today + timedelta(days=30)))
    ).fetchall()
    conn.close()
    return [{
        "policy_id": row[0], "client_name": row[1], "email": row[2],
        "policy_number": row[3], "end_date": row[4],
        "days_remaining": (datetime.strptime(row[4], "%Y-%m-%d").date() - today).days
    } for row in rows]

CLAIM_STATUSES = {"Reported", "Under Investigation", "Assessment", "Approved", "Rejected", "Payment", "Closed"}

def validate_claim_data(claim_number, policy_id, date_reported, claim_type,
                        amount_claimed, amount_approved, status):
    if not claim_number.strip() or not claim_type.strip() or not date_reported.strip():
        raise ValueError("Claim number, claim type, and report date are required.")
    try:
        datetime.strptime(date_reported, "%Y-%m-%d")
    except ValueError as error:
        raise ValueError("Report date must use the YYYY-MM-DD format.") from error
    for label, value in (("Amount claimed", amount_claimed), ("Amount approved", amount_approved)):
        if value not in (None, ""):
            try:
                if float(value) < 0:
                    raise ValueError
            except (TypeError, ValueError) as error:
                raise ValueError(f"{label} must be a non-negative number.") from error
    if status not in CLAIM_STATUSES:
        raise ValueError("Invalid claim status.")
    conn = connect_db()
    policy = conn.execute(
        "SELECT 1 FROM policies WHERE policy_id=? AND deleted_at IS NULL", (policy_id,)
    ).fetchone()
    duplicate = conn.execute(
        "SELECT 1 FROM claims WHERE claim_number=?", (claim_number.strip(),)
    ).fetchone()
    conn.close()
    if not policy:
        raise ValueError("Policy not found.")
    if duplicate:
        raise ValueError(f"Claim number '{claim_number}' already exists.")

def create_claim(claim_number, policy_id, date_reported, claim_type,
                 amount_claimed, amount_approved, adjuster, status,
                 settlement_date, notes):
    validate_claim_data(claim_number, policy_id, date_reported, claim_type,
                        amount_claimed, amount_approved, status)
    timestamp = datetime.now().isoformat(timespec="seconds")
    with transaction() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO claims (claim_number, policy_id, date_reported, claim_type, amount_claimed, "
            "amount_approved, adjuster, status, settlement_date, notes, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (claim_number.strip(), policy_id, date_reported, claim_type.strip(),
             amount_claimed or None, amount_approved or None, adjuster.strip(), status,
             settlement_date or None, notes.strip(), timestamp, timestamp)
        )
        claim_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (policy_id, "claim_created", f"Claim {claim_number} created", timestamp)
        )
    return claim_id

def get_claims(status=""):
    conn = connect_db()
    query = """
        SELECT claims.claim_id, claims.claim_number, claims.date_reported,
               claims.claim_type, claims.amount_claimed, claims.amount_approved,
               claims.adjuster, claims.status, claims.settlement_date,
               clients.full_name, policies.policy_number, claims.notes
        FROM claims
        JOIN policies ON claims.policy_id=policies.policy_id
        JOIN clients ON policies.client_id=clients.client_id
        WHERE policies.deleted_at IS NULL
    """
    parameters = []
    if status:
        query += " AND claims.status=?"
        parameters.append(status)
    query += " ORDER BY claims.date_reported DESC, claims.claim_id DESC"
    rows = conn.execute(query, parameters).fetchall()
    conn.close()
    return rows

def update_claim_status(claim_id, status):
    if status not in CLAIM_STATUSES:
        raise ValueError("Invalid claim status.")
    with transaction() as conn:
        claim = conn.execute(
            "SELECT policy_id FROM claims WHERE claim_id=?", (claim_id,)
        ).fetchone()
        if not claim:
            return False
        timestamp = datetime.now().isoformat(timespec="seconds")
        conn.execute("UPDATE claims SET status=?, updated_at=? WHERE claim_id=?", (status, timestamp, claim_id))
        conn.execute(
            "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (claim[0], "claim_status_changed", f"Claim {claim_id} changed to {status}", timestamp)
        )
    return True

def get_file_movements(policy_id=None):
    conn = connect_db()
    query = """
        SELECT file_movements.movement_id, file_movements.policy_id,
               policies.policy_number, file_movements.shelf_location,
               file_movements.checked_out_by, file_movements.checked_out_at,
               file_movements.returned_at, file_movements.notes
        FROM file_movements JOIN policies ON file_movements.policy_id=policies.policy_id
        WHERE policies.deleted_at IS NULL
    """
    params = []
    if policy_id is not None:
        query += " AND file_movements.policy_id=?"
        params.append(policy_id)
    query += " ORDER BY file_movements.checked_out_at DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows

def checkout_file(policy_id, shelf_location, checked_out_by, notes=""):
    if not policy_exists(policy_id):
        raise ValueError("Policy not found.")
    if not shelf_location.strip() or not checked_out_by.strip():
        raise ValueError("Shelf location and staff member are required.")
    with transaction() as conn:
        active = conn.execute(
            "SELECT movement_id FROM file_movements WHERE policy_id=? AND returned_at IS NULL", (policy_id,)
        ).fetchone()
        if active:
            raise ValueError("This file is already checked out.")
        timestamp = datetime.now().isoformat(timespec="seconds")
        conn.execute(
            "INSERT INTO file_movements (policy_id, shelf_location, checked_out_by, checked_out_at, notes) VALUES (?, ?, ?, ?, ?)",
            (policy_id, shelf_location.strip(), checked_out_by.strip(), timestamp, notes.strip())
        )
        conn.execute(
            "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (policy_id, "file_checked_out", f"File checked out by {checked_out_by}", timestamp)
        )

def return_file(movement_id, notes=""):
    with transaction() as conn:
        movement = conn.execute(
            "SELECT policy_id FROM file_movements WHERE movement_id=? AND returned_at IS NULL", (movement_id,)
        ).fetchone()
        if not movement:
            return False
        timestamp = datetime.now().isoformat(timespec="seconds")
        conn.execute(
            "UPDATE file_movements SET returned_at=?, notes=COALESCE(NULLIF(?, ''), notes) WHERE movement_id=?",
            (timestamp, notes.strip(), movement_id)
        )
        conn.execute(
            "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (movement[0], "file_returned", f"File movement {movement_id} returned", timestamp)
        )
    return True

def get_record_by_policy_id(policy_id):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            clients.client_id,
            clients.full_name,
            clients.phone,
            clients.email,
            policies.policy_id,
            policies.policy_number,
            policies.policy_type,
            policies.start_date,
            policies.end_date,
            policies.status,
            file_log.shelf_location,
            policies.premium,
            policies.currency,
            policies.sum_insured,
            policies.deductible,
            policies.broker,
            policies.underwriter,
            policies.description
        FROM policies
        JOIN clients ON policies.client_id = clients.client_id
        JOIN file_log ON policies.policy_id = file_log.policy_id
        WHERE policies.deleted_at IS NULL AND policies.policy_id = ?
    """, (policy_id,))
    result = cursor.fetchone()
    conn.close()
    return result

def policy_exists(policy_id):
    conn = connect_db()
    result = conn.execute(
        "SELECT 1 FROM policies WHERE policy_id=? AND deleted_at IS NULL", (policy_id,)
    ).fetchone()
    conn.close()
    return result is not None

def update_record(client_id, policy_id, full_name, phone, email, policy_number, policy_type, start_date, end_date, status, shelf_location,
                  premium=None, currency="", sum_insured=None, deductible=None,
                  broker="", underwriter="", description=""):
    validate_policy_data(full_name, phone, email, policy_number, policy_type,
                         start_date, end_date, status, policy_id,
                         premium=premium, sum_insured=sum_insured, deductible=deductible)
    with transaction() as conn:
        cursor = conn.cursor()
        previous_dates = cursor.execute(
            "SELECT start_date, end_date FROM policies WHERE deleted_at IS NULL AND policy_id=?", (policy_id,)
        ).fetchone()
        cursor.execute("UPDATE clients SET full_name=?, phone=?, email=? WHERE client_id=?",
                       (full_name, phone, email, client_id))
        cursor.execute("""
            UPDATE policies SET policy_number=?, policy_type=?, start_date=?, end_date=?, status=?,
                premium=?, currency=?, sum_insured=?, deductible=?, broker=?, underwriter=?,
                description=?, updated_at=?
            WHERE deleted_at IS NULL AND policy_id=?
        """, (policy_number, policy_type, start_date, end_date, status,
               premium or None, currency, sum_insured or None, deductible or None,
               broker, underwriter, description, datetime.now().isoformat(timespec="seconds"), policy_id))
        cursor.execute("UPDATE file_log SET shelf_location=? WHERE policy_id=?",
                       (shelf_location, policy_id))
        if previous_dates and previous_dates != (start_date, end_date):
            cursor.execute(
                "INSERT INTO renewal_history (policy_id, previous_start_date, previous_end_date, new_start_date, new_end_date, renewed_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (policy_id, previous_dates[0], previous_dates[1], start_date, end_date,
                 datetime.now().isoformat(timespec="seconds"))
            )
            action = "renewed"
            details = f"Policy dates changed from {previous_dates[0]} - {previous_dates[1]} to {start_date} - {end_date}"
        else:
            action = "updated"
            details = f"Policy {policy_number} updated"
        cursor.execute(
            "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (policy_id, action, details, datetime.now().isoformat(timespec="seconds"))
        )

def delete_record(policy_id):
    with transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT policy_number FROM policies WHERE deleted_at IS NULL AND policy_id=?", (policy_id,))
        row = cursor.fetchone()
        if row:
            deleted_at = datetime.now().isoformat(timespec="seconds")
            cursor.execute("UPDATE policies SET deleted_at=? WHERE policy_id=?", (deleted_at, policy_id))
            cursor.execute(
                "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
                (policy_id, "deleted", f"Policy {row[0]} soft-deleted", deleted_at)
            )

def mark_policy_expired(policy_id):
    if not policy_exists(policy_id):
        return False
    with transaction() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE policies SET status='Expired' WHERE deleted_at IS NULL AND policy_id=?", (policy_id,))
        cursor.execute(
            "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (policy_id, "marked_expired", "Policy marked expired from risk dashboard", datetime.now().isoformat(timespec="seconds"))
        )
    return True

# ─── Step 1: Risk Flagging ────────────────────────────────────────────────────

def get_risk_flags():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    flags = []
    today = datetime.today().date()
    soon = today + timedelta(days=30)

    # Flag 1: Expiring within 30 days
    cursor.execute("""
        SELECT clients.full_name, policies.policy_number, policies.end_date, policies.policy_id
        FROM policies
        JOIN clients ON policies.client_id = clients.client_id
        WHERE policies.deleted_at IS NULL AND policies.status = 'Active' AND policies.end_date <= ? AND policies.end_date >= ?
    """, (str(soon), str(today)))
    for row in cursor.fetchall():
        flags.append({
            "type": "expiring_soon",
            "level": "warning",
            "icon": "⚠️",
            "message": f"{row[0]}'s policy ({row[1]}) expires on {row[2]}",
            "policy_id": row[3]
        })

    # Flag 2: Already expired but still marked Active
    cursor.execute("""
        SELECT clients.full_name, policies.policy_number, policies.end_date, policies.policy_id
        FROM policies
        JOIN clients ON policies.client_id = clients.client_id
        WHERE policies.deleted_at IS NULL AND policies.status = 'Active' AND policies.end_date < ?
    """, (str(today),))
    for row in cursor.fetchall():
        flags.append({
            "type": "expired_active",
            "level": "danger",
            "icon": "🔴",
            "message": f"{row[0]}'s policy ({row[1]}) expired on {row[2]} but is still marked Active",
            "policy_id": row[3]
        })

    # Flag 3: Duplicate policy numbers
    cursor.execute("""
        SELECT policy_number, COUNT(*) as count
        FROM policies
        WHERE deleted_at IS NULL
        GROUP BY policy_number
        HAVING count > 1
    """)
    for row in cursor.fetchall():
        flags.append({
            "type": "duplicate",
            "level": "danger",
            "icon": "🔴",
            "message": f"Duplicate policy number detected: {row[0]} appears {row[1]} times",
            "policy_id": None
        })

    # Flag 4: Missing email
    cursor.execute("""
        SELECT clients.full_name, policies.policy_id
        FROM clients
        JOIN policies ON policies.client_id = clients.client_id
        WHERE policies.deleted_at IS NULL AND (clients.email IS NULL OR clients.email = '')
    """)
    for row in cursor.fetchall():
        flags.append({
            "type": "missing_email",
            "level": "info",
            "icon": "ℹ️",
            "message": f"{row[0]} has no email address on file",
            "policy_id": row[1]
        })

    conn.close()
    return flags

def get_policy_risk_score(policy_id):
    conn = connect_db()
    policy = conn.execute("""
        SELECT policies.policy_number, policies.end_date, policies.status,
               policies.premium, policies.sum_insured, clients.email,
               (SELECT COUNT(*) FROM policy_documents WHERE policy_id=policies.policy_id),
               (SELECT COUNT(*) FROM policies duplicate WHERE duplicate.policy_number=policies.policy_number
                AND duplicate.deleted_at IS NULL)
        FROM policies JOIN clients ON policies.client_id=clients.client_id
        WHERE policies.policy_id=? AND policies.deleted_at IS NULL
    """, (policy_id,)).fetchone()
    conn.close()
    if not policy:
        return None

    score = 0
    reasons = []
    effective_status = get_effective_status(policy[1], policy[1], policy[2])
    try:
        days_remaining = (datetime.strptime(policy[1], "%Y-%m-%d").date() - datetime.today().date()).days
    except (TypeError, ValueError):
        days_remaining = None
    if days_remaining is not None and days_remaining < 0:
        score += 40
        reasons.append("Policy has expired")
    elif days_remaining is not None and days_remaining <= 30:
        score += 25
        reasons.append(f"Expires in {days_remaining} days")
    if not policy[5]:
        score += 15
        reasons.append("Client email is missing")
    if not policy[6]:
        score += 15
        reasons.append("No policy document is attached")
    if policy[3] is None:
        score += 10
        reasons.append("Premium is missing")
    if policy[4] is None:
        score += 10
        reasons.append("Sum insured is missing")
    if policy[7] > 1:
        score += 25
        reasons.append("Duplicate policy number detected")
    score = min(score, 100)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    return {"policy_id": policy_id, "score": score, "level": level, "reasons": reasons}

def get_portfolio_risk():
    conn = connect_db()
    policy_ids = [row[0] for row in conn.execute(
        "SELECT policy_id FROM policies WHERE deleted_at IS NULL ORDER BY policy_id"
    ).fetchall()]
    conn.close()
    scores = [get_policy_risk_score(policy_id) for policy_id in policy_ids]
    scores = [score for score in scores if score]
    return sorted(scores, key=lambda item: item["score"], reverse=True)

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = connect_db()
        user = conn.execute(
            "SELECT user_id, username, password_hash, role FROM users WHERE username=? AND active=1",
            (username,)
        ).fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session.clear()
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]
            next_url = request.args.get("next", "/")
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = "/"
            return redirect(next_url)
        return render_template("login.html", error="Invalid username or password."), 401
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/claims", methods=["GET", "POST"])
@role_required("Admin", "Claims Officer")
def claims():
    error = ""
    if request.method == "POST":
        try:
            create_claim(
                request.form.get("claim_number", ""), request.form.get("policy_id", ""),
                request.form.get("date_reported", ""), request.form.get("claim_type", ""),
                request.form.get("amount_claimed"), request.form.get("amount_approved"),
                request.form.get("adjuster", ""), "Reported", request.form.get("settlement_date"),
                request.form.get("notes", "")
            )
            return redirect(url_for("claims"))
        except ValueError as validation_error:
            error = str(validation_error)
    conn = connect_db()
    policies = conn.execute(
        "SELECT policies.policy_id, policies.policy_number, clients.full_name "
        "FROM policies JOIN clients ON policies.client_id=clients.client_id "
        "WHERE policies.deleted_at IS NULL ORDER BY policies.policy_number"
    ).fetchall()
    stats = {
        "total": conn.execute("SELECT COUNT(*) FROM claims").fetchone()[0],
        "open": conn.execute("SELECT COUNT(*) FROM claims WHERE status NOT IN ('Closed', 'Rejected')").fetchone()[0],
        "approved": conn.execute("SELECT COUNT(*) FROM claims WHERE status='Approved'").fetchone()[0],
    }
    conn.close()
    return render_template("claims.html", claims=get_claims(), policies=policies, stats=stats, error=error)

@app.route("/claims/<int:claim_id>/status", methods=["POST"])
@role_required("Admin", "Claims Officer")
def claim_status(claim_id):
    if not update_claim_status(claim_id, request.form.get("status", "")):
        return "Claim not found", 404
    return redirect(url_for("claims"))

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    results = []
    message = ""
    search_query = request.args.get("search_query", "")
    status_filter = request.args.get("status", "")
    policy_type_filter = request.args.get("policy_type", "")
    expiry_window = request.args.get("expiry_window", "")

    if request.method == "POST":
        if "search" in request.form:
            search_query = request.form["search_query"]
            results = search_by_client_name(search_query)
            if not results:
                message = f"No records found for '{search_query}'"

        elif "add" in request.form:
            try:
                add_client_and_policy(
                    request.form["full_name"], request.form["phone"], request.form["email"],
                    request.form["policy_number"], request.form["policy_type"],
                    request.form["start_date"], request.form["end_date"],
                    request.form["status"], request.form["shelf_location"],
                    request.form.get("premium"), request.form.get("currency", ""),
                    request.form.get("sum_insured"), request.form.get("deductible"),
                    request.form.get("broker", ""), request.form.get("underwriter", ""),
                    request.form.get("description", "")
                )
                message = "Client and policy added successfully!"
            except ValueError as error:
                message = str(error)

    all_policies = get_all_policies(search_query, status_filter, policy_type_filter, expiry_window)
    risk_flags = get_risk_flags()
    return render_template("index.html",
                           results=results,
                           message=message,
                           search_query=search_query,
                           all_policies=all_policies,
                           risk_flags=risk_flags,
                           stats=get_dashboard_stats(),
                           analytics=get_dashboard_analytics(),
                           status_filter=status_filter,
                           policy_type_filter=policy_type_filter,
                           expiry_window=expiry_window)

@app.route("/upload-pdf", methods=["POST"])
@role_required("Admin", "Underwriter", "Operations")
def upload_pdf():
    if "pdf_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["pdf_file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename, {"pdf"}):
        return jsonify({"error": "Only PDF files are supported."}), 400
    pdf_bytes = file.read()
    if not valid_file_signature(pdf_bytes, file.filename):
        return jsonify({"error": "The uploaded file is not a valid PDF."}), 400
    data, error = extract_policy_from_pdf(pdf_bytes)
    if error:
        return jsonify({"error": error}), 500
    return jsonify(data)

@app.route("/edit/<int:policy_id>", methods=["GET", "POST"])
@role_required("Admin", "Underwriter", "Operations")
def edit(policy_id):
    if request.method == "POST":
        try:
            update_record(
                request.form["client_id"], policy_id, request.form["full_name"],
                request.form["phone"], request.form["email"], request.form["policy_number"],
                request.form["policy_type"], request.form["start_date"],
                request.form["end_date"], request.form["status"], request.form["shelf_location"],
                request.form.get("premium"), request.form.get("currency", ""),
                request.form.get("sum_insured"), request.form.get("deductible"),
                request.form.get("broker", ""), request.form.get("underwriter", ""),
                request.form.get("description", "")
            )
            return redirect(url_for("index"))
        except ValueError as error:
            record = get_record_by_policy_id(policy_id)
            return render_template("edit.html", record=record, error=str(error),
                                   renewal_history=get_renewal_history(policy_id),
                                   documents=get_policy_documents(policy_id),
                                   effective_status=get_effective_status(record[7], record[8], record[9])), 400
    record = get_record_by_policy_id(policy_id)
    if not record:
        return redirect(url_for("index"))
    return render_template("edit.html", record=record,
                           renewal_history=get_renewal_history(policy_id),
                           documents=get_policy_documents(policy_id),
                           effective_status=get_effective_status(record[7], record[8], record[9]))

@app.route("/delete/<int:policy_id>", methods=["POST"])
@role_required("Admin")
def delete(policy_id):
    delete_record(policy_id)
    return redirect(url_for("index"))

@app.route("/mark-expired/<int:policy_id>", methods=["POST"])
@role_required("Admin", "Underwriter", "Operations")
def mark_expired(policy_id):
    if not mark_policy_expired(policy_id):
        return "Policy not found", 404
    return redirect(url_for("index"))

@app.route("/export.csv")
@login_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Client Name", "Phone", "Policy Number", "Policy Type", "Status", "Shelf Location", "End Date"])
    for row in get_all_policies():
        writer.writerow([row[0], row[1], row[2], row[3], row[4], row[5], row[8]])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), mimetype="text/csv", as_attachment=True, download_name="policies.csv")

@app.route("/backup")
@role_required("Admin")
def backup_database():
    backup_name = f"policy_tracker_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    backup_path = os.path.join(UPLOAD_FOLDER, backup_name)
    shutil.copy2(DB_PATH, backup_path)
    return send_file(backup_path, as_attachment=True, download_name=backup_name)

@app.route("/policy/<int:policy_id>/document", methods=["POST"])
@role_required("Admin", "Operations", "Underwriter")
def upload_document(policy_id):
    if not policy_exists(policy_id):
        return jsonify({"error": "Policy not found."}), 404
    file = request.files.get("document")
    if not file or not file.filename:
        return jsonify({"error": "Select a document first."}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Allowed files: PDF, JPG, JPEG, and PNG."}), 400
    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({"error": "Invalid filename."}), 400
    file_bytes = file.read()
    if not valid_file_signature(file_bytes, filename):
        return jsonify({"error": "The file content does not match its extension."}), 400
    file.stream.seek(0)
    stored_name = f"{policy_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
    stored_path = os.path.join(UPLOAD_FOLDER, stored_name)
    try:
        file.save(stored_path)
        with transaction() as conn:
            conn.execute(
                "INSERT INTO policy_documents (policy_id, filename, stored_path, uploaded_at) VALUES (?, ?, ?, ?)",
                (policy_id, filename, stored_path, datetime.now().isoformat(timespec="seconds"))
            )
            conn.execute(
                "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
                (policy_id, "document_uploaded", filename, datetime.now().isoformat(timespec="seconds"))
            )
    except Exception:
        if os.path.exists(stored_path):
            os.remove(stored_path)
        return jsonify({"error": "Document could not be saved."}), 500
    return redirect(url_for("edit", policy_id=policy_id))

@app.route("/policy-document/<int:document_id>")
@login_required
def download_document(document_id):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT filename, stored_path FROM policy_documents WHERE document_id=?", (document_id,)
    ).fetchone()
    conn.close()
    if not row or not os.path.exists(row[1]):
        return "Document not found", 404
    return send_file(row[1], as_attachment=True, download_name=row[0])

@app.route("/notifications/due")
@login_required
def due_notifications():
    return jsonify({"reminders": get_due_reminders(), "configured_channels": []})

@app.route("/risk-score/<int:policy_id>")
@login_required
def risk_score(policy_id):
    result = get_policy_risk_score(policy_id)
    if not result:
        return jsonify({"error": "Policy not found."}), 404
    return jsonify(result)

@app.route("/risk-intelligence")
@login_required
def risk_intelligence():
    scores = get_portfolio_risk()
    portfolio_score = round(sum(item["score"] for item in scores) / len(scores)) if scores else 0
    return render_template(
        "risk_intelligence.html",
        scores=scores,
        portfolio_score=portfolio_score,
        critical=[item for item in scores if item["level"] == "HIGH"],
        warnings=[item for item in scores if item["level"] == "MEDIUM"],
    )

@app.route("/analytics")
@login_required
def analytics():
    return render_template(
        "analytics.html",
        stats=get_dashboard_stats(),
        analytics=get_dashboard_analytics(),
        risk_scores=get_portfolio_risk(),
    )

@app.route("/global-search")
@login_required
def global_search():
    query = request.args.get("q", "").strip()
    if len(query) < 2:
        return jsonify({"results": []})
    pattern = f"%{query}%"
    conn = connect_db()
    results = []
    for row in conn.execute(
        "SELECT policy_id, policy_number, policy_type FROM policies "
        "WHERE deleted_at IS NULL AND (policy_number LIKE ? OR policy_type LIKE ?) LIMIT 8",
        (pattern, pattern)
    ):
        results.append({"type": "Policy", "label": row[1], "detail": row[2], "url": f"/edit/{row[0]}"})
    for row in conn.execute(
        "SELECT client_id, full_name, phone FROM clients "
        "WHERE full_name LIKE ? OR phone LIKE ? LIMIT 8", (pattern, pattern)
    ):
        results.append({"type": "Client", "label": row[1], "detail": row[2] or "", "url": f"/?search_query={row[1]}"})
    for row in conn.execute(
        "SELECT claim_id, claim_number, claim_type FROM claims "
        "WHERE claim_number LIKE ? OR claim_type LIKE ? LIMIT 8", (pattern, pattern)
    ):
        results.append({"type": "Claim", "label": row[1], "detail": row[2], "url": "/claims"})
    for row in conn.execute(
        "SELECT document_id, filename, uploaded_at FROM policy_documents WHERE filename LIKE ? LIMIT 8", (pattern,)
    ):
        results.append({"type": "Document", "label": row[1], "detail": row[2], "url": f"/policy-document/{row[0]}"})
    conn.close()
    return jsonify({"results": results[:20]})

@app.route("/file-tracking", methods=["GET", "POST"])
@role_required("Admin", "Operations")
def file_tracking():
    error = ""
    if request.method == "POST":
        try:
            checkout_file(
                request.form.get("policy_id", ""), request.form.get("shelf_location", ""),
                request.form.get("checked_out_by", ""), request.form.get("notes", "")
            )
            return redirect(url_for("file_tracking"))
        except ValueError as validation_error:
            error = str(validation_error)
    conn = connect_db()
    policies = conn.execute(
        "SELECT policies.policy_id, policies.policy_number, clients.full_name FROM policies "
        "JOIN clients ON policies.client_id=clients.client_id WHERE policies.deleted_at IS NULL ORDER BY policies.policy_number"
    ).fetchall()
    conn.close()
    return render_template("file_tracking.html", policies=policies, movements=get_file_movements(), error=error)

@app.route("/file-tracking/<int:movement_id>/return", methods=["POST"])
@role_required("Admin", "Operations")
def file_tracking_return(movement_id):
    if not return_file(movement_id):
        return "File movement not found", 404
    return redirect(url_for("file_tracking"))

@app.route("/policy/<int:policy_id>/history")
@login_required
def policy_history(policy_id):
    conn = sqlite3.connect(DB_PATH)
    audit_rows = conn.execute(
        "SELECT action, details, created_at FROM audit_log WHERE policy_id=? ORDER BY created_at DESC", (policy_id,)
    ).fetchall()
    conn.close()
    return jsonify({"renewals": get_renewal_history(policy_id), "audit": audit_rows})

if __name__ == "__main__":
    init_db()
    debug_mode = os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}
    port = int(os.getenv("FLASK_PORT", "5000"))
    app.run(debug=debug_mode, port=port)
    
   