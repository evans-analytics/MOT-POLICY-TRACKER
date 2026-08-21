from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file
import sqlite3
from datetime import datetime, timedelta
from google import genai
import pdfplumber
import io
import json
import os
import csv
import shutil
from werkzeug.utils import secure_filename

app = Flask(__name__)
DB_PATH = "policy_tracker.db"  # Local database in project folder
UPLOAD_FOLDER = "policy_documents"

# ─── Gemini Setup ─────────────────────────────────────────────────────────────
# IMPORTANT: Replace with your actual API key from https://aistudio.google.com/apikey
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "YOUR_API_KEY_HERE")
client = genai.Client(api_key=GEMINI_API_KEY)

# ─── Database Setup ───────────────────────────────────────────────────────────

def init_db():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
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
    conn.commit()
    conn.close()

# ─── Core Functions ───────────────────────────────────────────────────────────

def log_audit(policy_id, action, details=""):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
        (policy_id, action, details, datetime.now().isoformat(timespec="seconds"))
    )
    conn.commit()
    conn.close()

def search_by_client_name(name):
    conn = sqlite3.connect(DB_PATH)
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
            policies.policy_id
        FROM policies
        JOIN clients ON policies.client_id = clients.client_id
        JOIN file_log ON policies.policy_id = file_log.policy_id
        WHERE clients.full_name LIKE ?
    """, (f"%{name}%",))
    results = cursor.fetchall()
    conn.close()
    return results

def add_client_and_policy(full_name, phone, email, policy_number, policy_type, start_date, end_date, status, shelf_location):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO clients (full_name, phone, email) VALUES (?, ?, ?)",
                   (full_name, phone, email))
    client_id = cursor.lastrowid
    cursor.execute("""
        INSERT INTO policies (policy_number, policy_type, start_date, end_date, status, client_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (policy_number, policy_type, start_date, end_date, status, client_id))
    policy_id = cursor.lastrowid
    cursor.execute("INSERT INTO file_log (policy_id, shelf_location) VALUES (?, ?)",
                   (policy_id, shelf_location))
    cursor.execute(
        "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
        (policy_id, "created", f"Policy {policy_number} created", datetime.now().isoformat(timespec="seconds"))
    )
    conn.commit()
    conn.close()
    return policy_id

def get_all_policies(search_query="", status="", policy_type="", expiry_window=""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    conditions = []
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
    return results

def get_dashboard_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    stats = {
        "total": cursor.execute("SELECT COUNT(*) FROM policies").fetchone()[0],
        "active": cursor.execute("SELECT COUNT(*) FROM policies WHERE status='Active'").fetchone()[0],
        "expired": cursor.execute("SELECT COUNT(*) FROM policies WHERE status='Expired'").fetchone()[0],
        "expiring_soon": cursor.execute(
            "SELECT COUNT(*) FROM policies WHERE status='Active' AND end_date BETWEEN ? AND ?",
            (str(datetime.today().date()), str(datetime.today().date() + timedelta(days=30)))
        ).fetchone()[0]
    }
    conn.close()
    return stats

def get_renewal_history(policy_id):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT previous_start_date, previous_end_date, new_start_date, new_end_date, renewed_at "
        "FROM renewal_history WHERE policy_id=? ORDER BY renewed_at DESC", (policy_id,)
    ).fetchall()
    conn.close()
    return rows

def get_policy_documents(policy_id):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT document_id, filename, uploaded_at FROM policy_documents WHERE policy_id=? ORDER BY uploaded_at DESC",
        (policy_id,)
    ).fetchall()
    conn.close()
    return rows

def get_due_reminders():
    conn = sqlite3.connect(DB_PATH)
    today = datetime.today().date()
    rows = conn.execute(
        "SELECT policies.policy_id, clients.full_name, clients.email, policies.policy_number, policies.end_date "
        "FROM policies JOIN clients ON policies.client_id=clients.client_id "
        "WHERE policies.status='Active' AND policies.end_date BETWEEN ? AND ?",
        (str(today), str(today + timedelta(days=30)))
    ).fetchall()
    conn.close()
    return [{
        "policy_id": row[0], "client_name": row[1], "email": row[2],
        "policy_number": row[3], "end_date": row[4],
        "days_remaining": (datetime.strptime(row[4], "%Y-%m-%d").date() - today).days
    } for row in rows]

def get_record_by_policy_id(policy_id):
    conn = sqlite3.connect(DB_PATH)
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
            file_log.shelf_location
        FROM policies
        JOIN clients ON policies.client_id = clients.client_id
        JOIN file_log ON policies.policy_id = file_log.policy_id
        WHERE policies.policy_id = ?
    """, (policy_id,))
    result = cursor.fetchone()
    conn.close()
    return result

def update_record(client_id, policy_id, full_name, phone, email, policy_number, policy_type, start_date, end_date, status, shelf_location):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    previous_dates = cursor.execute(
        "SELECT start_date, end_date FROM policies WHERE policy_id=?", (policy_id,)
    ).fetchone()
    cursor.execute("UPDATE clients SET full_name=?, phone=?, email=? WHERE client_id=?",
                   (full_name, phone, email, client_id))
    cursor.execute("UPDATE policies SET policy_number=?, policy_type=?, start_date=?, end_date=?, status=? WHERE policy_id=?",
                   (policy_number, policy_type, start_date, end_date, status, policy_id))
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
    conn.commit()
    conn.close()

def delete_record(policy_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT client_id FROM policies WHERE policy_id=?", (policy_id,))
    row = cursor.fetchone()
    if row:
        client_id = row[0]
        cursor.execute("DELETE FROM file_log WHERE policy_id=?", (policy_id,))
        cursor.execute("DELETE FROM policies WHERE policy_id=?", (policy_id,))
        cursor.execute("DELETE FROM clients WHERE client_id=?", (client_id,))
        cursor.execute(
            "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
            (policy_id, "deleted", "Policy record deleted", datetime.now().isoformat(timespec="seconds"))
        )
    conn.commit()
    conn.close()

def mark_policy_expired(policy_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE policies SET status='Expired' WHERE policy_id=?", (policy_id,))
    cursor.execute(
        "INSERT INTO audit_log (policy_id, action, details, created_at) VALUES (?, ?, ?, ?)",
        (policy_id, "marked_expired", "Policy marked expired from risk dashboard", datetime.now().isoformat(timespec="seconds"))
    )
    conn.commit()
    conn.close()

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
        WHERE policies.status = 'Active' AND policies.end_date <= ? AND policies.end_date >= ?
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
        WHERE policies.status = 'Active' AND policies.end_date < ?
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
        WHERE clients.email IS NULL OR clients.email = ''
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

# ─── Document Intelligence ────────────────────────────────────────────────────

def extract_policy_from_pdf(pdf_bytes):
    text = ""
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page in pdf.pages:
                text += page.extract_text() or ""
    except Exception as e:
        return None, f"Error reading PDF: {str(e)}"

    if not text.strip():
        return None, "Could not extract text from PDF"

    prompt = f"""You are a data extraction assistant. Extract policy information from the following document text and return ONLY a JSON object with these exact keys:
- full_name (client full name)
- phone (phone number, empty string if not found)
- email (email address, empty string if not found)
- policy_number (policy number or ID)
- policy_type (type of policy e.g. Motor, Life, Fire, Health)
- start_date (in YYYY-MM-DD format, empty string if not found)
- end_date (in YYYY-MM-DD format, empty string if not found)
- status (Active or Expired)
- shelf_location (empty string if not found)

Return ONLY the JSON object, no explanation, no markdown, no backticks.

Document text:
{text[:3000]}"""

    try:
        if GEMINI_API_KEY == "YOUR_API_KEY_HERE":
            return None, "❌ Gemini API key not configured. Please set your API key in the environment or code."
        
        response = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        raw = response.text.strip()
        try:
            data = json.loads(raw)
            return data, None
        except json.JSONDecodeError:
            return None, "AI could not parse the document. Please fill in manually."
    except Exception as e:
        return None, f"API Error: {str(e)}. Check your API key is valid."

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    message = ""
    search_query = ""
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
            add_client_and_policy(
                request.form["full_name"],
                request.form["phone"],
                request.form["email"],
                request.form["policy_number"],
                request.form["policy_type"],
                request.form["start_date"],
                request.form["end_date"],
                request.form["status"],
                request.form["shelf_location"]
            )
            message = "Client and policy added successfully!"

    all_policies = get_all_policies(search_query, status_filter, policy_type_filter, expiry_window)
    risk_flags = get_risk_flags()
    return render_template("index.html",
                           results=results,
                           message=message,
                           search_query=search_query,
                           all_policies=all_policies,
                           risk_flags=risk_flags,
                           stats=get_dashboard_stats(),
                           status_filter=status_filter,
                           policy_type_filter=policy_type_filter,
                           expiry_window=expiry_window)

@app.route("/upload-pdf", methods=["POST"])
def upload_pdf():
    if "pdf_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["pdf_file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    pdf_bytes = file.read()
    data, error = extract_policy_from_pdf(pdf_bytes)
    if error:
        return jsonify({"error": error}), 500
    return jsonify(data)

@app.route("/edit/<int:policy_id>", methods=["GET", "POST"])
def edit(policy_id):
    if request.method == "POST":
        update_record(
            request.form["client_id"],
            policy_id,
            request.form["full_name"],
            request.form["phone"],
            request.form["email"],
            request.form["policy_number"],
            request.form["policy_type"],
            request.form["start_date"],
            request.form["end_date"],
            request.form["status"],
            request.form["shelf_location"]
        )
        return redirect(url_for("index"))
    record = get_record_by_policy_id(policy_id)
    if not record:
        return redirect(url_for("index"))
    return render_template("edit.html", record=record,
                           renewal_history=get_renewal_history(policy_id),
                           documents=get_policy_documents(policy_id))

@app.route("/delete/<int:policy_id>", methods=["POST"])
def delete(policy_id):
    delete_record(policy_id)
    return redirect(url_for("index"))

@app.route("/mark-expired/<int:policy_id>", methods=["POST"])
def mark_expired(policy_id):
    mark_policy_expired(policy_id)
    return redirect(url_for("index"))

@app.route("/export.csv")
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Client Name", "Phone", "Policy Number", "Policy Type", "Status", "Shelf Location", "End Date"])
    for row in get_all_policies():
        writer.writerow([row[0], row[1], row[2], row[3], row[4], row[5], row[8]])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode("utf-8")), mimetype="text/csv", as_attachment=True, download_name="policies.csv")

@app.route("/backup")
def backup_database():
    backup_name = f"policy_tracker_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    backup_path = os.path.join(UPLOAD_FOLDER, backup_name)
    shutil.copy2(DB_PATH, backup_path)
    return send_file(backup_path, as_attachment=True, download_name=backup_name)

@app.route("/policy/<int:policy_id>/document", methods=["POST"])
def upload_document(policy_id):
    file = request.files.get("document")
    if not file or not file.filename:
        return jsonify({"error": "Select a document first."}), 400
    filename = secure_filename(file.filename)
    stored_name = f"{policy_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
    stored_path = os.path.join(UPLOAD_FOLDER, stored_name)
    file.save(stored_path)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO policy_documents (policy_id, filename, stored_path, uploaded_at) VALUES (?, ?, ?, ?)",
        (policy_id, filename, stored_path, datetime.now().isoformat(timespec="seconds"))
    )
    conn.commit()
    conn.close()
    log_audit(policy_id, "document_uploaded", filename)
    return redirect(url_for("edit", policy_id=policy_id))

@app.route("/policy-document/<int:document_id>")
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
def due_notifications():
    return jsonify({"reminders": get_due_reminders(), "configured_channels": []})

@app.route("/policy/<int:policy_id>/history")
def policy_history(policy_id):
    conn = sqlite3.connect(DB_PATH)
    audit_rows = conn.execute(
        "SELECT action, details, created_at FROM audit_log WHERE policy_id=? ORDER BY created_at DESC", (policy_id,)
    ).fetchall()
    conn.close()
    return jsonify({"renewals": get_renewal_history(policy_id), "audit": audit_rows})

if __name__ == "__main__":
    init_db()
    app.run(debug=True)