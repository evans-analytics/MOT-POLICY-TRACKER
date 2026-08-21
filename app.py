from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
from datetime import datetime, timedelta
from google import genai
import pdfplumber
import io
import json
import os

app = Flask(__name__)
DB_PATH = "policy_tracker.db"  # Local database in project folder

# ─── Gemini Setup ─────────────────────────────────────────────────────────────
# IMPORTANT: Replace with your actual API key from https://aistudio.google.com/apikey
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "YOUR_API_KEY_HERE")
client = genai.Client(api_key=GEMINI_API_KEY)

# ─── Database Setup ───────────────────────────────────────────────────────────

def init_db():
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
    conn.commit()
    conn.close()

# ─── Core Functions ───────────────────────────────────────────────────────────

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
    conn.commit()
    conn.close()

def get_all_policies():
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
            policies.policy_id,
            policies.end_date
        FROM policies
        JOIN clients ON policies.client_id = clients.client_id
        JOIN file_log ON policies.policy_id = file_log.policy_id
        ORDER BY clients.full_name ASC
    """)
    results = cursor.fetchall()
    conn.close()
    return results

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
    cursor.execute("UPDATE clients SET full_name=?, phone=?, email=? WHERE client_id=?",
                   (full_name, phone, email, client_id))
    cursor.execute("UPDATE policies SET policy_number=?, policy_type=?, start_date=?, end_date=?, status=? WHERE policy_id=?",
                   (policy_number, policy_type, start_date, end_date, status, policy_id))
    cursor.execute("UPDATE file_log SET shelf_location=? WHERE policy_id=?",
                   (shelf_location, policy_id))
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
    conn.commit()
    conn.close()

def mark_policy_expired(policy_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE policies SET status='Expired' WHERE policy_id=?", (policy_id,))
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

    all_policies = get_all_policies()
    risk_flags = get_risk_flags()
    return render_template("index.html",
                           results=results,
                           message=message,
                           search_query=search_query,
                           all_policies=all_policies,
                           risk_flags=risk_flags)

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
    return render_template("edit.html", record=record)

@app.route("/delete/<int:policy_id>", methods=["POST"])
def delete(policy_id):
    delete_record(policy_id)
    return redirect(url_for("index"))

@app.route("/mark-expired/<int:policy_id>", methods=["POST"])
def mark_expired(policy_id):
    mark_policy_expired(policy_id)
    return redirect(url_for("index"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)