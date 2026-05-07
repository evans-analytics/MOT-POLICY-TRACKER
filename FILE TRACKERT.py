import sqlite3

# This creates the database file (or connects if it already exists)
conn = sqlite3.connect("policy_tracker.db")
cursor = conn.cursor()

# Table 1 - Clients
cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        client_id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        phone TEXT,
        email TEXT
    )
""")

# Table 2 - Policies
cursor.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
        policy_number TEXT NOT NULL UNIQUE,
        policy_type TEXT,
        start_date TEXT,
        end_date TEXT,
        status TEXT,
        client_id INTEGER,
        FOREIGN KEY (client_id) REFERENCES clients(client_id)
    )
""")

# Table 3 - File Log (tracks physical file location)
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

print("Database and tables created successfully!")