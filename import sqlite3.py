import sqlite3

def add_client(full_name, phone, email):
    conn = sqlite3.connect("policy_tracker.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO clients (full_name, phone, email)
        VALUES (?, ?, ?)
    """, (full_name, phone, email))

    conn.commit()
    client_id = cursor.lastrowid
    conn.close()
    print(f"Client '{full_name}' added successfully! ID: {client_id}")
    return client_id

def add_policy(policy_number, policy_type, start_date, end_date, status, client_id, shelf_location):
    conn = sqlite3.connect("policy_tracker.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO policies (policy_number, policy_type, start_date, end_date, status, client_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (policy_number, policy_type, start_date, end_date, status, client_id))

    policy_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO file_log (policy_id, shelf_location)
        VALUES (?, ?)
    """, (policy_id, shelf_location))

    conn.commit()
    conn.close()
    print(f"Policy '{policy_number}' added successfully!")

# --- Test with dummy data ---
client_id = add_client("John Mensah", "0244123456", "john@email.com")
add_policy("POL-001", "Motor", "2024-01-01", "2025-01-01", "Active", client_id, "Shelf A - Row 2")

client_id = add_client("Akosua Boateng", "0277654321", "akosua@email.com")
add_policy("POL-002", "Life", "2023-06-01", "2026-06-01", "Active", client_id, "Shelf B - Row 1")