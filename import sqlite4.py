import sqlite3

def search_by_client_name(name):
    conn = sqlite3.connect("policy_tracker.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            clients.full_name,
            clients.phone,
            policies.policy_number,
            policies.policy_type,
            policies.status,
            file_log.shelf_location
        FROM policies
        JOIN clients ON policies.client_id = clients.client_id
        JOIN file_log ON policies.policy_id = file_log.policy_id
        WHERE clients.full_name LIKE ?
    """, (f"%{name}%",))

    results = cursor.fetchall()
    conn.close()

    if results:
        print(f"\n--- Results for '{name}' ---")
        for row in results:
            print(f"""
            Client Name   : {row[0]}
            Phone         : {row[1]}
            Policy Number : {row[2]}
            Policy Type   : {row[3]}
            Status        : {row[4]}
            File Location : {row[5]}
            """)
    else:
        print(f"No records found for '{name}'")

# --- Search ---
search_by_client_name("John")