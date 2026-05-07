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
        print(f"\nNo records found for '{name}'")

def main():
    while True:
        print("""
=============================
  SIC Policy Tracker
=============================
1. Add new client & policy
2. Search for a file
3. Exit
        """)

        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            print("\n--- Add New Client ---")
            full_name = input("Client full name: ")
            phone = input("Phone number: ")
            email = input("Email address: ")
            client_id = add_client(full_name, phone, email)
            print(f"Client added! ID: {client_id}")

            print("\n--- Add Policy ---")
            policy_number = input("Policy number: ")
            policy_type = input("Policy type (e.g. Motor, Life, Fire): ")
            start_date = input("Start date (YYYY-MM-DD): ")
            end_date = input("End date (YYYY-MM-DD): ")
            status = input("Status (Active/Expired): ")
            shelf_location = input("Shelf location (e.g. Shelf A - Row 2): ")
            add_policy(policy_number, policy_type, start_date, end_date, status, client_id, shelf_location)
            print("Policy added successfully!")

        elif choice == "2":
            name = input("\nEnter client name to search: ")
            search_by_client_name(name)

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please enter 1, 2 or 3.")

main()