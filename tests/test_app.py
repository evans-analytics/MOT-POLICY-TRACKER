import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import app
from services.ai_extraction import extract_policy_from_pdf
from werkzeug.security import generate_password_hash


class PolicyIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = app.DB_PATH
        self.original_upload_folder = app.UPLOAD_FOLDER
        app.DB_PATH = os.path.join(self.temp_dir.name, "test.db")
        app.UPLOAD_FOLDER = os.path.join(self.temp_dir.name, "documents")
        app.init_db()

    def tearDown(self):
        app.DB_PATH = self.original_db_path
        app.UPLOAD_FOLDER = self.original_upload_folder
        self.temp_dir.cleanup()

    def test_soft_delete_preserves_client_and_audit_record(self):
        policy_id = app.add_client_and_policy(
            "Test Client",
            "555-0100",
            "client@example.com",
            "TEST-001",
            "Motor",
            "2026-01-01",
            "2026-12-31",
            "Active",
            "Shelf A-1",
        )

        app.delete_record(policy_id)

        conn = app.connect_db()
        policy = conn.execute(
            "SELECT deleted_at FROM policies WHERE policy_id=?", (policy_id,)
        ).fetchone()
        client = conn.execute(
            "SELECT full_name FROM clients WHERE full_name=?", ("Test Client",)
        ).fetchone()
        audit = conn.execute(
            "SELECT action, details FROM audit_log WHERE policy_id=? AND action='deleted'",
            (policy_id,),
        ).fetchone()
        conn.close()

        self.assertIsNotNone(policy[0])
        self.assertEqual(client[0], "Test Client")
        self.assertEqual(audit[0], "deleted")
        self.assertIn("soft-deleted", audit[1])
        self.assertEqual(app.get_all_policies(), [])

    def test_database_initialization_is_idempotent(self):
        app.init_db()
        app.init_db()
        conn = app.connect_db()
        columns = {row[1] for row in conn.execute("PRAGMA table_info(policies)")}
        conn.close()
        self.assertIn("deleted_at", columns)

    def test_invalid_dates_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "End date cannot be earlier"):
            app.add_client_and_policy(
                "Test Client", "555-0100", "", "TEST-002", "Motor",
                "2026-12-31", "2026-01-01", "Active", "Shelf A-1"
            )

    def test_duplicate_policy_numbers_are_rejected(self):
        values = (
            "Test Client", "555-0100", "", "TEST-003", "Motor",
            "2026-01-01", "2026-12-31", "Active", "Shelf A-1"
        )
        app.add_client_and_policy(*values)
        with self.assertRaisesRegex(ValueError, "already exists"):
            app.add_client_and_policy(*values)

    def test_multiple_policies_reuse_existing_client(self):
        first = app.add_client_and_policy(
            "Test Client", "555-0100", "client@example.com", "TEST-005", "Motor",
            "2026-01-01", "2026-12-31", "Active", "Shelf A-1"
        )
        second = app.add_client_and_policy(
            "Test Client", "555-0100", "client@example.com", "TEST-006", "Life",
            "2026-02-01", "2027-01-31", "Active", "Shelf A-2"
        )

        conn = app.connect_db()
        client_count = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        policy_clients = conn.execute(
            "SELECT client_id FROM policies WHERE policy_id IN (?, ?)", (first, second)
        ).fetchall()
        conn.close()

        self.assertEqual(client_count, 1)
        self.assertEqual(policy_clients[0][0], policy_clients[1][0])

    def test_transaction_rolls_back_on_error(self):
        with self.assertRaises(sqlite3.OperationalError):
            with app.transaction() as conn:
                conn.execute("INSERT INTO clients (full_name) VALUES (?)", ("Rollback Client",))
                conn.execute("INSERT INTO table_that_does_not_exist VALUES (1)")

        conn = app.connect_db()
        count = conn.execute(
            "SELECT COUNT(*) FROM clients WHERE full_name=?", ("Rollback Client",)
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 0)

    def test_effective_status_is_date_driven(self):
        from datetime import date, timedelta

        today = date.today()
        self.assertEqual(
            app.get_effective_status("2026-01-01", str(today + timedelta(days=45)), "Active"),
            "Active",
        )
        self.assertEqual(
            app.get_effective_status("2026-01-01", str(today + timedelta(days=7)), "Active"),
            "Expiring Soon",
        )
        self.assertEqual(
            app.get_effective_status("2026-01-01", str(today - timedelta(days=1)), "Active"),
            "Expired",
        )
        self.assertEqual(
            app.get_effective_status("2026-01-01", str(today - timedelta(days=1)), "Cancelled"),
            "Cancelled",
        )

    def test_login_protects_dashboard_and_sets_session(self):
        with app.transaction() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("admin", generate_password_hash("correct-password"), "Admin", "2026-01-01T00:00:00")
            )
        client = app.app.test_client()

        self.assertEqual(client.get("/").status_code, 302)
        response = client.post(
            "/login", data={"username": "admin", "password": "correct-password"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(client.get("/").status_code, 200)

    def test_invalid_login_is_rejected(self):
        with app.transaction() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("viewer", generate_password_hash("correct-password"), "Viewer", "2026-01-01T00:00:00")
            )
        response = app.app.test_client().post(
            "/login", data={"username": "viewer", "password": "wrong-password"}
        )
        self.assertEqual(response.status_code, 401)

    def test_missing_policy_mutations_return_not_found(self):
        with app.transaction() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("mutation-admin", generate_password_hash("correct-password"), "Admin", "2026-01-01T00:00:00")
            )
        client = app.app.test_client()
        client.post("/login", data={"username": "mutation-admin", "password": "correct-password"})
        self.assertEqual(client.post("/mark-expired/999999").status_code, 404)
        self.assertEqual(
            client.post("/policy/999999/document", data={}, content_type="multipart/form-data").status_code,
            404,
        )

    def test_pdf_extraction_rejects_empty_pdf_text(self):
        data, error = extract_policy_from_pdf(b"not a valid pdf")
        self.assertIsNone(data)
        self.assertIn("Error reading PDF", error)

    def test_pdf_extraction_does_not_call_ai_without_key(self):
        pdf_context = MagicMock()
        pdf_context.__enter__.return_value.pages = [
            MagicMock(extract_text=lambda: "Policy number: TEST-004")
        ]
        with patch.dict("os.environ", {"GEMINI_API_KEY": ""}), patch(
            "services.ai_extraction.pdfplumber.open", return_value=pdf_context
        ):
            data, error = extract_policy_from_pdf(b"readable pdf")
        self.assertIsNone(data)
        self.assertIn("API key not configured", error)


if __name__ == "__main__":
    unittest.main()
