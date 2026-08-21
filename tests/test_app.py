import os
import re
import sys
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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

    def csrf_token(self, client):
        page = client.get("/login")
        match = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

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
                ("test-admin", generate_password_hash("correct-password"), "Admin", "2026-01-01T00:00:00")
            )
        client = app.app.test_client()

        self.assertEqual(client.get("/").status_code, 302)
        token = self.csrf_token(client)
        response = client.post(
            "/login", data={"username": "test-admin", "password": "correct-password", "csrf_token": token}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(client.get("/").status_code, 200)

    def test_invalid_login_is_rejected(self):
        with app.transaction() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("viewer", generate_password_hash("correct-password"), "Viewer", "2026-01-01T00:00:00")
            )
        client = app.app.test_client()
        response = client.post(
            "/login", data={"username": "viewer", "password": "wrong-password", "csrf_token": self.csrf_token(client)}
        )
        self.assertEqual(response.status_code, 401)

    def test_missing_policy_mutations_return_not_found(self):
        with app.transaction() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("mutation-admin", generate_password_hash("correct-password"), "Admin", "2026-01-01T00:00:00")
            )
        client = app.app.test_client()
        client.post("/login", data={"username": "mutation-admin", "password": "correct-password", "csrf_token": self.csrf_token(client)})
        token = self.csrf_token(client)
        self.assertEqual(client.post("/mark-expired/999999", data={"csrf_token": token}).status_code, 404)
        self.assertEqual(
            client.post("/policy/999999/document", data={"csrf_token": token}, content_type="multipart/form-data").status_code,
            404,
        )

    def test_state_changing_request_requires_csrf_token(self):
        client = app.app.test_client()
        self.assertEqual(
            client.post("/login", data={"username": "unknown", "password": "unknown"}).status_code,
            400,
        )

    def test_viewer_cannot_delete_or_edit_policy(self):
        with app.transaction() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("viewer-role", generate_password_hash("viewer-password"), "Viewer", "2026-01-01T00:00:00")
            )
        policy_id = app.add_client_and_policy(
            "Viewer Client", "555-0200", "viewer@example.com", "VIEW-001", "Motor",
            "2026-01-01", "2026-12-31", "Active", "Shelf V-1"
        )
        client = app.app.test_client()
        client.post("/login", data={"username": "viewer-role", "password": "viewer-password", "csrf_token": self.csrf_token(client)})
        token = self.csrf_token(client)
        self.assertEqual(client.get(f"/edit/{policy_id}").status_code, 403)
        self.assertEqual(client.post(f"/delete/{policy_id}", data={"csrf_token": token}).status_code, 403)

    def test_invalid_file_signature_is_rejected(self):
        self.assertFalse(app.valid_file_signature(b"not a pdf", "document.pdf"))
        self.assertFalse(app.valid_file_signature(b"MZ executable", "document.pdf"))
        self.assertTrue(app.valid_file_signature(b"%PDF-1.7", "document.pdf"))

    def test_logout_clears_authenticated_session(self):
        with app.transaction() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("logout-admin", generate_password_hash("logout-password"), "Admin", "2026-01-01T00:00:00")
            )
        client = app.app.test_client()
        client.post("/login", data={"username": "logout-admin", "password": "logout-password", "csrf_token": self.csrf_token(client)})
        token = self.csrf_token(client)
        self.assertEqual(client.post("/logout", data={"csrf_token": token}).status_code, 302)
        self.assertEqual(client.get("/").status_code, 302)

    def test_claim_creation_and_status_transition(self):
        policy_id = app.add_client_and_policy(
            "Claims Client", "555-0300", "claims@example.com", "CLM-POL-001", "Motor",
            "2026-01-01", "2026-12-31", "Active", "Shelf C-1"
        )
        claim_id = app.create_claim(
            "CLM-001", policy_id, "2026-08-21", "Collision", "1200", "", "Adjuster A",
            "Reported", "", "Initial report"
        )
        self.assertEqual(len(app.get_claims()), 1)
        self.assertTrue(app.update_claim_status(claim_id, "Under Investigation"))
        self.assertEqual(app.get_claims()[0][7], "Under Investigation")

    def test_claim_route_requires_claims_role(self):
        with app.transaction() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                ("claims-viewer", generate_password_hash("claims-password"), "Viewer", "2026-01-01T00:00:00")
            )
        client = app.app.test_client()
        client.post("/login", data={"username": "claims-viewer", "password": "claims-password", "csrf_token": self.csrf_token(client)})
        self.assertEqual(client.get("/claims").status_code, 403)

    def test_policy_risk_score_explains_missing_data(self):
        policy_id = app.add_client_and_policy(
            "Risk Client", "555-0400", "", "RISK-001", "Motor",
            "2026-01-01", "2026-08-25", "Active", "Shelf R-1"
        )
        result = app.get_policy_risk_score(policy_id)
        self.assertIsNotNone(result)
        self.assertIn("Client email is missing", result["reasons"])
        self.assertIn("No policy document is attached", result["reasons"])
        self.assertGreater(result["score"], 0)

    def test_risk_score_route_requires_login(self):
        self.assertEqual(app.app.test_client().get("/risk-score/999999").status_code, 302)

    def test_portfolio_risk_page_requires_login(self):
        policy_id = app.add_client_and_policy(
            "Portfolio Risk Client", "555-0500", "", "RISK-PORT-001", "Motor",
            "2026-01-01", "2026-08-25", "Active", "Shelf P-1"
        )
        scores = app.get_portfolio_risk()
        self.assertTrue(any(item["policy_id"] == policy_id for item in scores))
        self.assertEqual(app.app.test_client().get("/risk-intelligence").status_code, 302)

    def test_analytics_route_requires_login(self):
        self.assertEqual(app.app.test_client().get("/analytics").status_code, 302)
        analytics = app.get_dashboard_analytics()
        self.assertIn("policy_types", analytics)
        self.assertIn("statuses", analytics)

    def test_global_search_requires_login_and_handles_short_queries(self):
        client = app.app.test_client()
        self.assertEqual(client.get("/global-search?q=policy").status_code, 302)
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["role"] = "Admin"
        response = client.get("/global-search?q=x")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"results": []})

    def test_file_checkout_and_return_history(self):
        policy_id = app.add_client_and_policy(
            "File Client", "555-0600", "file@example.com", "FILE-001", "Motor",
            "2026-01-01", "2026-12-31", "Active", "Shelf F-1"
        )
        app.checkout_file(policy_id, "Desk 3", "Operations User")
        with self.assertRaisesRegex(ValueError, "already checked out"):
            app.checkout_file(policy_id, "Desk 4", "Operations User")
        movement = app.get_file_movements(policy_id)[0]
        self.assertIsNone(movement[6])
        self.assertTrue(app.return_file(movement[0]))
        self.assertIsNotNone(app.get_file_movements(policy_id)[0][6])

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
