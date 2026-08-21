import os
import sqlite3
import tempfile
import unittest

import app


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


if __name__ == "__main__":
    unittest.main()
