"""Tests for database-backed dashboard authentication."""

import unittest
from unittest.mock import patch

from werkzeug.security import generate_password_hash

import app as dashboard


class LoginTests(unittest.TestCase):
    def setUp(self):
        dashboard.app.config.update(TESTING=True, SECRET_KEY="test-session-key")
        self.client = dashboard.app.test_client()
        dashboard._failed_logins.clear()

    @patch.object(dashboard.db, "fetch_user")
    @patch.object(dashboard.db, "connect")
    def test_database_account_can_log_in(self, connect, fetch_user):
        fetch_user.return_value = {
            "username": "alice",
            "password_hash": generate_password_hash("a-strong-password"),
            "role": "admin",
        }

        response = self.client.post(
            "/api/login",
            json={"username": "Alice", "password": "a-strong-password"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"username": "alice", "role": "admin"})
        connect.return_value.close.assert_called_once()
        self.assertTrue(self.client.get("/api/me").get_json()["authenticated"])

    @patch.object(dashboard.db, "fetch_user", return_value=None)
    @patch.object(dashboard.db, "connect")
    def test_unknown_user_is_rejected(self, connect, _fetch_user):
        response = self.client.post(
            "/api/login",
            json={"username": "not-a-user", "password": "some-password"},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["error"], "Wrong username or password.")
        connect.return_value.close.assert_called_once()

    @patch.object(dashboard.db, "connect", side_effect=dashboard.db.pymysql.OperationalError("offline"))
    def test_database_error_is_reported_as_unavailable(self, _connect):
        response = self.client.post(
            "/api/login",
            json={"username": "alice", "password": "some-password"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error"], "Login service is temporarily unavailable.")


if __name__ == "__main__":
    unittest.main()
