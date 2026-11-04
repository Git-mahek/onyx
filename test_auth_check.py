"""Tests for auth_check.py. Run with:  python test_auth_check.py"""

import unittest

import auth_check
import fake_targets

auth_check.DELAY_BETWEEN_ATTEMPTS = 0  # no need to be polite to our own fake servers


def issues(findings):
    return {f.issue for f in findings}


class HttpTests(unittest.TestCase):
    def test_no_auth(self):
        server = fake_targets.start_http(creds=None)
        found = auth_check.check_http("127.0.0.1", server.server_address[1])
        self.assertIn("No authentication required", issues(found))

    def test_default_credentials(self):
        server = fake_targets.start_http(creds=("admin", "admin"))
        found = auth_check.check_http("127.0.0.1", server.server_address[1])
        self.assertIn("Default credentials accepted", issues(found))
        self.assertIn("Credentials sent in cleartext", issues(found))

    def test_strong_password_not_flagged(self):
        server = fake_targets.start_http(creds=("admin", "Xk9#vQ2!mLp7"))
        found = auth_check.check_http("127.0.0.1", server.server_address[1])
        self.assertNotIn("Default credentials accepted", issues(found))


class MqttTests(unittest.TestCase):
    def test_anonymous(self):
        server = fake_targets.start_mqtt(creds=None)
        found = auth_check.check_mqtt("127.0.0.1", server.server_address[1])
        self.assertIn("Anonymous access allowed", issues(found))

    def test_default_credentials(self):
        server = fake_targets.start_mqtt(creds=("root", "root"))
        found = auth_check.check_mqtt("127.0.0.1", server.server_address[1])
        self.assertIn("Default credentials accepted", issues(found))

    def test_secure_broker(self):
        server = fake_targets.start_mqtt(creds=("sensor1", "Xk9#vQ2!mLp7"))
        found = auth_check.check_mqtt("127.0.0.1", server.server_address[1])
        self.assertEqual(issues(found), set())  # non-1883 port, no findings


class TelnetTests(unittest.TestCase):
    def test_default_credentials(self):
        server = fake_targets.start_telnet(creds=("admin", "admin"))
        found = auth_check.check_telnet("127.0.0.1", server.server_address[1])
        self.assertIn("Telnet service is running", issues(found))
        self.assertIn("Default credentials accepted", issues(found))

    def test_strong_password_still_flags_telnet(self):
        server = fake_targets.start_telnet(creds=("admin", "Xk9#vQ2!mLp7"))
        found = auth_check.check_telnet("127.0.0.1", server.server_address[1])
        self.assertIn("Telnet service is running", issues(found))
        self.assertNotIn("Default credentials accepted", issues(found))


class GuardTests(unittest.TestCase):
    def test_public_address_refused(self):
        with self.assertRaises(ValueError):
            auth_check.require_private("8.8.8.8")


if __name__ == "__main__":
    unittest.main()
