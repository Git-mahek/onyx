"""Tests for auth_check.py. Run with:  python test_auth_check.py"""

import socket
import unittest

import auth_check
import fake_targets

auth_check.DELAY_BETWEEN_ATTEMPTS = 0  # no need to be polite to our own fake servers
auth_check.SCAN_DELAY = 0


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


def closed_port():
    """A port that is guaranteed to have nothing listening."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.http = fake_targets.start_http(creds=("admin", "admin")).server_address[1]
        self.mqtt = fake_targets.start_mqtt(creds=None).server_address[1]
        self.telnet = fake_targets.start_telnet(creds=("root", "root")).server_address[1]
        self.closed = closed_port()
        self.ports = [self.http, self.mqtt, self.telnet, self.closed]

    def test_scan_finds_open_ports_only(self):
        found = auth_check.scan_ports("127.0.0.1", self.ports)
        self.assertEqual(found, sorted([self.http, self.mqtt, self.telnet]))
        self.assertNotIn(self.closed, found)

    def test_identify_services(self):
        self.assertEqual(auth_check.identify_service("127.0.0.1", self.http), "http")
        self.assertEqual(auth_check.identify_service("127.0.0.1", self.mqtt), "mqtt")
        self.assertEqual(auth_check.identify_service("127.0.0.1", self.telnet), "telnet")

    def test_unexpected_ports_flagged(self):
        allow = {"127.0.0.1": {self.http}}  # only http is supposed to be open
        services, found = auth_check.scan_host("127.0.0.1", allow, self.ports)
        flagged = {f.port for f in found if f.issue == "Unexpected open port"}
        self.assertEqual(flagged, {self.mqtt, self.telnet})
        self.assertEqual(len(services), 3)  # allowlisted ports are still returned for auth checks

    def test_telnet_unexpected_is_high(self):
        _, found = auth_check.scan_host("127.0.0.1", {}, [self.telnet, self.http])
        by_port = {f.port: f.severity for f in found}
        self.assertEqual(by_port[self.telnet], "HIGH")
        self.assertEqual(by_port[self.http], "MEDIUM")

    def test_no_allowlist_entry_means_default_deny(self):
        _, found = auth_check.scan_host("127.0.0.1", {}, self.ports)
        self.assertEqual(len(found), 3)

    def test_fully_allowlisted_host_has_no_port_findings(self):
        allow = {"127.0.0.1": {self.http, self.mqtt, self.telnet}}
        _, found = auth_check.scan_host("127.0.0.1", allow, self.ports)
        self.assertEqual(found, [])

    def test_discovered_ports_feed_auth_checks(self):
        found = auth_check.scan_and_check(["127.0.0.1"], {}, self.ports)
        creds = {(f.port, f.service) for f in found if f.issue == "Default credentials accepted"}
        self.assertEqual(creds, {(self.http, "http"), (self.telnet, "telnet")})
        self.assertIn((self.mqtt, "mqtt"), {(f.port, f.service) for f in found
                                            if f.issue == "Anonymous access allowed"})

    def test_findings_use_shared_finding_class(self):
        import findings
        found = auth_check.scan_and_check(["127.0.0.1"], {}, self.ports)
        self.assertTrue(found and all(isinstance(f, findings.Finding) for f in found))
        self.assertIs(auth_check.Finding, findings.Finding)

    def test_public_address_not_scanned(self):
        with self.assertRaises(ValueError):
            auth_check.scan_ports("8.8.8.8", [80])
        self.assertEqual(auth_check.scan_and_check(["8.8.8.8"], {}, [80]), [])


class GuardTests(unittest.TestCase):
    def test_public_address_refused(self):
        with self.assertRaises(ValueError):
            auth_check.require_private("8.8.8.8")


if __name__ == "__main__":
    unittest.main()
