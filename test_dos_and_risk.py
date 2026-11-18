"""Tests for dos_check.py and risk_aggregation.py.
Run with:  python test_dos_and_risk.py -v"""

import unittest

import fake_targets
from dos_check import flood_check
from findings import Finding
from risk_aggregation import score_all, score_device


class DosCheckTests(unittest.TestCase):
    def test_healthy_http_target_not_flagged_high(self):
        server = fake_targets.start_http(creds=None)
        port = server.server_address[1]
        findings = flood_check("127.0.0.1", port, "http", duration=1.0, rate=20)
        self.assertTrue(all(f.severity in ("LOW", "MEDIUM") for f in findings))

    def test_unreachable_target_handled_not_crashed(self):
        # nothing listens on port 1 - should report a finding, not raise
        findings = flood_check("127.0.0.1", 1, "http", duration=0.5, rate=10)
        self.assertEqual(len(findings), 1)
        self.assertIn("unreachable", findings[0].issue.lower())

    def test_healthy_mqtt_target_not_flagged_high(self):
        server = fake_targets.start_mqtt(creds=None)
        port = server.server_address[1]
        findings = flood_check("127.0.0.1", port, "mqtt", duration=1.0, rate=15)
        self.assertTrue(all(f.severity in ("LOW", "MEDIUM") for f in findings))

    def test_unknown_service_rejected(self):
        with self.assertRaises(ValueError):
            flood_check("127.0.0.1", 1234, "telnet", duration=0.2, rate=5)


class RiskAggregationTests(unittest.TestCase):
    def test_single_low_finding_is_low(self):
        findings = [Finding("n1", 8883, "mqtt", "No significant degradation observed", "LOW", "")]
        result = score_device("n1", findings)
        self.assertEqual(result.severity, "LOW")

    def test_telnet_plus_default_creds_combo_scores_higher_than_sum(self):
        findings = [
            Finding("n1", 23, "telnet", "Telnet service is running", "HIGH", ""),
            Finding("n1", 23, "telnet", "Default credentials accepted", "CRITICAL", "root:root"),
        ]
        result = score_device("n1", findings)
        plain_sum = 6 + 10  # HIGH + CRITICAL points only, no combo bonus
        self.assertGreater(result.score, plain_sum)
        self.assertIn("COMBO", " ".join(result.explanation))
        self.assertIn(result.severity, ("HIGH", "CRITICAL"))

    def test_unexpected_port_plus_default_creds_gets_combo_bonus_once(self):
        findings = [
            Finding("n1", 8080, "http", "Unexpected open port", "MEDIUM", ""),
            Finding("n1", 8080, "http", "Default credentials accepted", "CRITICAL", ""),
            Finding("n1", 8080, "telnet", "Telnet service is running", "HIGH", ""),
        ]
        result = score_device("n1", findings)
        self.assertEqual(result.score, 27)  # 3 + 10 + 6 + one 8-point combo
        self.assertEqual(sum("COMBO" in line for line in result.explanation), 1)

    def test_score_hosts_maps_nodes_and_keeps_clean_hosts(self):
        from risk_aggregation import score_hosts

        finding = Finding("10.0.0.1", 80, "http", "No authentication required", "HIGH", "")
        scores = score_hosts(
            ["10.0.0.1", "10.0.0.2"],
            [finding],
            {"10.0.0.1": "node1", "10.0.0.2": "node2"},
        )
        self.assertEqual(set(scores), {"node1", "node2"})
        self.assertEqual(scores["node1"].score, 6)
        self.assertEqual(scores["node2"].score, 0)

    def test_no_findings_is_low_zero(self):
        result = score_device("n1", [])
        self.assertEqual(result.severity, "LOW")
        self.assertEqual(result.score, 0)

    def test_score_all_handles_multiple_devices(self):
        by_device = {
            "n1": [Finding("n1", 23, "telnet", "Telnet service is running", "HIGH", "")],
            "n2": [],
        }
        scores = score_all(by_device)
        self.assertEqual(set(scores.keys()), {"n1", "n2"})
        self.assertEqual(scores["n2"].severity, "LOW")


if __name__ == "__main__":
    unittest.main()