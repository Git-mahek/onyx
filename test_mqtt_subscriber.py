"""Tests for MQTT topic/payload identity validation."""

import json
import unittest

from mqtt_subscriber import parse_message


class ParseMessageIdentityTests(unittest.TestCase):
    def test_topic_identity_is_used_when_payload_identity_is_omitted(self):
        row = parse_message(
            "sensors/water/node1",
            json.dumps({"level_pct": 50}),
        )

        self.assertEqual(row[0:2], ("node1", "water"))

    def test_matching_payload_identity_is_accepted(self):
        row = parse_message(
            "sensors/temp/node3",
            json.dumps({"node_id": "node3", "sensor": "temp"}),
        )

        self.assertEqual(row[0:2], ("node3", "temp"))

    def test_mismatched_node_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "node_id does not match"):
            parse_message(
                "sensors/water/node1",
                json.dumps({"node_id": "node2"}),
            )

    def test_mismatched_sensor_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "sensor does not match"):
            parse_message(
                "sensors/water/node1",
                json.dumps({"sensor": "temp"}),
            )

    def test_non_string_payload_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "node_id does not match"):
            parse_message(
                "sensors/water/node1",
                json.dumps({"node_id": 1}),
            )

    def test_overlong_topic_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exceeds supported length"):
            parse_message(
                "sensors/water/" + ("n" * 33),
                "{}",
            )


if __name__ == "__main__":
    unittest.main()
