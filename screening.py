"""screening.py - rate limiting + 3-tier plausibility check, built against the
REAL row shape produced by mqtt_subscriber.parse_message():

    (node_id, sensor, topic, ts, received_at,
     level_cm, level_pct, leak, motion, temperature_c, humidity_pct, payload)

Unlike a single-value schema, one message can carry several numeric fields
(e.g. a "temp" message has both temperature_c and humidity_pct). Each
present field is checked independently; the row's overall tier is the
worst tier of any field in it.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

# Row tuple column indices, named for readability.
IDX = {"node_id": 0, "sensor": 1, "topic": 2, "ts": 3, "received_at": 4,
       "level_cm": 5, "level_pct": 6, "leak": 7, "motion": 8,
       "temperature_c": 9, "humidity_pct": 10, "payload": 11}

# (min, max) a field can physically be. Outside this = impossible.
# level_cm has no fixed upper bound here since tank height varies by
# deployment; level_pct (0-100, normalized) is the more meaningful check.
FIELD_LIMITS = {
    "level_pct": (0, 100),
    "level_cm": (0, 1000),
    "temperature_c": (-10, 60),   # DHT11 spec is 0-50, with margin
    "humidity_pct": (0, 100),
}

# Max change since that node's last reading for this field. Exceeding = unusual.
JUMP_LIMITS = {
    "level_pct": 40,
    "temperature_c": 15,
    "humidity_pct": 30,
}
# leak and motion are booleans - never range- or jump-checked.

TIER_RANK = {"normal": 0, "unusual": 1, "impossible": 2}


@dataclass
class ScreenResult:
    tier: str
    reasons: list = field(default_factory=list)


class RateLimiter:
    """Sliding window per node_id. Same design regardless of message schema."""

    def __init__(self, max_messages: int, window_seconds: float):
        self.max_messages = max_messages
        self.window_seconds = window_seconds
        self._timestamps = defaultdict(deque)

    def allow(self, node_id: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        q = self._timestamps[node_id]
        while q and now - q[0] > self.window_seconds:
            q.popleft()
        if len(q) >= self.max_messages:
            return False
        q.append(now)
        return True


class PlausibilityChecker:
    def __init__(self):
        self._last = {}  # (node_id, field_name) -> last value

    def check_row(self, row, now=None) -> ScreenResult:
        node_id = row[IDX["node_id"]]
        worst = "normal"
        reasons = []

        for field_name, limits in FIELD_LIMITS.items():
            value = row[IDX[field_name]]
            if value is None:
                continue  # this message type doesn't carry this field

            low, high = limits
            if not (low <= value <= high):
                reasons.append(f"{field_name}={value} outside [{low}, {high}]")
                worst = "impossible"
                continue  # impossible already beats anything jump-check could add

            key = (node_id, field_name)
            jump_limit = JUMP_LIMITS.get(field_name)
            if jump_limit is not None and key in self._last:
                delta = abs(value - self._last[key])
                if delta > jump_limit:
                    reasons.append(f"{field_name} jumped {delta:.1f} (limit {jump_limit})")
                    if TIER_RANK["unusual"] > TIER_RANK[worst]:
                        worst = "unusual"
            self._last[key] = value

        if worst == "normal" and not reasons:
            reasons = ["within range and expected variance"]
        return ScreenResult(worst, reasons)