"""risk_aggregation.py - combine Findings from all scanner modules into one
per-device risk score.

Not just "worst single finding": specific COMBINATIONS of findings are
treated as materially worse than either alone, because that mirrors how
real attacks work (Mirai didn't need an open port OR a default password -
it needed both, together, on the same device).

Scoring is a simple, explainable points system on purpose - easy to defend
in a presentation, not a black box:
  - Each finding contributes points for its severity.
  - A defined set of "combo" rules add bonus points when two specific
    finding types co-occur on the same host.
  - Points are capped and mapped to a final LOW/MEDIUM/HIGH/CRITICAL band.
"""

from dataclasses import dataclass
from datetime import datetime, timezone

SEVERITY_POINTS = {"LOW": 1, "MEDIUM": 3, "HIGH": 6, "CRITICAL": 10}

# (issue substring A, issue substring B, bonus points, why)
# Matched case-insensitively against Finding.issue. Order doesn't matter;
# a pair only needs to appear once each on the same host to trigger.
COMBO_RULES = [
    ("telnet service is running", "default credentials accepted", 8,
     "exposed service + working default login = directly exploitable (the Mirai pattern)"),
    ("no authentication required", "requests failed under load", 4,
     "unauthenticated service that also degrades under load = easy target, no resilience"),
    ("anonymous access allowed", "default credentials accepted", 5,
     "broker allows anonymous AND has a working default login elsewhere - broad access surface"),
    # TODO once A's port-scan module is merged: add its exact "unexpected
    # open port" issue string here, paired with "default credentials
    # accepted" - that pairing (not the telnet-only one above) is the
    # canonical Mirai combo this scoring exists to catch. Confirm the
    # exact wording with A before adding it.
]

BAND_THRESHOLDS = [(0, "LOW"), (8, "MEDIUM"), (18, "HIGH"), (30, "CRITICAL")]


@dataclass
class RiskScore:
    node_id: str
    score: float
    severity: str
    last_scanned: datetime
    explanation: list


def _band_for(points):
    band = "LOW"
    for threshold, name in BAND_THRESHOLDS:
        if points >= threshold:
            band = name
    return band


def score_device(node_id, findings, now=None):
    """findings: list of Finding, already filtered to one device (by host,
    or by whatever identifies a node for your deployment - the scanner
    modules key on host; map host -> node_id before calling this if they
    differ)."""
    now = now or datetime.now(timezone.utc)
    points = 0.0
    explanation = []

    for f in findings:
        pts = SEVERITY_POINTS.get(f.severity, 0)
        points += pts
        explanation.append(f"{f.severity} '{f.issue}' (+{pts})")

    issues_lower = [f.issue.lower() for f in findings]
    for a, b, bonus, why in COMBO_RULES:
        has_a = any(a in issue for issue in issues_lower)
        has_b = any(b in issue for issue in issues_lower)
        if has_a and has_b:
            points += bonus
            explanation.append(f"COMBO: {why} (+{bonus})")

    severity = _band_for(points)
    return RiskScore(node_id, points, severity, now, explanation)


def score_all(findings_by_device, now=None):
    """findings_by_device: dict of node_id -> list[Finding]. Returns dict
    of node_id -> RiskScore."""
    return {node_id: score_device(node_id, findings, now)
            for node_id, findings in findings_by_device.items()}
