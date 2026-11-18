"""db.py - MySQL access + shape-mapping for the Onyx dashboard.

Kept separate from app.py so the mapping functions (pure Python, no
database) can be unit-tested without a live MySQL connection. Uses the
same pymysql connection pattern as mqtt_subscriber.py / risk_writer.py:
password only from MYSQL_PASSWORD, never hardcoded.
"""

import json
import os
from datetime import datetime, timedelta

import pymysql

# ----------------------------------------------------------------- connect
def cfg_from_env():
    return {
        "host": os.environ.get("MYSQL_HOST", "localhost"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "sensor"),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "database": os.environ.get("MYSQL_DATABASE", "sensors"),
        "ssl_ca": os.environ.get("MYSQL_SSL_CA"),
    }


def connect(cfg=None):
    cfg = cfg or cfg_from_env()
    kw = dict(host=cfg["host"], port=cfg["port"], user=cfg["user"],
              password=cfg["password"], database=cfg["database"],
              charset="utf8mb4", autocommit=True, connect_timeout=10,
              cursorclass=pymysql.cursors.DictCursor)
    if cfg.get("ssl_ca"):
        kw["ssl"] = {"ca": cfg["ssl_ca"]}
    return pymysql.connect(**kw)


# ------------------------------------------------------------ sensor tags
SENSOR_TAG = {"water": "Water", "pir": "Motion", "temp": "DHT11"}
NODE_LABEL = {"node1": "Node 1 (Water Tank)", "node2": "Node 2 (Motion PIR)", "node3": "Node 3 (DHT11 Climate)"}


# ------------------------------------------------------- decision mapping
# audit_log.decision is the one real column. Both screens derive their own
# vocabulary from it, so a decision only ever needs mapping in ONE place.
def alert_status(decision):
    """Maps to the Alerts screen's 3-state vocabulary."""
    return {"accepted": "normal", "flagged": "flagged",
            "rejected": "rejected", "rate_limited": "rejected"}.get(decision, "flagged")


def audit_result(decision):
    """Maps to the Audit screen's 4-state vocabulary."""
    return {"accepted": "normal", "flagged": "warning",
            "rejected": "rejected", "rate_limited": "throttled"}.get(decision, "warning")


def audit_code(decision, sensor, reason):
    if decision == "rejected":
        return "REJECTED_IMPOSSIBLE_READING" if "outside" in reason else "REJECTED_READING"
    if decision == "flagged":
        return "FLAGGED_UNUSUAL_READING"
    if decision == "rate_limited":
        return "RATE_LIMIT_EXCEEDED (DoS)"
    return "READING_ACCEPTED"


# --------------------------------------------------- risk score normalizer
# risk_aggregation.py: unbounded points, bands LOW/MEDIUM/HIGH/CRITICAL at
# 0/8/18/30. The dashboard: 0-100 score, bands Low/Medium/High at
# 0-39/40-69/70-100. This maps one onto the other, scaling the points
# WITHIN each band proportionally into that band's 0-100 sub-range, so a
# combo bonus still visibly moves the bar, not just the label.
_BAND_RANGES = {
    "LOW": (0, 8, 0, 39),
    "MEDIUM": (8, 18, 40, 69),
    "HIGH": (18, 30, 70, 100),
    "CRITICAL": (30, 60, 70, 100),  # CRITICAL has no upper points bound; cap the input at 60
}
_UI_LABEL = {"LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "High"}


def normalize_score(points, severity):
    """(score_0_to_100: int, ui_band: 'Low'|'Medium'|'High')"""
    lo, hi, out_lo, out_hi = _BAND_RANGES.get(severity, _BAND_RANGES["LOW"])
    points = max(lo, min(hi, points))
    frac = (points - lo) / (hi - lo) if hi > lo else 0
    score = round(out_lo + frac * (out_hi - out_lo))
    return score, _UI_LABEL.get(severity, "Low")


# -------------------------------------------------------------- queries
def fetch_alerts(conn, limit=50):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM audit_log ORDER BY ts DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
    out = []
    for r in rows:
        tag = SENSOR_TAG.get(r["sensor"], r["sensor"])
        out.append({
            "id": f"a{r['id']}",
            "time": r["ts"].strftime("%H:%M:%S"),
            "node": r["node_id"],
            "tag": tag,
            "status": alert_status(r["decision"]),
            "title": f"{r['decision'].replace('_', ' ').title()}: {r['reason']}"[:120],
            "desc": r["reason"],
            "rule": f"screening.py · {r['decision']}",
            "action": "Dropped, audit_log only" if r["decision"] in ("rejected", "rate_limited")
                      else "Stored in readings",
            "payload": {"node_id": r["node_id"], "sensor": r["sensor"], "ts": r["ts"].isoformat()},
        })
    return out


def fetch_audit(conn, limit=100):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM audit_log ORDER BY ts DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
    out = []
    for r in rows:
        out.append({
            "key": f"evt-{r['id']}",
            "id": f"#EVT-{r['id']}",
            "time": r["ts"].strftime("%H:%M:%S"),
            "result": audit_result(r["decision"]),
            "title": r["decision"].replace("_", " ").title(),
            "sub": f"Source: {r['node_id']} · {r['reason']}"[:120],
            "code": audit_code(r["decision"], r["sensor"], r["reason"]),
            "origin": NODE_LABEL.get(r["node_id"], r["node_id"]),
            "rule": f"screening.py · {r['decision']} · {r['reason']}"[:160],
            "payload": {"node_id": r["node_id"], "sensor": r["sensor"], "ts": r["ts"].isoformat(),
                        "reason": r["reason"]},
            "action": "Dropped before MySQL insert" if r["decision"] in ("rejected", "rate_limited")
                      else "Stored in readings",
        })
    return out


def fetch_risk(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM device_risk")
        rows = cur.fetchall()
    out = []
    for r in rows:
        score, band = normalize_score(r["score"], r["severity"])
        out.append({
            "node_id": r["node_id"],
            "score": score,
            "band": band,
            "raw_points": r["score"],
            "raw_severity": r["severity"],
            "last_scanned": r["last_scanned"].isoformat(),
        })
    return out


def fetch_sensor_latest(conn):
    """Latest reading per sensor kind, for the overview/sensor cards."""
    out = {}
    with conn.cursor() as cur:
        for kind in ("water", "pir", "temp"):
            cur.execute(
                "SELECT * FROM readings WHERE sensor = %s ORDER BY ts DESC LIMIT 1", (kind,)
            )
            row = cur.fetchone()
            if row:
                out[kind] = row
    return out


def fetch_sensor_series(conn, kind, minutes=60, points=48):
    """Downsampled time series for one sensor kind, for the chart."""
    since = datetime.utcnow() - timedelta(minutes=minutes)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT * FROM readings WHERE sensor = %s AND ts >= %s ORDER BY ts ASC", (kind, since)
        )
        rows = cur.fetchall()
    if len(rows) > points:
        step = len(rows) / points
        rows = [rows[int(i * step)] for i in range(points)]
    return rows
