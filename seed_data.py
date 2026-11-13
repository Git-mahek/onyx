#!/usr/bin/env python3
"""
seed_data.py - fill `readings` and `audit_log` with realistic sample rows.

For anyone who has MySQL but not Docker/Mosquitto: no broker, no paho needed.
Needs only `pip install pymysql` and screening.py in the same folder.

How the rows are made: three nodes (same topics and payload shape as
mqtt_fake_sensors.py) are simulated over the last --hours, then every message is
run through the REAL screening.py (rate limit -> plausibility check), exactly as
mqtt_subscriber.py does:
  * accepted / flagged  -> row in readings + audit_log entry
  * rejected (impossible) / rate_limited -> audit_log entry only, never in readings
So the sample data has the same shape as a live pipeline, including a few bad
readings so the rejected / flagged / rate_limited paths have data to query.

Settings: flags or the same env vars as mqtt_subscriber.py
    MYSQL_HOST MYSQL_PORT MYSQL_USER MYSQL_PASSWORD MYSQL_DATABASE MYSQL_SSL_CA
(the password is environment-only so it never shows up in `ps`).

Examples:
    export MYSQL_PASSWORD=sensorpw
    python seed_data.py --init-schema                 # create tables, then seed 24 h
    python seed_data.py --hours 6 --interval 30       # denser, shorter
    python seed_data.py --truncate --yes --seed 7     # wipe both tables first, reproducible
    python seed_data.py --dry-run                     # no database: just print what would be inserted
"""
import argparse
import json
import math
import os
import random
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from screening import PlausibilityChecker, RateLimiter

# Same SQL as mqtt_subscriber.py (column order = the row tuple from parse_message()).
INSERT_SQL = (
    "INSERT INTO readings (node_id, sensor, topic, ts, received_at, level_cm, "
    "level_pct, leak, motion, temperature_c, humidity_pct, payload) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
AUDIT_INSERT_SQL = (
    "INSERT INTO audit_log (node_id, sensor, decision, reason, ts) VALUES (%s, %s, %s, %s, %s)"
)

TOPICS = {
    "water": ("sensors/water/node1", "node1"),
    "pir": ("sensors/pir/node2", "node2"),
    "temp": ("sensors/temp/node3", "node3"),
}


# ------------------------------------------------------------- simulators
# Same models as mqtt_fake_sensors.py, copied so this script needs no paho.
class WaterSim:
    TANK_CM = 100.0

    def __init__(self, rng):
        self.rng = rng
        self.level = rng.uniform(55, 90)
        self.refilling = False
        self.leak_until = 0.0

    def step(self, t, dt):
        if self.refilling:
            self.level += 0.30 * dt
            if self.level >= 92:
                self.refilling = False
        else:
            self.level -= 0.02 * dt * self.rng.uniform(0.5, 1.5)
            if self.level <= 25:
                self.refilling = True
        if t > self.leak_until and self.rng.random() < 0.0005 * dt:
            self.leak_until = t + self.rng.uniform(120, 400)
        leak = t < self.leak_until
        if leak:
            self.level -= 0.08 * dt
        self.level = max(0.0, min(self.TANK_CM, self.level))
        measured = self.level + self.rng.gauss(0, 0.15)
        return {"level_cm": round(measured, 2),
                "level_pct": round(100 * measured / self.TANK_CM, 1),
                "leak": leak}


class PirSim:
    HOLD_S = 8.0

    def __init__(self, rng):
        self.rng = rng
        self.hold_until = 0.0

    def step(self, t, dt):
        hour = (t % 86400) / 3600
        awake = 7 <= hour <= 23
        if self.rng.random() < (0.04 if awake else 0.003) * dt:
            self.hold_until = max(self.hold_until, t + self.HOLD_S * self.rng.uniform(0.7, 2.5))
        return {"motion": t < self.hold_until}


class TempSim:
    def __init__(self, rng):
        self.rng = rng
        self.drift = 0.0

    def step(self, t, dt):
        hour = (t % 86400) / 3600
        base = 27.0 + 5.0 * math.sin((hour - 9.0) / 24 * 2 * math.pi)
        self.drift += self.rng.gauss(0, 0.01) * dt
        self.drift *= 0.999
        temp = base + self.drift + self.rng.gauss(0, 0.1)
        hum = 60.0 - 1.8 * (temp - 27.0) + self.rng.gauss(0, 0.8)
        return {"temperature_c": round(temp, 2),
                "humidity_pct": round(max(10.0, min(100.0, hum)), 1)}


SUB_STEP = 2.0  # sim step in seconds; matches the fake sensors' default publish interval


def sample(sim, t, interval):
    """Advance a sim across one sampling interval in small steps, return the last reading."""
    out = None
    for i in range(max(1, int(interval / SUB_STEP))):
        out = sim.step(t + i * SUB_STEP, SUB_STEP)
    return out


# -------------------------------------------------------------- anomalies
# Injected one-shot bad readings (name -> sensor kind, mutate, extra copies in a burst).
def _water_jump(p):
    pct = p["level_pct"]
    new = round(pct - 45 if pct >= 50 else pct + 45, 1)
    return {**p, "level_pct": new, "level_cm": new}


ANOMALIES = {
    "humidity_spike": ("temp", lambda p: {**p, "humidity_pct": 120.0}, 0),   # -> rejected
    "temp_jump": ("temp", lambda p: {**p, "temperature_c": round(p["temperature_c"] + 20, 2)}, 0),  # -> flagged
    "water_jump": ("water", _water_jump, 0),                                 # -> flagged
    "temp_impossible": ("temp", lambda p: {**p, "temperature_c": 85.0}, 0),  # -> rejected
    "flood": ("temp", lambda p: p, 30),                                      # -> rate_limited
}


# ------------------------------------------------------------- generation
def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def generate(args):
    """Return (readings_rows, audit_rows, decision_counts)."""
    rng = random.Random(args.seed)
    sims = {"water": WaterSim(rng), "pir": PirSim(rng), "temp": TempSim(rng)}
    limiter = RateLimiter(args.rate_limit_count, args.rate_limit_window)
    checker = PlausibilityChecker()

    rounds = int(args.hours * 3600 / args.interval)
    if rounds < 1:
        sys.exit("--hours / --interval gives zero rounds")
    start = utcnow().replace(microsecond=0) - timedelta(seconds=rounds * args.interval)

    # Spread the anomalies over the run; keep the first rounds clean as a baseline for jump checks.
    plan = {}
    names = list(ANOMALIES)
    for i in range(args.anomalies):
        r = rng.randrange(min(10, rounds - 1), rounds)
        plan.setdefault(r, []).append(names[i % len(names)])

    readings, audits, counts = [], [], Counter()

    def process(kind, data, when):
        node_id = TOPICS[kind][1]
        received = when + timedelta(milliseconds=rng.randint(5, 120))
        received = received.replace(microsecond=received.microsecond // 1000 * 1000)  # DATETIME(3)
        row = (
            node_id, kind, TOPICS[kind][0],
            when.replace(microsecond=0), received,
            data.get("level_cm"), data.get("level_pct"),
            None if "leak" not in data else int(data["leak"]),
            None if "motion" not in data else int(data["motion"]),
            data.get("temperature_c"), data.get("humidity_pct"),
            json.dumps(data, separators=(",", ":")),
        )
        epoch = when.replace(tzinfo=timezone.utc).timestamp()
        if not limiter.allow(node_id, epoch):
            decision, reason = "rate_limited", "exceeded message rate limit"
        else:
            result = checker.check_row(row)
            decision = {"impossible": "rejected", "unusual": "flagged", "normal": "accepted"}[result.tier]
            reason = "; ".join(result.reasons)
            if decision != "rejected":
                readings.append(row)
        audits.append((node_id, kind, decision, reason[:255], received))
        counts[decision] += 1

    for r in range(rounds):
        when = start + timedelta(seconds=r * args.interval)
        t = when.replace(tzinfo=timezone.utc).timestamp()
        active = plan.get(r, [])
        for kind, sim in sims.items():
            data = {"node_id": TOPICS[kind][1], "sensor": kind,
                    "ts": when.replace(tzinfo=timezone.utc).isoformat(timespec="seconds"),
                    **sample(sim, t, args.interval)}
            copies = 1
            for name in active:
                target, mutate, extra = ANOMALIES[name]
                if target == kind:
                    data, copies = mutate(data), copies + extra
            for c in range(copies):
                process(kind, data, when + timedelta(milliseconds=100 * c))  # bursts are 0.1 s apart
    return readings, audits, counts


# --------------------------------------------------------------- database
def connect(args):
    try:
        import pymysql
    except ImportError:
        sys.exit("pymysql is not installed: pip install pymysql")
    kw = dict(host=args.mysql_host, port=args.mysql_port, user=args.mysql_user,
              password=os.environ.get("MYSQL_PASSWORD", ""), database=args.mysql_db,
              charset="utf8mb4", autocommit=False, connect_timeout=10)
    if args.mysql_ssl_ca:
        kw["ssl"] = {"ca": args.mysql_ssl_ca}
    try:
        return pymysql.connect(**kw)
    except pymysql.MySQLError as e:
        sys.exit(f"cannot connect to MySQL at {args.mysql_host}:{args.mysql_port}: {e}")


def schema_statements():
    """schema.sql split into statements (same comment-stripping as mqtt_subscriber.init_schema)."""
    sql = Path(__file__).with_name("schema.sql").read_text()
    body = "\n".join(l for l in sql.splitlines() if not l.lstrip().startswith("--"))
    return [s.strip() for s in body.split(";") if s.strip()]


def insert_batches(conn, sql, rows, size=500):
    with conn.cursor() as cur:
        for i in range(0, len(rows), size):
            cur.executemany(sql, rows[i:i + size])
    conn.commit()


def main():
    e = os.environ.get
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_argument_group("MySQL")
    g.add_argument("--mysql-host", default=e("MYSQL_HOST", "localhost"))
    g.add_argument("--mysql-port", type=int, default=int(e("MYSQL_PORT", "3306")))
    g.add_argument("--mysql-user", default=e("MYSQL_USER", "sensor"))
    g.add_argument("--mysql-db", default=e("MYSQL_DATABASE", "sensors"))
    g.add_argument("--mysql-ssl-ca", default=e("MYSQL_SSL_CA"))
    g.add_argument("--init-schema", action="store_true", help="run schema.sql first (CREATE TABLE IF NOT EXISTS)")
    g.add_argument("--truncate", action="store_true", help="empty readings and audit_log before seeding")
    g.add_argument("--yes", action="store_true", help="don't ask for confirmation on --truncate")
    g = ap.add_argument_group("data")
    g.add_argument("--hours", type=float, default=24.0, help="history to generate, ending now (default 24)")
    g.add_argument("--interval", type=float, default=60.0, help="seconds between readings per node (default 60; keep it <= ~120 so pump refills don't trip the jump check)")
    g.add_argument("--anomalies", type=int, default=6,
                   help="bad-data events to inject, cycling through %s (default 6)" % ", ".join(ANOMALIES))
    g.add_argument("--seed", type=int, help="seed the RNG for reproducible data")
    g.add_argument("--rate-limit-count", type=int, default=20, help="same defaults as mqtt_subscriber.py")
    g.add_argument("--rate-limit-window", type=float, default=10.0)
    ap.add_argument("--dry-run", action="store_true", help="generate and summarise only; don't touch MySQL")
    args = ap.parse_args()

    readings, audits, counts = generate(args)
    print(f"generated {len(readings)} readings rows and {len(audits)} audit_log rows")
    print("decisions: " + ", ".join(f"{k}={counts.get(k, 0)}" for k in ("accepted", "flagged", "rejected", "rate_limited")))
    if args.dry_run:
        for row in readings[:3]:
            print("  readings:", row[:11])
        return 0

    if args.truncate and not args.yes:
        if input(f"TRUNCATE readings and audit_log in {args.mysql_db}@{args.mysql_host}? [y/N] ").strip().lower() != "y":
            return 1
    conn = connect(args)
    try:
        with conn.cursor() as cur:
            if args.init_schema:
                for stmt in schema_statements():
                    cur.execute(stmt)
                conn.commit()
            if args.truncate:
                cur.execute("TRUNCATE TABLE readings")
                cur.execute("TRUNCATE TABLE audit_log")
                conn.commit()
        insert_batches(conn, INSERT_SQL, readings)
        insert_batches(conn, AUDIT_INSERT_SQL, audits)
    except Exception as err:  # e.g. tables missing -> hint at --init-schema
        conn.rollback()
        msg = str(err)
        sys.exit(f"insert failed: {msg}" + ("\n(hint: run again with --init-schema)" if "doesn't exist" in msg else ""))
    finally:
        conn.close()
    print(f"inserted into {args.mysql_db}@{args.mysql_host}:{args.mysql_port}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
