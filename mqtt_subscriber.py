#!/usr/bin/env python3
"""
MQTT -> MySQL collector.

Subscribes to sensors/# over TLS, parses each JSON payload and stores it in the
`readings` table (schema.sql).

Settings come from flags or environment variables. Secrets are environment-only
so they never show up in `ps`:
    MQTT_HOST MQTT_PORT MQTT_CAFILE MQTT_CERTFILE MQTT_KEYFILE MQTT_USERNAME MQTT_PASSWORD
    MYSQL_HOST MYSQL_PORT MYSQL_USER MYSQL_PASSWORD MYSQL_DATABASE MYSQL_SSL_CA

Example:
    export MYSQL_PASSWORD=sensorpw
    python mqtt_subscriber.py --host localhost --cafile certs/ca.crt \\
        --mysql-user sensor --init-schema

Design: the paho network thread only parses and enqueues; a separate writer thread
batches rows into MySQL, so a slow or restarting database never stalls MQTT.
If MySQL goes away the writer keeps the batch and retries with backoff.

Before a row reaches the readings queue it's screened (screening.py):
rate limit -> 3-tier plausibility check. Impossible readings are never
stored; every decision (accepted/flagged/rejected/rate_limited) goes to a
second table, audit_log, via its own writer thread.
"""
import argparse
import json
import logging
import math
import os
import queue
import re
import signal
import ssl
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
import pymysql

from screening import PlausibilityChecker, RateLimiter

log = logging.getLogger("collector")

TOPIC_RE = re.compile(r"^sensors/([^/]+)/([^/]+)$")

INSERT_SQL = (
    "INSERT INTO readings (node_id, sensor, topic, ts, received_at, level_cm, "
    "level_pct, leak, motion, temperature_c, humidity_pct, payload) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)

AUDIT_INSERT_SQL = (
    "INSERT INTO audit_log (node_id, sensor, decision, reason, ts) VALUES (%s, %s, %s, %s, %s)"
)


# ---------------------------------------------------------------- parsing
def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _num(v):
    if v is None or isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _bool(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return int(bool(v))
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "yes", "on"):
            return 1
        if s in ("false", "0", "no", "off"):
            return 0
    return None


def _parse_ts(value, fallback):
    """ISO-8601 string or epoch seconds -> naive UTC datetime; fallback if unusable."""
    try:
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            dt = datetime.fromtimestamp(value, tz=timezone.utc)
        else:
            return fallback
    except (ValueError, OverflowError, OSError):
        return fallback
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0)


def parse_message(topic, raw, received_at=None):
    """Return a row tuple matching INSERT_SQL, or raise ValueError for bad input."""
    received_at = received_at or utcnow()
    m = TOPIC_RE.match(topic)
    if not m:
        raise ValueError("topic does not match sensors/<type>/<node>")
    try:
        data = json.loads(raw)
    except ValueError as e:  # includes UnicodeDecodeError and JSONDecodeError
        raise ValueError(f"invalid JSON: {e}") from None
    if not isinstance(data, dict):
        raise ValueError("payload is not a JSON object")
    try:
        payload = json.dumps(data, separators=(",", ":"), allow_nan=False)
    except ValueError:
        raise ValueError("payload contains NaN or Infinity") from None

    kind, node = m.groups()
    return (
        str(data.get("node_id") or node)[:32],
        str(data.get("sensor") or kind)[:16],
        topic[:128],
        _parse_ts(data.get("ts"), received_at.replace(microsecond=0)),
        received_at,
        _num(data.get("level_cm")),
        _num(data.get("level_pct")),
        _bool(data.get("leak")),
        _bool(data.get("motion")),
        _num(data.get("temperature_c")),
        _num(data.get("humidity_pct")),
        payload,
    )


# --------------------------------------------------------------- database
def connect_db(cfg):
    kw = dict(
        host=cfg["host"],
        port=cfg["port"],
        user=cfg["user"],
        password=cfg["password"],
        database=cfg["database"],
        charset="utf8mb4",
        autocommit=False,
        connect_timeout=10,
    )
    if cfg.get("ssl_ca"):
        kw["ssl"] = {"ca": cfg["ssl_ca"]}
    return pymysql.connect(**kw)


def init_schema(cfg):
    sql = Path(__file__).with_name("schema.sql").read_text()
    body = "\n".join(l for l in sql.splitlines() if not l.lstrip().startswith("--"))
    statements = [s.strip() for s in body.split(";") if s.strip()]
    conn = connect_db(cfg)
    try:
        with conn.cursor() as cur:
            for stmt in statements:
                cur.execute(stmt)
        conn.commit()
    finally:
        conn.close()


@dataclass
class Stats:
    received: int = 0
    rejected: int = 0       # malformed messages (bad JSON/topic) - parse_message failures
    dropped: int = 0        # queue was full
    accepted: int = 0       # passed screening, within normal range
    flagged: int = 0        # passed screening, but an unusual jump
    screen_rejected: int = 0  # failed screening - impossible value, never stored
    rate_limited: int = 0


class DbWriter(threading.Thread):
    """Drains the queue into MySQL in batches; survives database outages."""

    def __init__(self, cfg, q, batch_size, stats, insert_sql=INSERT_SQL, name="db-writer"):
        super().__init__(name=name)
        self.cfg, self.q, self.batch_size, self.stats = cfg, q, batch_size, stats
        self.insert_sql = insert_sql
        self.stop_event = threading.Event()
        self.conn = None
        self.inserted = 0
        self.lost = 0

    def _drain(self, room):
        items = []
        try:
            items.append(self.q.get(timeout=0.1 if self.stop_event.is_set() else 1.0))
        except queue.Empty:
            return items
        while len(items) < room:
            try:
                items.append(self.q.get_nowait())
            except queue.Empty:
                break
        return items

    def _close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def _write(self, batch):
        """Insert a batch. True = batch is finished with (stored or unsalvageable)."""
        try:
            if self.conn is None:
                self.conn = connect_db(self.cfg)
                log.info("connected to MySQL at %s:%s", self.cfg["host"], self.cfg["port"])
            with self.conn.cursor() as cur:
                cur.executemany(self.insert_sql, batch)
            self.conn.commit()
            self.inserted += len(batch)
            return True
        except (pymysql.DataError, pymysql.IntegrityError) as e:
            # A bad row would otherwise block the queue forever: isolate it.
            log.warning("batch rejected (%s); retrying row by row", e)
            return self._write_row_by_row(batch)
        except (pymysql.MySQLError, OSError) as e:
            log.warning("MySQL write failed (%s); will retry", e)
            self._close()
            return False

    def _write_row_by_row(self, batch):
        try:
            self.conn.rollback()
            for row in batch:
                try:
                    with self.conn.cursor() as cur:
                        cur.execute(self.insert_sql, row)
                    self.conn.commit()
                    self.inserted += 1
                except (pymysql.DataError, pymysql.IntegrityError) as e:
                    self.conn.rollback()
                    self.lost += 1
                    log.error("dropping unstorable row %s: %s", row[:4], e)
            return True
        except (pymysql.MySQLError, OSError) as e:
            log.warning("MySQL write failed (%s); will retry", e)
            self._close()
            return False

    def run(self):
        batch, backoff = [], 1.0
        while True:
            if len(batch) < self.batch_size:
                batch += self._drain(self.batch_size - len(batch))
            if not batch:
                if self.stop_event.is_set():
                    break
                continue
            if self._write(batch):
                batch, backoff = [], 1.0
            elif self.stop_event.is_set():
                self.lost += len(batch)
                log.error("shutting down with MySQL unreachable; %d rows lost", len(batch))
                break
            else:
                self.stop_event.wait(backoff)
                backoff = min(backoff * 2, 30.0)
        self._close()


# ------------------------------------------------------------------- MQTT
def build_client(args, q, audit_q, rate_limiter, checker, stats):
    try:  # paho-mqtt >= 2.0
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=args.client_id)
    except AttributeError:  # paho-mqtt 1.x
        client = mqtt.Client(client_id=args.client_id)

    if args.username:
        client.username_pw_set(args.username, os.environ.get("MQTT_PASSWORD"))

    if not args.no_tls:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.cafile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if args.certfile:
            ctx.load_cert_chain(args.certfile, args.keyfile)
        if args.tls_insecure:
            ctx.check_hostname = False  # chain is still verified against the CA
        client.tls_set_context(ctx)

    def on_connect(client, userdata, flags, rc, properties=None):
        failed = rc.is_failure if hasattr(rc, "is_failure") else rc != 0
        if failed:
            log.error("broker refused connection: %s", rc)
            return
        log.info("connected to broker; subscribing to %s (qos %d)", args.topic, args.qos)
        client.subscribe(args.topic, qos=args.qos)  # re-subscribes after reconnects

    def on_disconnect(client, userdata, *rest):
        log.warning("disconnected from broker (%s); paho will reconnect", rest[-2] if len(rest) > 1 else rest)

    def _audit(node_id, sensor, decision, reason, ts):
        try:
            audit_q.put_nowait((node_id, sensor, decision, reason, ts))
        except queue.Full:
            log.error("audit queue full, dropping audit entry for %s/%s", node_id, sensor)

    def on_message(client, userdata, msg):
        received_at = utcnow()
        stats.received += 1
        try:
            row = parse_message(msg.topic, msg.payload, received_at)
        except ValueError as e:
            stats.rejected += 1
            log.warning("rejected message on %s: %s", msg.topic, e)
            return

        node_id, sensor = row[0], row[1]

        if not rate_limiter.allow(node_id):
            stats.rate_limited += 1
            _audit(node_id, sensor, "rate_limited", "exceeded message rate limit", received_at)
            return

        result = checker.check_row(row)
        reason = "; ".join(result.reasons)

        if result.tier == "impossible":
            stats.screen_rejected += 1
            _audit(node_id, sensor, "rejected", reason, received_at)
            log.warning("rejected impossible reading from %s/%s: %s", node_id, sensor, reason)
            return  # never stored in readings

        decision = "flagged" if result.tier == "unusual" else "accepted"
        if decision == "flagged":
            stats.flagged += 1
            log.warning("flagged unusual reading from %s/%s: %s", node_id, sensor, reason)
        else:
            stats.accepted += 1
        _audit(node_id, sensor, decision, reason, received_at)

        try:
            q.put_nowait(row)
        except queue.Full:
            stats.dropped += 1
            log.error("queue full, dropping message from %s", msg.topic)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    return client


# ------------------------------------------------------------------- main
def parse_args():
    e = os.environ.get
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)

    g = ap.add_argument_group("MQTT")
    g.add_argument("--host", default=e("MQTT_HOST", "localhost"))
    g.add_argument("--port", type=int, default=int(e("MQTT_PORT", "8883")))
    g.add_argument("--cafile", default=e("MQTT_CAFILE"), help="CA that signed the broker cert (default: system CAs)")
    g.add_argument("--certfile", default=e("MQTT_CERTFILE"), help="client certificate (mutual TLS)")
    g.add_argument("--keyfile", default=e("MQTT_KEYFILE"), help="client private key (mutual TLS)")
    g.add_argument("--tls-insecure", action="store_true", help="skip hostname check (chain still verified)")
    g.add_argument("--no-tls", action="store_true", help="plain MQTT, for local debugging only")
    g.add_argument("--username", default=e("MQTT_USERNAME"))
    g.add_argument("--topic", default="sensors/#")
    g.add_argument("--qos", type=int, default=1, choices=[0, 1, 2])
    g.add_argument("--client-id", default="sensor-collector")

    g = ap.add_argument_group("MySQL")
    g.add_argument("--mysql-host", default=e("MYSQL_HOST", "localhost"))
    g.add_argument("--mysql-port", type=int, default=int(e("MYSQL_PORT", "3306")))
    g.add_argument("--mysql-user", default=e("MYSQL_USER", "sensor"))
    g.add_argument("--mysql-db", default=e("MYSQL_DATABASE", "sensors"))
    g.add_argument("--mysql-ssl-ca", default=e("MYSQL_SSL_CA"), help="CA file to encrypt the MySQL connection")
    g.add_argument("--init-schema", action="store_true", help="run schema.sql at startup (CREATE TABLE IF NOT EXISTS)")

    g = ap.add_argument_group("tuning")
    g.add_argument("--batch-size", type=int, default=100)
    g.add_argument("--queue-size", type=int, default=10000)
    g.add_argument("--stats-interval", type=float, default=30.0)
    g.add_argument("--rate-limit-count", type=int, default=20,
                    help="max messages per node_id per --rate-limit-window seconds")
    g.add_argument("--rate-limit-window", type=float, default=10.0)
    g.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    cfg = {
        "host": args.mysql_host,
        "port": args.mysql_port,
        "user": args.mysql_user,
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "database": args.mysql_db,
        "ssl_ca": args.mysql_ssl_ca,
    }

    # Fail fast on a bad database config instead of silently buffering forever.
    try:
        if args.init_schema:
            init_schema(cfg)
            log.info("schema ready")
        connect_db(cfg).close()
    except (pymysql.MySQLError, OSError) as e:
        log.error("cannot use MySQL at %s:%s: %s", cfg["host"], cfg["port"], e)
        return 1

    stats = Stats()
    q = queue.Queue(maxsize=args.queue_size)
    writer = DbWriter(cfg, q, args.batch_size, stats)
    writer.start()

    audit_q = queue.Queue(maxsize=args.queue_size)
    audit_writer = DbWriter(cfg, audit_q, args.batch_size, stats,
                             insert_sql=AUDIT_INSERT_SQL, name="audit-writer")
    audit_writer.start()

    rate_limiter = RateLimiter(args.rate_limit_count, args.rate_limit_window)
    checker = PlausibilityChecker()

    client = build_client(args, q, audit_q, rate_limiter, checker, stats)
    try:
        client.connect(args.host, args.port, keepalive=30)
    except (ssl.SSLError, OSError) as e:
        log.error("cannot connect to broker %s:%s: %s", args.host, args.port, e)
        writer.stop_event.set()
        audit_writer.stop_event.set()
        writer.join()
        audit_writer.join()
        return 1
    client.loop_start()  # handles reconnects from here on

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    while not stop.wait(args.stats_interval):
        log.info(
            "received=%d inserted=%d rejected=%d dropped=%d queued=%d "
            "accepted=%d flagged=%d screen_rejected=%d rate_limited=%d",
            stats.received, writer.inserted, stats.rejected, stats.dropped, q.qsize(),
            stats.accepted, stats.flagged, stats.screen_rejected, stats.rate_limited,
        )

    log.info("shutting down")
    client.disconnect()
    client.loop_stop()
    writer.stop_event.set()
    audit_writer.stop_event.set()
    writer.join(timeout=30)
    audit_writer.join(timeout=30)
    log.info("final: received=%d inserted=%d rejected=%d dropped=%d lost=%d "
             "accepted=%d flagged=%d screen_rejected=%d rate_limited=%d",
             stats.received, writer.inserted, stats.rejected, stats.dropped, writer.lost,
             stats.accepted, stats.flagged, stats.screen_rejected, stats.rate_limited)
    return 0


if __name__ == "__main__":
    sys.exit(main())