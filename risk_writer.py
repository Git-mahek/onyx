"""risk_writer.py - write RiskScore results into the device_risk table.

Connection pattern matches mqtt_subscriber.py's connect_db() exactly on
purpose: pymysql, password only from the MYSQL_PASSWORD environment
variable (never a CLI flag, never hardcoded), utf8mb4, optional TLS via
MYSQL_SSL_CA. One MySQL connection convention for the whole project.
"""

import argparse
import os

import pymysql

UPSERT_SQL = (
    "INSERT INTO device_risk (node_id, score, severity, last_scanned) "
    "VALUES (%s, %s, %s, %s) "
    "ON DUPLICATE KEY UPDATE score=VALUES(score), severity=VALUES(severity), "
    "last_scanned=VALUES(last_scanned)"
)


def connect_db(cfg):
    """Identical shape to mqtt_subscriber.connect_db - same project, same
    pattern, so there's exactly one way this project talks to MySQL."""
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


def write_scores(cfg, scores):
    """scores: dict of node_id -> RiskScore (from risk_aggregation.py).
    Upserts one row per device - a re-scan updates the existing row rather
    than appending, since device_risk holds current state, not history."""
    conn = connect_db(cfg)
    try:
        with conn.cursor() as cur:
            for score in scores.values():
                cur.execute(UPSERT_SQL, (
                    score.node_id, score.score, score.severity,
                    score.last_scanned.replace(tzinfo=None),
                ))
        conn.commit()
    finally:
        conn.close()


def cfg_from_env(args):
    return {
        "host": args.mysql_host,
        "port": args.mysql_port,
        "user": args.mysql_user,
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "database": args.mysql_db,
        "ssl_ca": args.mysql_ssl_ca,
    }


def build_arg_parser():
    ap = argparse.ArgumentParser(description="Write risk scores to device_risk")
    ap.add_argument("--mysql-host", default=os.environ.get("MYSQL_HOST", "localhost"))
    ap.add_argument("--mysql-port", type=int, default=int(os.environ.get("MYSQL_PORT", "3306")))
    ap.add_argument("--mysql-user", default=os.environ.get("MYSQL_USER", "sensor"))
    ap.add_argument("--mysql-db", default=os.environ.get("MYSQL_DATABASE", "sensors"))
    ap.add_argument("--mysql-ssl-ca", default=os.environ.get("MYSQL_SSL_CA"))
    return ap
