"""app.py - Flask backend for the Onyx dashboard.

Fixes the one thing that mattered most: login used to be entirely
client-side with plaintext passwords sitting in the page's own JS source
(viewable via view-source on ANY visitor). Auth now happens here, server
side, with hashed passwords and a real session cookie.

Run:
    export MYSQL_PASSWORD=sensorpw
    python app.py
"""

import os
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request, session, send_from_directory
from werkzeug.security import check_password_hash

import db

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

# Server-side lockout: 5 failed attempts per 5 minutes, PER USERNAME - the
# UI already claimed this; now it's actually enforced, not just decorative.
_failed_logins = defaultdict(deque)
LOCKOUT_MAX = 5
LOCKOUT_WINDOW = 5 * 60


def _locked_out(username):
    now = time.time()
    q = _failed_logins[username]
    while q and now - q[0] > LOCKOUT_WINDOW:
        q.popleft()
    return len(q) >= LOCKOUT_MAX


def _record_failure(username):
    _failed_logins[username].append(time.time())


# ------------------------------------------------------------------- auth
@app.post("/api/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))

    if _locked_out(username):
        return jsonify(error="Too many failed attempts. Try again later."), 429

    try:
        conn = db.connect()
        try:
            user = db.fetch_user(conn, username)
        finally:
            conn.close()
    except db.pymysql.MySQLError:
        app.logger.exception("could not look up user during login")
        return jsonify(error="Login service is temporarily unavailable."), 503

    if not user or not check_password_hash(user["password_hash"], password):
        _record_failure(username)
        return jsonify(error="Wrong username or password."), 401

    _failed_logins.pop(username, None)
    session.clear()
    session["username"] = username
    session["role"] = user["role"]
    return jsonify(username=username, role=user["role"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    if "username" not in session:
        return jsonify(authenticated=False), 401
    return jsonify(authenticated=True, username=session["username"], role=session["role"])


def require_login():
    return "username" in session


def require_admin():
    return session.get("role") == "admin"


# --------------------------------------------------------------- data API
@app.get("/api/alerts")
def api_alerts():
    if not require_login():
        return jsonify(error="login required"), 401
    conn = db.connect()
    try:
        return jsonify(db.fetch_alerts(conn))
    finally:
        conn.close()


@app.get("/api/sensors")
def api_sensors():
    if not require_login():
        return jsonify(error="login required"), 401
    conn = db.connect()
    try:
        latest = db.fetch_sensor_latest(conn)
        out = {}
        for kind, row in latest.items():
            out[kind] = {k: (v.isoformat() if hasattr(v, "isoformat") else v)
                         for k, v in row.items()}
        return jsonify(out)
    finally:
        conn.close()


@app.get("/api/sensors/<kind>/series")
def api_sensor_series(kind):
    if not require_login():
        return jsonify(error="login required"), 401
    if kind not in ("water", "pir", "temp"):
        return jsonify(error="unknown sensor kind"), 404
    minutes = int(request.args.get("minutes", 60))
    conn = db.connect()
    try:
        rows = db.fetch_sensor_series(conn, kind, minutes=minutes)
        out = [{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in r.items()}
               for r in rows]
        return jsonify(out)
    finally:
        conn.close()


@app.get("/api/risk")
def api_risk():
    if not require_login():
        return jsonify(error="login required"), 401
    conn = db.connect()
    try:
        return jsonify(db.fetch_risk(conn))
    finally:
        conn.close()


@app.get("/api/audit")
def api_audit():
    if not require_login():
        return jsonify(error="login required"), 401
    if not require_admin():
        return jsonify(error="admin only"), 403
    conn = db.connect()
    try:
        return jsonify(db.fetch_audit(conn))
    finally:
        conn.close()


# ------------------------------------------------------------- static page
@app.get("/")
def index():
    return send_from_directory(".", "fixed_ONYX.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
