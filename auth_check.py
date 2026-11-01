"""auth_check.py - inadequate-authentication checks for the IoT scanner.

For every open service it is pointed at, this module asks three questions:
  1. Does the service require authentication at all?
  2. Does it accept a well-known factory-default login?
  3. Are credentials sent over an unencrypted channel?

Supported services: http (Basic auth), mqtt (plain, port 1883), telnet.
Uses only the Python standard library.

!! Only run this against devices you own or are authorised to test. !!
Guards built in: private/loopback addresses only, a short fixed credential
list (this is a default-credential check, NOT a password cracker), and a
delay between attempts so small devices (ESP32) are not hammered or locked out.

Usage:
    python auth_check.py --target 192.168.1.50:8080:http --target 192.168.1.50:1883:mqtt
    python auth_check.py --from-scan port_scan_results.json --out auth_findings.json
"""

import argparse
import base64
import http.client
import ipaddress
import json
import socket
import sys
import time
from dataclasses import asdict, dataclass

# Keep this list short. Widening it turns the tool into a brute-forcer.
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", ""),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
]
DELAY_BETWEEN_ATTEMPTS = 1.0  # seconds
TIMEOUT = 3.0  # seconds


@dataclass
class Finding:
    """Same shape as the open-port module so the final report can merge them."""

    host: str
    port: int
    service: str
    issue: str
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    detail: str = ""


def require_private(host):
    """Refuse to touch anything that is not on a private or loopback address."""
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if not (ip.is_private or ip.is_loopback):
        raise ValueError(f"{host} is not a private address; refusing to scan")


# --------------------------------------------------------------------- HTTP
def _http_get(host, port, path, headers=None):
    conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        resp.read(1024)
        return resp.status, resp.getheader("WWW-Authenticate") or ""
    finally:
        conn.close()


def check_http(host, port, path="/"):
    findings = []
    status, www_auth = _http_get(host, port, path)  # OSError -> caller skips

    if status == 200:
        findings.append(Finding(host, port, "http", "No authentication required", "HIGH",
                                f"GET {path} returned 200 without any credentials"))
    elif status == 401 and www_auth.lower().startswith("basic"):
        findings.append(Finding(host, port, "http", "Credentials sent in cleartext", "MEDIUM",
                                "HTTP Basic auth over plain HTTP: login is only base64-encoded"))
        for user, password in DEFAULT_CREDENTIALS:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            try:
                status, _ = _http_get(host, port, path, {"Authorization": f"Basic {token}"})
            except OSError:
                break
            if status == 200:
                findings.append(Finding(host, port, "http", "Default credentials accepted", "CRITICAL",
                                        f"login worked with {user}:{password!r}"))
                break
            time.sleep(DELAY_BETWEEN_ATTEMPTS)
    return findings


# --------------------------------------------------------------------- MQTT
def _mqtt_str(raw):
    return len(raw).to_bytes(2, "big") + raw


def _mqtt_connect(host, port, username=None, password=None):
    """Send an MQTT 3.1.1 CONNECT packet and return the CONNACK code.

    0 = accepted, 4 = bad username/password, 5 = not authorised.
    """
    flags = 0x02  # clean session
    payload = _mqtt_str(b"iot-scanner")
    if username is not None:
        flags |= 0x80
        payload += _mqtt_str(username.encode())
        if password is not None:
            flags |= 0x40
            payload += _mqtt_str(password.encode())
    body = _mqtt_str(b"MQTT") + bytes([4, flags]) + (30).to_bytes(2, "big") + payload
    assert len(body) < 128  # remaining-length fits in one byte
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        sock.sendall(bytes([0x10, len(body)]) + body)
        reply = sock.recv(4)
    if len(reply) < 4 or reply[0] != 0x20:
        raise ValueError("service did not answer like an MQTT broker")
    return reply[3]


def check_mqtt(host, port):
    findings = []
    if port == 1883:
        findings.append(Finding(host, port, "mqtt", "MQTT traffic is unencrypted", "MEDIUM",
                                "plain MQTT on 1883; use TLS on 8883"))
    if _mqtt_connect(host, port) == 0:
        findings.append(Finding(host, port, "mqtt", "Anonymous access allowed", "HIGH",
                                "broker accepted a connection with no username or password"))
        return findings
    for user, password in DEFAULT_CREDENTIALS:
        try:
            code = _mqtt_connect(host, port, user, password)
        except OSError:
            break
        if code == 0:
            findings.append(Finding(host, port, "mqtt", "Default credentials accepted", "CRITICAL",
                                    f"login worked with {user}:{password!r}"))
            break
        time.sleep(DELAY_BETWEEN_ATTEMPTS)
    return findings


# ------------------------------------------------------------------- Telnet
IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251
PROMPT_ENDINGS = (":", "#", "$", ">", "%")
FAILURE_WORDS = ("incorrect", "failed", "invalid", "denied", "bad password")


def _telnet_read(sock, quiet=1.0):
    """Read until the server stops talking or shows a prompt.

    Telnet servers open with option negotiation (IAC bytes). We refuse every
    option, which is enough to get to the login prompt.
    """
    sock.settimeout(quiet)
    data = bytearray()
    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            i = 0
            while i < len(chunk):
                if chunk[i] == IAC and i + 1 < len(chunk) and chunk[i + 1] == IAC:
                    data.append(IAC)
                    i += 2
                elif chunk[i] == IAC and i + 2 < len(chunk):
                    command, option = chunk[i + 1], chunk[i + 2]
                    if command == DO:
                        sock.sendall(bytes([IAC, WONT, option]))
                    elif command == WILL:
                        sock.sendall(bytes([IAC, DONT, option]))
                    i += 3
                else:
                    data.append(chunk[i])
                    i += 1
            if bytes(data).decode(errors="ignore").rstrip().endswith(PROMPT_ENDINGS):
                break
    except socket.timeout:
        pass
    return bytes(data).decode(errors="ignore")


def _telnet_login(host, port, user, password):
    """True = logged in, False = rejected, None = no login prompt seen."""
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        banner = _telnet_read(sock).lower()
        if "login" not in banner and "username" not in banner:
            return None
        sock.sendall(user.encode() + b"\r\n")
        reply = _telnet_read(sock)
        if "password" in reply.lower():
            sock.sendall(password.encode() + b"\r\n")
            reply = _telnet_read(sock)
    low = reply.lower()
    if any(word in low for word in FAILURE_WORDS):
        return False
    # Conservative: only call it a success if we end on a shell-looking prompt.
    return reply.rstrip().endswith(("#", "$", ">", "%"))


def check_telnet(host, port):
    findings = [Finding(host, port, "telnet", "Telnet service is running", "HIGH",
                        "Telnet is unencrypted by design; logins can be read off the network")]
    for user, password in DEFAULT_CREDENTIALS:
        try:
            result = _telnet_login(host, port, user, password)
        except OSError:
            break
        if result is None:
            break  # no login prompt, nothing more to test
        if result:
            findings.append(Finding(host, port, "telnet", "Default credentials accepted", "CRITICAL",
                                    f"login worked with {user}:{password!r}"))
            break
        time.sleep(DELAY_BETWEEN_ATTEMPTS)
    return findings


# --------------------------------------------------------------- dispatcher
CHECKS = {"http": check_http, "mqtt": check_mqtt, "telnet": check_telnet}
SERVICE_NAMES = {"http": "http", "http-alt": "http", "http-proxy": "http",
                 "mqtt": "mqtt", "telnet": "telnet"}
PORT_HINTS = {23: "telnet", 2323: "telnet", 80: "http", 8080: "http", 1883: "mqtt"}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def run_checks(targets):
    """targets: list of (host, port, service). Returns a list of Finding."""
    findings = []
    for host, port, service in targets:
        try:
            require_private(host)
            findings.extend(CHECKS[service](host, port))
        except (OSError, ValueError) as err:
            print(f"[skip] {host}:{port} ({service}): {err}", file=sys.stderr)
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])


def targets_from_scan(path):
    """Read the open-port module's JSON output and pick out services we can test."""
    with open(path) as handle:
        entries = json.load(handle)
    targets = set()
    for entry in entries:
        port = int(entry["port"])
        service = SERVICE_NAMES.get(str(entry.get("service", "")).lower()) or PORT_HINTS.get(port)
        if service:
            targets.add((entry["host"], port, service))
    return sorted(targets)


def main():
    parser = argparse.ArgumentParser(description="Inadequate-authentication checks")
    parser.add_argument("--target", action="append", default=[], metavar="HOST:PORT:SERVICE")
    parser.add_argument("--from-scan", metavar="FILE", help="JSON output of the open-port module")
    parser.add_argument("--out", metavar="FILE", help="save findings as JSON")
    args = parser.parse_args()

    targets = []
    for text in args.target:
        host, port, service = text.split(":")
        if service not in CHECKS:
            parser.error(f"service must be one of {sorted(CHECKS)}")
        targets.append((host, int(port), service))
    if args.from_scan:
        targets.extend(targets_from_scan(args.from_scan))
    if not targets:
        parser.error("give at least one --target or --from-scan")

    findings = run_checks(targets)
    for f in findings:
        print(f"[{f.severity:8}] {f.host}:{f.port} {f.service:6} {f.issue} - {f.detail}")
    if not findings:
        print("No authentication findings.")
    if args.out:
        with open(args.out, "w") as handle:
            json.dump([asdict(f) for f in findings], handle, indent=2)


if __name__ == "__main__":
    main()
