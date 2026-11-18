"""auth_check.py - open-port scan + inadequate-authentication checks.

One "port + auth" module. Two stages:
  A. PORT SCAN: TCP connect scan of common IoT ports, identify the service on
     each open port (banner / probe / port-number heuristic), and flag any
     open port that is not on that host's allowlist ("Unexpected open port").
  B. AUTH CHECKS: every discovered service we can test is passed straight into
     check_http / check_mqtt / check_telnet.

For every open service it is pointed at, the auth stage asks three questions:
  1. Does the service require authentication at all?
  2. Does it accept a well-known factory-default login?
  3. Are credentials sent over an unencrypted channel?

Supported services: http (Basic auth), mqtt (plain, port 1883), telnet.
Uses only the Python standard library.

!! Only run this against devices you own or are authorised to test. !!
Guards built in: private/loopback addresses only (scan AND auth stages), a
short fixed credential list (this is a default-credential check, NOT a password cracker), and a
delay between attempts so small devices (ESP32) are not hammered or locked out.

Usage:
    python auth_check.py --scan 192.168.1.101 --allowlist allowlist.json --out findings.json
    python auth_check.py --target 192.168.1.50:8080:http --target 192.168.1.50:1883:mqtt
    python auth_check.py --from-scan port_scan_results.json --out auth_findings.json

allowlist.json maps each host to the ports it is SUPPOSED to expose, e.g.
    {"192.168.1.101": [8883], "192.168.1.102": [8883]}
A host missing from the file has an empty allowlist (default deny): every
open port on it is reported.
"""

import argparse
import base64
import http.client
import ipaddress
import json
import os
import socket
import sys
import time
from dataclasses import asdict
from urllib.parse import urljoin, urlsplit, urlunsplit

from findings import Finding
from risk_aggregation import score_hosts

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


def require_private(host):
    """Refuse to touch anything that is not on a private or loopback address."""
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if not (ip.is_private or ip.is_loopback):
        raise ValueError(f"{host} is not a private address; refusing to scan")


# --------------------------------------------------------------------- HTTP
def _http_get(host, port, path, headers=None):
    current_path = path
    for redirect_count in range(6):
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
        try:
            conn.request("GET", current_path, headers=headers or {})
            resp = conn.getresponse()
            status = resp.status
            www_auth = resp.getheader("WWW-Authenticate") or ""
            location = resp.getheader("Location")
            resp.read(1024)
        finally:
            conn.close()

        if status not in (301, 302, 303, 307, 308) or not location or redirect_count == 5:
            return status, www_auth

        target = urlsplit(urljoin(f"http://{host}:{port}{current_path}", location))
        try:
            target_port = target.port or 80
        except ValueError:
            return status, www_auth
        if (target.scheme != "http" or target.hostname != host.lower()
                or target_port != port or target.username or target.password):
            return status, www_auth
        current_path = urlunsplit(("", "", target.path or "/", target.query, ""))
    return status, www_auth


def check_http(host, port, path="/"):
    findings = []
    status, www_auth = _http_get(host, port, path)  # OSError -> caller skips

    if 200 <= status < 300:
        findings.append(Finding(host, port, "http", "No authentication required", "HIGH",
                                f"GET {path} returned {status} without any credentials"))
    elif status == 401 and www_auth.lower().startswith("basic"):
        findings.append(Finding(host, port, "http", "Credentials sent in cleartext", "MEDIUM",
                                "HTTP Basic auth over plain HTTP: login is only base64-encoded"))
        for user, password in DEFAULT_CREDENTIALS:
            token = base64.b64encode(f"{user}:{password}".encode()).decode()
            try:
                status, _ = _http_get(host, port, path, {"Authorization": f"Basic {token}"})
            except OSError:
                break
            if 200 <= status < 300:
                findings.append(Finding(host, port, "http", "Default credentials accepted", "CRITICAL",
                                        f"login worked with {user}:{password!r}"))
                break
            time.sleep(DELAY_BETWEEN_ATTEMPTS)
    return findings


# --------------------------------------------------------------------- MQTT
def _mqtt_str(raw):
    return len(raw).to_bytes(2, "big") + raw


def _recv_exact(sock, size):
    received = bytearray()
    while len(received) < size:
        chunk = sock.recv(size - len(received))
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)


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
        header = _recv_exact(sock, 2)
        if len(header) != 2 or header[0] != 0x20 or header[1] != 2:
            raise ValueError("service did not answer like an MQTT broker")
        body = _recv_exact(sock, 2)
    if len(body) != 2:
        raise ValueError("service did not answer like an MQTT broker")
    return body[1]


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


# ---------------------------------------------------------------- port scan
# Common ports for IoT devices. Kept short on purpose: this is a connect scan
# of our own devices, not a full-range sweep.
COMMON_PORTS = [21, 22, 23, 80, 443, 554, 1883, 1880, 2323, 5683, 8000, 8080, 8081, 8443, 8883, 8888]
SCAN_TIMEOUT = 0.5  # seconds per port
SCAN_DELAY = 0.05  # seconds between ports, so small devices (ESP32) are not flooded
BANNER_WAIT = 0.7  # seconds to listen for a banner the service sends by itself
# Used only when a service gives us nothing to go on.
PORT_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 2323: "telnet", 80: "http", 8080: "http",
              8000: "http", 8081: "http", 8888: "http", 1880: "http", 443: "https", 8443: "https",
              554: "rtsp", 1883: "mqtt", 8883: "mqtt-tls", 5683: "coap"}
RISKY_SERVICES = {"telnet", "ftp"}  # cleartext remote-login services


def scan_ports(host, ports=None):
    """TCP connect scan. Returns the sorted list of open ports on host."""
    require_private(host)
    open_ports = []
    for port in (COMMON_PORTS if ports is None else ports):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SCAN_TIMEOUT)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
        time.sleep(SCAN_DELAY)
    return sorted(open_ports)


def _grab(host, port, probe=b""):
    """Connect, optionally send a probe, return whatever the service says first."""
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        if probe:
            sock.sendall(probe)
        sock.settimeout(BANNER_WAIT)
        try:
            return sock.recv(256)
        except socket.timeout:
            return b""


def identify_service(host, port):
    """Name the service on an open port: banner first, then probes, then port number."""
    require_private(host)
    try:
        banner = _grab(host, port)  # passive: telnet/ssh/ftp talk first
        if banner[:1] == bytes([IAC]) or b"login:" in banner.lower():
            return "telnet"
        if banner.startswith(b"SSH-"):
            return "ssh"
        if banner.startswith(b"220"):
            return "ftp"
        if banner.startswith(b"HTTP/"):
            return "http"
        if not banner:  # silent service: HTTP and MQTT wait for the client
            if _grab(host, port, b"HEAD / HTTP/1.0\r\n\r\n").startswith(b"HTTP/"):
                return "http"
            try:
                _mqtt_connect(host, port)  # valid CONNACK reply = MQTT broker
                return "mqtt"
            except (ValueError, OSError):
                pass
    except OSError:
        pass
    return PORT_NAMES.get(port, "unknown")


def load_allowlist(path):
    """JSON file {host: [ports]} -> {host: set(ports)}."""
    with open(path) as handle:
        return {host: {int(p) for p in ports} for host, ports in json.load(handle).items()}


def load_node_map(path):
    """JSON file {host: node_id} -> validated host-to-device mapping."""
    with open(path) as handle:
        mapping = json.load(handle)
    if not isinstance(mapping, dict) or any(
        not isinstance(host, str) or not host.strip()
        or not isinstance(node_id, str) or not node_id.strip()
        for host, node_id in mapping.items()
    ):
        raise ValueError("node map must be a JSON object mapping host names to non-empty node IDs")
    return {host.strip(): node_id.strip() for host, node_id in mapping.items()}


def scan_host(host, allowlist=None, ports=None):
    """Scan one host. Returns (services, findings).

    services = [(host, port, service)] for every open port, ready for run_checks.
    findings = one "Unexpected open port" Finding per open port not in the allowlist.
    """
    allowed = (allowlist or {}).get(host, set())
    services, findings = [], []
    for port in scan_ports(host, ports):
        service = identify_service(host, port)
        services.append((host, port, service))
        if port not in allowed:
            severity = "HIGH" if service in RISKY_SERVICES else "MEDIUM"
            findings.append(Finding(host, port, service, "Unexpected open port", severity,
                                    f"{service} is listening on {port} but this port is not in the allowlist for {host}"))
    return services, findings


def scan_and_check(hosts, allowlist=None, ports=None):
    """Full pipeline: scan -> identify -> allowlist -> auth checks. Returns Findings."""
    findings, _ = scan_hosts(hosts, allowlist, ports)
    return findings


def scan_hosts(hosts, allowlist=None, ports=None, auth_targets=None):
    """Return findings and scanned hosts; optionally collect discovered auth targets."""
    findings, targets = [], []
    scanned_hosts = []
    for host in hosts:
        try:
            services, host_findings = scan_host(host, allowlist, ports)
        except (OSError, ValueError) as err:
            print(f"[skip] {host}: {err}", file=sys.stderr)
            continue
        scanned_hosts.append(host)
        findings.extend(host_findings)
        targets.extend((h, p, s) for h, p, s in services if s in CHECKS)  # auto-feed
    if auth_targets is None:
        findings.extend(run_checks(targets))
    else:
        auth_targets.extend(targets)
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity]), scanned_hosts


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


def deduplicate_findings(findings):
    unique = []
    seen = set()
    for finding in findings:
        key = (finding.host, finding.port, finding.service, finding.issue,
               finding.severity, finding.detail)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


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
    parser = argparse.ArgumentParser(description="IoT port scan and authentication checks")
    parser.add_argument("--target", action="append", default=[], metavar="HOST:PORT:SERVICE")
    parser.add_argument("--scan", action="append", default=[], metavar="HOST",
                        help="scan this host for open ports, then auth-check what is found")
    parser.add_argument("--allowlist", metavar="FILE", help="JSON {host: [expected ports]}")
    parser.add_argument("--ports", metavar="LIST", help="comma-separated ports (default: common IoT ports)")
    parser.add_argument("--from-scan", metavar="FILE", help="JSON output of the open-port module")
    parser.add_argument("--out", metavar="FILE", help="save findings as JSON")
    parser.add_argument("--node-map", metavar="FILE", help="JSON mapping scanned hosts to sensor node IDs")
    parser.add_argument("--write-db", action="store_true",
                        help="score a full --scan and upsert scores into device_risk")
    parser.add_argument("--mysql-host", default=os.environ.get("MYSQL_HOST", "localhost"))
    parser.add_argument("--mysql-port", type=int, default=int(os.environ.get("MYSQL_PORT", "3306")))
    parser.add_argument("--mysql-user", default=os.environ.get("MYSQL_USER", "sensor"))
    parser.add_argument("--mysql-db", default=os.environ.get("MYSQL_DATABASE", "sensors"))
    parser.add_argument("--mysql-ssl-ca", default=os.environ.get("MYSQL_SSL_CA"))
    args = parser.parse_args()

    targets = []
    for text in args.target:
        host, port, service = text.split(":")
        if service not in CHECKS:
            parser.error(f"service must be one of {sorted(CHECKS)}")
        targets.append((host, int(port), service))
    if args.from_scan:
        targets.extend(targets_from_scan(args.from_scan))
    if not targets and not args.scan:
        parser.error("give at least one --scan, --target or --from-scan")
    if args.write_db and not args.scan:
        parser.error("--write-db requires a full --scan")
    if args.write_db and (args.target or args.from_scan):
        parser.error("--write-db cannot be combined with --target or --from-scan")
    if args.write_db and not args.node_map:
        parser.error("--write-db requires --node-map")

    node_map = {}
    if args.node_map:
        try:
            node_map = load_node_map(args.node_map)
        except (OSError, ValueError) as err:
            parser.error(f"cannot load node map: {err}")
    if args.write_db:
        missing = sorted(set(args.scan) - node_map.keys())
        if missing:
            parser.error("node map is missing scanned host(s): " + ", ".join(missing))

    scanned_hosts = []
    scan_auth_targets = []
    scan_findings = []
    if args.scan:
        allowlist = load_allowlist(args.allowlist) if args.allowlist else {}
        ports = [int(p) for p in args.ports.split(",")] if args.ports else None
        scan_findings, scanned_hosts = scan_hosts(
            args.scan, allowlist, ports, auth_targets=scan_auth_targets
        )
    targets.extend(scan_auth_targets)
    findings = run_checks(list(dict.fromkeys(targets)))
    findings.extend(scan_findings)
    findings = deduplicate_findings(findings)
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    for f in findings:
        print(f"[{f.severity:8}] {f.host}:{f.port} {f.service:6} {f.issue} - {f.detail}")
    if not findings:
        print("No findings.")
    if args.out:
        with open(args.out, "w") as handle:
            json.dump([asdict(f) for f in findings], handle, indent=2)
    if args.write_db:
        if not scanned_hosts:
            print("No hosts completed a scan; no risk scores written.")
            return
        import risk_writer

        scores = score_hosts(scanned_hosts, findings, node_map)
        risk_writer.write_scores(risk_writer.cfg_from_env(args), scores)
        for node_id in sorted(scores):
            score = scores[node_id]
            print(f"[RISK {score.severity:8}] {node_id}: {score.score:g} points")
        print(f"Wrote {len(scores)} risk score(s) to {args.mysql_db}.device_risk")


if __name__ == "__main__":
    main()

