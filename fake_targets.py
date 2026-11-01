"""fake_targets.py - deliberately insecure fake services for testing auth_check.py.

These run on 127.0.0.1 only. They let you test the scanner without real
hardware, and give your demo something vulnerable to find.

Run `python fake_targets.py` to start them on fixed ports, then in another
terminal:
    python auth_check.py --target 127.0.0.1:18080:http \
        --target 127.0.0.1:11883:mqtt --target 127.0.0.1:12323:telnet
"""

import base64
import http.server
import socketserver
import threading
import time


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def start_http(port=0, creds=None):
    """HTTP server. creds=(user, password) -> Basic auth; None -> no auth at all."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if creds:
                good = "Basic " + base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
                if self.headers.get("Authorization") != good:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="sensor"')
                    self.end_headers()
                    return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"temp=24.1")

        def log_message(self, *args):
            pass

    return _serve(http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler))


class _MQTTHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        flags = data[9]
        pos = 12  # skip fixed header, protocol name, level, flags, keep-alive
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")  # client id
        user = password = None
        if flags & 0x80:
            size = int.from_bytes(data[pos:pos + 2], "big")
            user = data[pos + 2:pos + 2 + size].decode()
            pos += 2 + size
        if flags & 0x40:
            size = int.from_bytes(data[pos:pos + 2], "big")
            password = data[pos + 2:pos + 2 + size].decode()
        allowed = self.server.creds
        ok = allowed is None or (user, password) == allowed
        self.request.sendall(bytes([0x20, 2, 0, 0 if ok else 5]))


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_mqtt(port=0, creds=None):
    """Fake MQTT broker. creds=None -> anonymous access allowed."""
    server = _TCPServer(("127.0.0.1", port), _MQTTHandler)
    server.creds = creds
    return _serve(server)


def _strip_iac(raw):
    out, i = bytearray(), 0
    while i < len(raw):
        if raw[i] == 255 and i + 2 < len(raw):
            i += 3
        else:
            out.append(raw[i])
            i += 1
    return bytes(out).decode(errors="ignore").strip()


class _TelnetHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(bytes([255, 253, 1]) + b"\r\nBusyBox login: ")  # IAC DO ECHO
        user = _strip_iac(self.rfile.readline())
        self.wfile.write(b"Password: ")
        password = _strip_iac(self.rfile.readline())
        if (user, password) == self.server.creds:
            self.wfile.write(b"\r\nWelcome\r\n~ # ")
        else:
            self.wfile.write(b"\r\nLogin incorrect\r\nBusyBox login: ")


def start_telnet(port=0, creds=("admin", "admin")):
    """Fake Telnet server that accepts one login (a factory default by default)."""
    server = _TCPServer(("127.0.0.1", port), _TelnetHandler)
    server.creds = creds
    return _serve(server)


if __name__ == "__main__":
    start_http(18080, creds=("admin", "admin"))
    start_mqtt(11883, creds=None)
    start_telnet(12323, creds=("root", "root"))
    print("Fake targets running: http 18080, mqtt 11883, telnet 12323 (Ctrl+C to stop)")
    while True:
        time.sleep(1)
