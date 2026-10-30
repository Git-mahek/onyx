# IoT Device Vulnerability Scanner — Build Guide

**Mentor:** Mr. Santosh Kumar
**Timeline:** Oct 15 – Dec 9 (8 weeks)

---

## 1. The big picture

```
ESP32 sensor nodes (x3)
   │  Wi-Fi + TLS (MQTT, port 8883)
   ▼
Mosquitto broker (TLS-only, self-signed cert)
   │
   ▼
Python/Flask server
   ├─ Rate limiting (caps messages per device)
   ├─ 3-tier plausibility check (impossible / unusual / normal)
   ├─ Vulnerability scanner (port scan + auth check, DoS check)
   ├─ Risk aggregation (combines both checks into a per-device score)
   └─ Admin-only audit log
   │
   ▼
MySQL database (readings + audit log)
   │
   ▼
Live dashboard (Flask + Chart.js, admin-protected)
```

The project has two halves that run in parallel: **the thing being protected** (sensor nodes → broker → server → database → dashboard) and **the thing that protects it** (the vulnerability scanner). We're building and demonstrating both — insecure first, then with fixes applied.

---

## 2. Sensor nodes (ESP32, firmware)

Three nodes, each on its own ESP32:

| Node | Sensor | Pins |
|---|---|---|
| Node 1 | Temperature/Humidity (DHT11) | 1 digital pin |
| Node 2 | PIR motion (HC-SR501) | 1 digital pin, edge-detected (HIGH/LOW transition) |
| Node 3 | Water level | 2 pins — power pin (pulsed on/off) + analog signal pin |

Each node:
1. Reads its sensor
2. Builds a JSON message matching the agreed schema (see §4)
3. Publishes it over MQTT to its own topic, via TLS

**Libraries used:** `WiFi.h`, `WiFiClientSecure.h`, `PubSubClient.h`

---

## 3. Mosquitto broker (TLS)

Mosquitto runs locally (or on a shared machine on our test network) as the MQTT broker, with **TLS enforced, no plaintext fallback for the real deployment** — port 8883 only.

- A self-signed CA + server certificate pair is generated with OpenSSL (`ca.crt`, `ca.key`, `server.crt`, `server.key`)
- `mosquitto.conf` points `cafile`/`certfile`/`keyfile` at these
- The same `ca.crt` is pasted into each ESP32's firmware (`setCACert()`) so nodes trust the broker
- During early development, plain port 1883 is left open alongside 8883 so TLS problems can be isolated from MQTT problems — **this gets closed before the final demo**, since an open 1883 is exactly the kind of finding our own scanner would flag

**Testing without hardware:** a Python "fake node" script using `paho-mqtt` can publish fake readings over TLS, letting the server/dashboard/scanner work proceed without waiting on firmware.

---

## 4. Message schema (agreed once, used everywhere)

Every sensor reading is a JSON object with these fields:

```json
{
  "node_id": "water1",
  "sensor_type": "water",
  "value": 2048,
  "unit": "raw_adc",
  "timestamp": 1733900000
}
```

**This schema doesn't change once agreed.** Every later module — the plausibility check, the audit log, the dashboard — reads this exact shape. If it needs to change, the whole team needs to know before anyone's code breaks on it.

Topic naming: `sensors/<type>/<node_id>` — e.g. `sensors/water/node1`.

---

## 5. Flask server — the receiving/processing side

A Python script subscribes to the broker (`paho-mqtt`, `tls_set()`) and, for each message:

1. **Rate limiting** — caps how many messages a device can send in a given window; excess is dropped/flagged (defends against flooding abuse at the application level, separate from the DoS *scanner check*, which tests resilience rather than enforcing a policy)
2. **3-tier plausibility check** — on the *value itself*, not the sender's identity:
   - **Impossible** (e.g. humidity > 100%, negative water level) → rejected
   - **Unusual** (e.g. implausible jump since the last reading) → flagged for review, stored but marked
   - **Normal** → accepted
3. **Storage** — verified readings go into MySQL
4. **Audit log** — every stored/flagged/rejected event is logged, viewable only by an authenticated admin on the dashboard

---

## 6. The vulnerability scanner — 2 modules

This is the "attacker's-eye view" half of the project — it probes the same system from outside, the way a real attacker would.

| Module | What it checks | Status |
|---|---|---|
| **Port scan + auth check** | Scans for open/unexpected ports and services (`socket`, `python-nmap`), compares against an allowlist per node, and tests whether open services (HTTP, MQTT, Telnet) accept no login or a well-known default credential | Built (`auth_check.py`; port scan to be merged in) |
| **DoS / flooding** | Sends a controlled, rate-limited, time-boxed flood against a service and measures response degradation — **never run uncontrolled against real hardware** | Planned, Week 4 |

Both modules output the same `Finding` shape — `host, port, service, issue, severity, detail` — so results can be merged into one report regardless of which module found them.

---

## 7. Risk aggregation

Both scanner modules' findings are combined into a single per-device risk score. Severity isn't just the worst single finding — combinations matter: an open port *plus* a working default login rates higher than either alone, since that's a directly exploitable path (this is the exact pattern Mirai used).

---

## 8. Dashboard

Flask + Chart.js, reading from MySQL (not talking to the sensors directly). Shows:
- Live sensor readings per node
- Flags from the plausibility check
- Per-device risk scores from the scanner
- Admin-only audit log view

---

## 9. Real-world grounding (for the report/presentation)

Every vulnerability category above maps to a real incident:

- **Mirai (2016)** — open Telnet + default passwords → ~600,000 devices compromised → record DDoS
- **BrickerBot (2017)** — same entry point as Mirai, but corrupted storage instead of hijacking (permanent "bricking")
- **VPNFilter (2018)** — unpatched firmware vulnerabilities → 500,000+ routers → traffic interception, data exfiltration, remote disable
- **Gayfemboy (2024–present)** — Mirai-derived, still exploiting weak Telnet credentials today, proving the problem remains unsolved nearly a decade later

Full citations are in the project README's Sources section — keep the two documents in sync.

---

## 10. Build order (why it's sequenced this way)

1. **Hardware + message format** — nothing else works until nodes can send a reading in the agreed shape
2. **Logging + dashboard** — get data visible early, so every later module has something real to check
3. **Port scan + auth check** — merge the two into one module
4. **DoS** — needs a stable target to test against safely
5. **Merge into the full scanner** — combine both modules behind one CLI, with a shared result format
6. **Scoring system** — needs both modules producing real findings to score against

---

## 11. Known limitations

- Open ports and weak authentication are tested; the HTTP check only probes one path (`/`) by default
- The DoS module measures degradation, not a true production-scale attack — by design, to avoid breaking our own hardware
- The plausibility check's thresholds are heuristic, not based on formal sensor-fault modeling
- Data spoofing / message integrity (HMAC signing) is **not** part of this build — messages are protected in transit by TLS, but a compromised or malicious node's data is not independently verified
