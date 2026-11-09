"""dos_check.py - controlled DoS/flood resilience check.

Sends a rate-limited, time-boxed burst of requests at a target and measures
whether response time degrades. This is NOT trying to crash anything - the
defaults are deliberately mild (5 seconds, low rate). Only ever point this
at fake_targets.py or hardware you own and have explicitly decided to test.

Supported targets: http, mqtt (re-uses auth_check's MQTT CONNECT handshake
as the "request" being timed - a real flood would use more than CONNECT,
but repeatedly connecting/disconnecting is itself a legitimate resource-
exhaustion vector worth measuring for a broker).
"""

import socket
import statistics
import time

from findings import Finding

TIMEOUT = 3.0


def _time_http_get(host, port, path="/"):
    import http.client
    start = time.monotonic()
    conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read(256)
        ok = resp.status < 500
    finally:
        conn.close()
    return time.monotonic() - start, ok


def _time_mqtt_connect(host, port):
    from auth_check import _mqtt_connect
    start = time.monotonic()
    try:
        _mqtt_connect(host, port)
        ok = True
    except (OSError, ValueError):
        ok = False
    return time.monotonic() - start, ok


TIMERS = {"http": _time_http_get, "mqtt": _time_mqtt_connect}


def flood_check(host, port, service, duration=5.0, rate=10.0):
    """Send `rate` requests/sec for `duration` seconds, comparing the first
    and second half of the run. Returns a list of Finding (possibly empty).

    rate is a ceiling, not a guarantee - a slow/overloaded target will
    naturally throttle how many requests actually get sent, which is
    itself part of what we're measuring.
    """
    if service not in TIMERS:
        raise ValueError(f"no timer for service {service!r}")
    timer = TIMERS[service]
    interval = 1.0 / rate

    samples = []   # (elapsed_since_start, latency, ok)
    failures = 0
    start = time.monotonic()
    while time.monotonic() - start < duration:
        tick = time.monotonic()
        try:
            latency, ok = timer(host, port)
        except OSError:
            latency, ok = None, False
        if not ok:
            failures += 1
        if latency is not None:
            samples.append((tick - start, latency))
        sleep_left = interval - (time.monotonic() - tick)
        if sleep_left > 0:
            time.sleep(sleep_left)

    if not samples:
        return [Finding(host, port, service, "Target unreachable during flood test", "MEDIUM",
                        f"no successful requests in {duration}s at {rate}/s - "
                        "either already down or refusing connections outright")]

    mid = duration / 2
    first_half = [lat for t, lat in samples if t < mid]
    second_half = [lat for t, lat in samples if t >= mid]

    findings = []
    if failures > 0:
        severity = "HIGH" if failures / max(len(samples) + failures, 1) > 0.3 else "MEDIUM"
        findings.append(Finding(host, port, service, "Requests failed under load", severity,
                                f"{failures} of {failures + len(samples)} requests failed "
                                f"during a {duration}s flood at {rate}/s"))

    if first_half and second_half:
        avg1, avg2 = statistics.mean(first_half), statistics.mean(second_half)
        if avg2 > avg1 * 2 and avg2 - avg1 > 0.05:
            findings.append(Finding(host, port, service, "Response time degrades under sustained load", "MEDIUM",
                                    f"avg latency rose from {avg1*1000:.0f}ms to {avg2*1000:.0f}ms "
                                    f"over a {duration}s flood at {rate}/s"))

    if not findings:
        findings.append(Finding(host, port, service, "No significant degradation observed", "LOW",
                                f"{len(samples)} requests over {duration}s at {rate}/s; "
                                f"avg latency {statistics.mean(lat for _, lat in samples)*1000:.0f}ms, "
                                f"{failures} failures"))
    return findings
