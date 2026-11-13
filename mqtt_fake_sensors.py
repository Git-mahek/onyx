#!/usr/bin/env python3
"""
Fake sensor harness: publishes realistic readings for three nodes over MQTT.

Topics (fixed):
    sensors/water/node1   water level + leak flag
    sensors/pir/node2     motion events (+ periodic heartbeat)
    sensors/temp/node3    temperature + humidity

Payload schema (JSON) -- EDIT HERE if your real schema differs:
    common:  {"node_id": str, "sensor": str, "ts": ISO-8601 UTC str}
    water:   {"level_cm": float, "level_pct": float, "leak": bool}
    pir:     {"motion": bool}
    temp:    {"temperature_c": float, "humidity_pct": float}

Usage:
    pip install paho-mqtt
    python mqtt_fake_sensors.py --host localhost
    python mqtt_fake_sensors.py --interval 0.5 --speed 60      # accelerated sim time
    python mqtt_fake_sensors.py --count 20 --seed 1            # deterministic, finite

Bad-data scenarios (live demo of the subscriber's screening):
    python mqtt_fake_sensors.py --scenario humidity_spike              # fires on round 3
    python mqtt_fake_sensors.py --scenario temp_jump --scenario-at 5   # fires on round 5
    python mqtt_fake_sensors.py --interactive                          # type a name + Enter to fire it live
    Scenarios: humidity_spike, temp_impossible (rejected) | temp_jump, water_jump (flagged) | flood (rate_limited)
    Fires are one-shot: the sim state is untouched, so the next round is normal again.
"""
import argparse
import json
import math
import queue
import random
import signal
import ssl
import sys
import threading
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

# ----------------------------------------------------------------- SCHEMA
TOPICS = {
    "water": ("sensors/water/node1", "node1"),
    "pir": ("sensors/pir/node2", "node2"),
    "temp": ("sensors/temp/node3", "node3"),
}


def envelope(kind, sim_time):
    return {
        "node_id": TOPICS[kind][1],
        "sensor": kind,
        "ts": datetime.fromtimestamp(sim_time, tz=timezone.utc).isoformat(timespec="seconds"),
    }


# ------------------------------------------------------------- SIMULATORS
class WaterSim:
    """Tank level: slow drain from usage, periodic pump refill, rare leak."""

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
        # leak: rare event, drains faster for a few minutes
        if t > self.leak_until and self.rng.random() < 0.0005 * dt:
            self.leak_until = t + self.rng.uniform(120, 400)
        leak = t < self.leak_until
        if leak:
            self.level -= 0.08 * dt
        self.level = max(0.0, min(self.TANK_CM, self.level))
        measured = self.level + self.rng.gauss(0, 0.15)  # sensor noise
        return {
            "level_cm": round(measured, 2),
            "level_pct": round(100 * measured / self.TANK_CM, 1),
            "leak": leak,
        }


class PirSim:
    """Motion arrives in bursts, more likely during waking hours, with hold time."""

    HOLD_S = 8.0

    def __init__(self, rng):
        self.rng = rng
        self.hold_until = 0.0

    def step(self, t, dt):
        hour = (t % 86400) / 3600
        awake = 7 <= hour <= 23
        p_start = (0.04 if awake else 0.003) * dt
        if self.rng.random() < p_start:
            self.hold_until = max(self.hold_until, t + self.HOLD_S * self.rng.uniform(0.7, 2.5))
        return {"motion": t < self.hold_until}


class TempSim:
    """Daily sinusoid (min ~05:00, max ~15:00) + drift + noise; humidity anti-correlated."""

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
        return {
            "temperature_c": round(temp, 2),
            "humidity_pct": round(max(10.0, min(100.0, hum)), 1),
        }


# -------------------------------------------------------------- SCENARIOS
# Bad-data scenarios for live demos. name -> (sensor kind, mutate(payload) -> payload, extra copies).
# The comment on each line is the tier screening.py should give it (thresholds: screening.py).
# Jump scenarios need a baseline reading first, hence --scenario-at defaults to round 3.
def _water_jump(p):
    pct = p["level_pct"]
    new = round(pct - 45 if pct >= 50 else pct + 45, 1)  # |delta| 45 > JUMP_LIMITS["level_pct"] 40
    return {**p, "level_pct": new, "level_cm": new}       # TANK_CM is 100, so cm == pct


FLOOD_COPIES = 30  # extra messages in one burst; subscriber default limit is 20 per node per 10 s

SCENARIOS = {
    "humidity_spike": ("temp", lambda p: {**p, "humidity_pct": 120.0}, 0),   # impossible -> rejected
    "temp_impossible": ("temp", lambda p: {**p, "temperature_c": 85.0}, 0),  # impossible -> rejected
    "temp_jump": ("temp", lambda p: {**p, "temperature_c": round(p["temperature_c"] + 20, 2)}, 0),  # unusual -> flagged
    "water_jump": ("water", _water_jump, 0),                                 # unusual -> flagged
    "flood": ("temp", lambda p: p, FLOOD_COPIES),                            # rate_limited
}


def watch_stdin(pending):
    """Demo trigger: type a scenario name + Enter; it fires on the next round."""
    for line in sys.stdin:
        name = line.strip().lower()
        if not name:
            continue
        if name in SCENARIOS:
            pending.put(name)
            print(f"[queued] {name}", file=sys.stderr)
        else:
            print(f"[unknown] {name!r}; choose from: {', '.join(sorted(SCENARIOS))}", file=sys.stderr)


# ------------------------------------------------------------------- MAIN
def make_client(args):
    try:  # paho-mqtt >= 2.0
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=args.client_id)
    except AttributeError:  # paho-mqtt 1.x
        client = mqtt.Client(client_id=args.client_id)
    if args.username:
        client.username_pw_set(args.username, args.password)
    if not args.no_tls:
        # same pattern as mqtt_subscriber.py's build_client(), kept in sync
        # deliberately: both sides of this pipeline should trust the broker
        # the same way
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.cafile)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if args.tls_insecure:
            ctx.check_hostname = False #chain is still verified against the CA
        client.tls_set_context(ctx)
    return client


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8883)
    ap.add_argument("--cafile", help="CA that signed the broker cert (required unless --no-tls)")
    ap.add_argument("--tls-insecure", action="store_true", help="skip hostname check (chain still verified)")
    ap.add_argument("--no-tls", action="store_true", help="plain MQTT, for local debugging only")
    ap.add_argument("--username")
    ap.add_argument("--password")
    ap.add_argument("--client-id", default="fake-sensor-harness")
    ap.add_argument("--interval", type=float, default=2.0, help="real seconds between publish rounds")
    ap.add_argument("--speed", type=float, default=1.0, help="simulated seconds per real second")
    ap.add_argument("--count", type=int, default=0, help="rounds to publish; 0 = run forever")
    ap.add_argument("--qos", type=int, default=1, choices=[0, 1, 2])
    ap.add_argument("--retain", action="store_true")
    ap.add_argument("--seed", type=int, help="seed RNG for reproducible runs")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--scenario", action="append", choices=sorted(SCENARIOS), metavar="NAME",
                    help="fire a bad-data scenario (repeatable): " + ", ".join(sorted(SCENARIOS)))
    ap.add_argument("--scenario-at", type=int, default=3, metavar="ROUND",
                    help="round (0-based) on which --scenario fires; rounds before it give the "
                         "subscriber a baseline for jump checks (default 3)")
    ap.add_argument("--interactive", action="store_true",
                    help="read scenario names from stdin while running (for live demos)")
    args = ap.parse_args()
    if args.scenario and args.count and args.scenario_at >= args.count:
        ap.error("--scenario-at must be smaller than --count, or the scenario never fires")

    rng = random.Random(args.seed)
    sims = {"water": WaterSim(rng), "pir": PirSim(rng), "temp": TempSim(rng)}

    client = make_client(args)
    client.connect(args.host, args.port, keepalive=30)
    client.loop_start()

    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    pending = queue.SimpleQueue()  # scenarios typed in --interactive mode
    if args.interactive:
        threading.Thread(target=watch_stdin, args=(pending,), daemon=True).start()
        print(f"interactive: type a scenario ({', '.join(sorted(SCENARIOS))}) + Enter", file=sys.stderr)

    sim_time = time.time()
    dt = args.interval * args.speed
    sent = 0
    while running and (args.count == 0 or sent < args.count):
        active = list(args.scenario or []) if sent == args.scenario_at else []
        while not pending.empty():
            active.append(pending.get_nowait())
        active = list(dict.fromkeys(active))  # each scenario at most once per round
        for name in active:
            print(f"[scenario] {name} fires on round {sent}", file=sys.stderr)

        for kind, sim in sims.items():
            payload = {**envelope(kind, sim_time), **sim.step(sim_time, dt)}
            copies = 1
            for name in active:
                target, mutate, extra = SCENARIOS[name]
                if target == kind:
                    payload = mutate(payload)
                    copies += extra
            topic = TOPICS[kind][0]
            for _ in range(copies):
                client.publish(topic, json.dumps(payload), qos=args.qos, retain=args.retain)
            if not args.quiet:
                print(f"{topic} {json.dumps(payload)}" + (f"  (x{copies})" if copies > 1 else ""))
        sent += 1
        sim_time += dt
        time.sleep(args.interval)

    client.loop_stop()
    client.disconnect()
    print(f"done: {sent} rounds published", file=sys.stderr)


if __name__ == "__main__":
    main()
