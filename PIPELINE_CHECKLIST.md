# Run Onyx from sensor to dashboard (Windows PowerShell)

This runbook covers the local simulator path:

`mqtt_fake_sensors.py` → Mosquitto over TLS → `mqtt_subscriber.py` screening → MySQL → Flask dashboard.

The scanner is a separate optional step for populating device risk scores. Run commands from the repository folder in PowerShell unless a step says otherwise. Each PowerShell window has its own environment, so set `MYSQL_PASSWORD` in every window that needs it.

> **Local development only:** `docker-compose.yml` binds MQTT to `127.0.0.1`. The fake sensors on this same computer can connect; ESP32s or other computers on Wi-Fi cannot. Real hardware also needs a broker certificate valid for the host name/IP it uses, plus suitable broker authentication and access controls.

## 0. One-time setup

- Start Docker Desktop.
- Confirm `mosquitto.conf` and `certs\ca.crt`, `certs\server.crt`, `certs\server.key` exist. They are already present in this project. If you need to generate them, run `gen_certs.sh` from Git Bash or WSL in the repository folder.
- Install the Python packages if needed:

```powershell
python -m pip install paho-mqtt pymysql Flask
```

## 1. Start and check MySQL and Mosquitto

```powershell
docker compose up -d
docker compose ps
```

Wait until both services show `Up`. Check MySQL; enter the root password configured in `docker-compose.yml` when prompted:

```powershell
docker compose exec mysql mysqladmin ping -uroot -p
```

Verify the local broker's TLS certificate:

```powershell
python -c "import ssl,socket; c=ssl.create_default_context(cafile=r'certs\ca.crt'); s=c.wrap_socket(socket.create_connection(('localhost',8883),timeout=5),server_hostname='localhost'); print('TLS:',s.version()); s.close()"
```

It should print a TLS version. If the certificate check fails, stop and fix the certificate/broker setup before starting the clients.

## 2. Start the collector — PowerShell window A

Set the value to the MySQL `sensor` password configured in `docker-compose.yml`, then start the collector. `--init-schema` creates any missing tables.

```powershell
$env:MYSQL_PASSWORD = '<MySQL sensor password>'
python mqtt_subscriber.py --host localhost --cafile certs\ca.crt --mysql-user sensor --init-schema --stats-interval 5
```

Leave this window open. The collector should connect to MySQL and subscribe to `sensors/#` over TLS. It writes accepted and flagged readings to `readings`, and screening decisions to `audit_log`.

## 3. Publish sensor data — PowerShell window B

```powershell
python mqtt_fake_sensors.py --host localhost --cafile certs\ca.crt --interval 2
```

Leave it running. It should print three topics per round: `sensors/water/node1`, `sensors/pir/node2`, and `sensors/temp/node3`. In window A, `received` and `accepted` should increase; `rejected` and `dropped` should stay at zero for normal simulated readings.

## 4. Verify MySQL — PowerShell window C

These commands prompt for the MySQL `sensor` password:

```powershell
docker compose exec mysql mysql -u sensor -p sensors -e "SHOW TABLES;"
docker compose exec mysql mysql -u sensor -p sensors -e "SELECT sensor, COUNT(*) FROM readings GROUP BY sensor;"
docker compose exec mysql mysql -u sensor -p sensors -e "SELECT decision, COUNT(*) FROM audit_log GROUP BY decision;"
docker compose exec mysql mysql -u sensor -p sensors -e "SELECT node_id, sensor, ts, level_pct, motion, temperature_c, humidity_pct FROM readings ORDER BY id DESC LIMIT 6;"
```

Expect the `readings` table to contain `water`, `pir`, and `temp` rows, and `audit_log` to contain mostly `accepted` decisions. The schema also creates `device_risk` and `users`.

## 5. Start and verify the dashboard — PowerShell window D

The dashboard reads MySQL; it does not connect to MQTT directly. Set the same MySQL password in this window:

```powershell
$env:MYSQL_PASSWORD = '<MySQL sensor password>'
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) and log in with an account already created in the `users` table. If you have not created an account yet, stop here and run `python create_user.py <username> --role admin` in another PowerShell window with `MYSQL_PASSWORD` set. New readings should appear after the collector has inserted them.

## 6. Optional: verify screening scenarios

Keep the collector running. Stop only the fake sensors in window B with `Ctrl+C`, then restart them with one scenario at a time. The scenario fires on round 3 by default, after three baseline rounds:

```powershell
python mqtt_fake_sensors.py --host localhost --cafile certs\ca.crt --scenario humidity_spike
```

Expected outcomes:

| Scenario | Expected decision | Stored in `readings`? |
|---|---|---|
| `humidity_spike` (humidity 120) | rejected as outside `[0, 100]` | No |
| `temp_impossible` (85 °C) | rejected as impossible | No |
| `temp_jump` (+20 °C) | flagged on the jump and return | Yes |
| `water_jump` (±45%) | flagged on the jump and return | Yes |
| `flood` (30 extra messages) | later messages rate-limited | Only up to the per-node limit |

The rate limit is 20 messages per node per 10 seconds by default. The number accepted during a flood depends on how much that node has already sent in the current window.

## 7. Optional: write scanner risk scores

The sensor pipeline does not create risk scores. To populate the dashboard's risk view, create a JSON map from each **authorized, privately addressed** sensor host to its database node ID, for example:

```json
{"192.168.1.101": "node1"}
```

Then, in PowerShell with `MYSQL_PASSWORD` set, run a full scan for that mapped host:

```powershell
python auth_check.py --scan 192.168.1.101 --node-map .\node-map.json --write-db
```

Only scan devices you own or are authorized to test. The scanner requires `--node-map` with `--write-db`; it writes scores to `device_risk`, which the dashboard reads.

## 8. Stop cleanly

1. Stop the fake sensors in window B with `Ctrl+C`.
2. Stop the collector in window A with `Ctrl+C`. Wait for its `final:` line; for a clean run, `dropped=0` and `lost=0`.
3. Stop Flask in window D with `Ctrl+C`.
4. To stop the containers while keeping their data, run:

```powershell
docker compose stop
```

## Optional: database-only sample data

To populate sample rows without running the broker or fake sensors, set `MYSQL_PASSWORD` in PowerShell and run:

```powershell
python seed_data.py --init-schema
```

This tests the database/dashboard path, not MQTT or TLS.
