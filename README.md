# IoT Device Vulnerability Scanner

A first-year project that builds a small IoT sensor network and a companion vulnerability scanner to detect common security weaknesses in connected devices — inspired by real-world IoT threats such as the Mirai botnet and its modern variants.

##  Overview

The Internet of Things (IoT) has introduced billions of low-power, resource-constrained devices to the internet, many of which ship with weak default security configurations. This project simulates a small-scale IoT environment using sensor nodes and builds a scanner tool to identify and report common vulnerabilities present in such devices — the same classes of weaknesses that have historically been exploited by large-scale attacks like Mirai, Gayfemboy, and Aisuru.

This project has two main components:

1. **IoT Sensor Node Environment** — a set of networked sensor nodes simulating a realistic IoT deployment.
2. **Vulnerability Scanner** — a tool that scans the sensor network for known classes of vulnerabilities and generates a risk report.

##  Sensor Node Environment

The simulated IoT environment consists of three sensor nodes, each built on a microcontroller (e.g., ESP32/ESP8266/Arduino) with network connectivity:

| Node | Sensor | Purpose |
|---|---|---|
| Node 1 | Temperature & Humidity Sensor (e.g., DHT11/DHT22, BME280) | Environmental monitoring |
| Node 2 | PIR Motion Sensor (e.g., HC-SR501) | Motion/presence detection |
| Node 3 | Water Level Sensor | Liquid level monitoring |

Each node communicates over Wi-Fi using common IoT protocols (HTTP/MQTT), representing typical low-power, resource-constrained IoT devices — the same category of devices frequently targeted by real-world IoT attacks.

##  Vulnerability Scanner

The scanner probes the sensor network and identifies devices affected by the following vulnerability classes:

### 1. Open Ports
Detects network services exposed without proper restriction (e.g., open Telnet, HTTP admin panels, MQTT brokers) using port-scanning techniques. Increases attack surface even before authentication is considered.

### 2. Weak / Inadequate Authentication
Checks whether exposed services use default, hardcoded, or easily guessable credentials — the same weakness exploited by Mirai and its modern derivatives.

### 3. Denial of Service (DoS) Susceptibility
Evaluates how resilient a node is to resource exhaustion, given the limited processing/memory typical of low-power IoT hardware.

##  Risk Reporting

The scanner combines findings from each check into a per-device risk report. Vulnerabilities are not scored in isolation — for example, an open port paired with weak authentication is flagged as significantly higher risk than an open port with strong authentication, reflecting how vulnerabilities compound in practice.

##  Motivation

Despite being nearly a decade old, the vulnerability classes exploited by the original Mirai botnet (2016) — open ports, default/weak credentials, and resulting DoS capability — remain highly active today:

- **Mirai (2016):** Compromised ~600,000 IoT devices via open Telnet ports and hardcoded default credentials, powering some of the largest DDoS attacks recorded at the time.
- **Gayfemboy (2024–2025):** A Mirai-derived botnet still exploiting weak Telnet credentials alongside newer N-day/zero-day vulnerabilities, infecting 15,000+ devices daily.
- **Aisuru (2024–2025):** A "TurboMirai-class" Mirai derivative built from compromised routers and cameras, responsible for record-breaking DDoS attacks exceeding 20 Tbps.

These recent incidents demonstrate that the vulnerabilities this project targets remain relevant, real-world attack vectors — underscoring the continued need for accessible IoT vulnerability scanning tools, even in small-scale/educational deployments like this one.

##  References

- W. Trappe, R. Howard, and R. S. Moore, "Low-Energy Security: Limits and Opportunities in the Internet of Things," *IEEE Security & Privacy*, vol. 13, no. 1, pp. 14–21, 2015.
- OWASP, "OWASP IoT Security Testing Guide (ISTG)," first released March 2024. [Online]. Available: https://owasp.org/www-project-iot-security-testing-guide/
- FortiGuard Labs / Security Affairs, "The Return of 'Gayfemboy' Botnet Exploiting IoT Vulnerabilities Worldwide," 2025.
- Netscout ASERT, "Aisuru and Related TurboMirai Botnet DDoS Attack Mitigation and Suppression," October 2025.

##  Tech Stack

- **Sensor Nodes:** Arduino/ESP32, DHT11/DHT22, HC-SR501, Water Level Sensor
- **Communication:** Wi-Fi, MQTT/HTTP
- **Scanner:** Python (e.g., `nmap`, `socket`, `paho-mqtt`, `hmac`/`hashlib`)
- **Reporting:** Console/HTML/PDF report generation

##  Disclaimer

This project is developed strictly for **educational purposes** as part of a first-year academic project. The scanner is intended to be run only against the project's own sensor node environment or systems the user has explicit authorization to test. Do not use this tool against any network or device without permission.

## 👤 Developers
- Mahek Mehta 
- Nena Shah 
- Alluru Ruthvik Sai
- Sharry Goyal
