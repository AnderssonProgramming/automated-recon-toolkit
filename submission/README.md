---
Title: "Technical Installation: Security Automation and Tool Integration"
Project: Lab 15 - Automation
Subject: IT Security and Privacy
Professor: Daniel Esteban Vela López
Author: Andersson David Sánchez Méndez & Cristian Santiago Pedraza Rodríguez
Date: 2026-05-12
Location: Bogotá, Colombia
Confidentiality: Internal / Academic Use Only
---

# TECHNICAL INSTALLATION: SECURITY AUTOMATION AND SCRIPTING

<div align="center">
  <img src="https://upload.wikimedia.org/wikipedia/commons/9/91/Logo_de_la_Escuela_Colombiana_de_Ingenier%C3%ADa_-_Universidad.webp" width="250">
  <br>
  <strong>Escuela Colombiana de Ingeniería Julio Garavito</strong>
  <br>
  <br>
  <strong>Project:</strong> Lab 15 - Automation <br> 
  <strong>Subject:</strong> IT Security and Privacy <br> 
  <strong>Professor:</strong> Daniel Esteban Vela López <br> 
  <strong>Authors:</strong> Andersson David Sánchez Méndez & Cristian Santiago Pedraza Rodríguez <br> 
  <strong>Date:</strong> 2026-05-12 <br> 
  <strong>Location:</strong> Bogotá, Colombia <br><br> 
  <strong>Confidentiality:</strong> Internal / Academic Use Only
</div>

---

## 1. Environment & Setup Instructions

Per the laboratory requirements, this suite of security tools is designed to run natively on Kali Linux with minimal external dependencies to maintain Operational Security (OPSEC) and ensure portability.

* **Python Version required:** Python 3.10+
* **System Binaries required:** `nmap`, `whois`, `dig`, `curl`, `ssh-keyscan`

<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>

### Dependencies
All core scripts utilize the Python Standard Library (`asyncio`, `argparse`, `xml.etree.ElementTree`, `subprocess`, `re`, `statistics`, `logging`). Therefore, **no external pip installation is required** for the required deliverables. 

*(Note: If extending the tool to use the passive Shodan/VirusTotal APIs discussed in the theory section, you would run: `pip install shodan requests python-dotenv`)*.

---

## 2. Script Documentation & Design Choices

Below is the execution guide and architectural justification for the scripts included in the `submission/` directory.

### Part 1: `scanner.py` (Concurrent Port Scanner)
* **Usage Example:** `python3 scanner.py 127.0.0.1 -p 1-1024 --rate 200 -o scan_results.json`
* **Purpose:** A high-speed TCP connect scanner.
* **Design Choices:** We chose `asyncio` with `asyncio.Semaphore` over `ThreadPoolExecutor`. Network scanning is heavily I/O-bound (waiting for TCP handshakes). `asyncio` allows a single thread to multiplex thousands of sockets, reducing OS memory overhead, while the semaphore caps concurrency to prevent self-imposed DoS or triggering basic IDS signatures.

### Part 2: `parse_scan.py` (Nmap XML Parser & Enricher)
* **Usage Example:** `python3 parse_scan.py --input scan.xml --output hosts.json`
* **Purpose:** Parses Nmap's `-oX` XML output and dynamically enriches SSH findings.
* **Design Choices:** We used the built-in `xml.etree.ElementTree` to avoid third-party dependencies. For enrichment, we utilized `subprocess` to trigger `ssh-keyscan` against hosts with port 22 open. Crucially, we included a `timeout=5` parameter to ensure the pipeline fails gracefully and independently if the target firewall drops the packets.

<br>
<br>
<br>
<br>

### Part 3: `auth_analysis.py` & `log_analysis.py` (Anomaly Detection)
* **Usage Example:** `python3 auth_analysis.py` && `python3 log_analysis.py`
* **Purpose:** Ingests server logs to identify brute-force targets, attack signatures, and statistical anomalies.
* **Design Choices:** We designed these scripts to process multi-gigabyte logs without loading them entirely into memory by using generator expressions (`for line in f:`). We implemented the **3-Sigma Rule** using Python's `statistics` module to dynamically detect anomalies based on actual traffic baselines, adapting to environments without hardcoded thresholds.

### Part 4: `recon.py` (Integrated Reconnaissance Tool)
* **Usage Example:** `python3 recon.py google.com --mode domain --output ./sample_output`
* **Purpose:** A comprehensive CLI tool orchestrating `nmap`, `whois`, `dig`, and `curl`.
* **Design Choices:** * **Audit Logging:** Every `subprocess.run()` is wrapped in logic that outputs to `audit.log`, a non-negotiable OPSEC requirement for tracing actions during pentests.
    * **Independent Failures:** Used granular `try/except` blocks. If `whois` is rate-limited, the script catches the error and proceeds to `dig` without crashing.

---

## 3. Laboratory Execution Evidence & Telemetry

### Phase 1: High-Speed Concurrency Execution
Execution of the `asyncio` scanner against the loopback interface demonstrated extreme efficiency, completing 1,024 ports in 0.02s while adhering to a 200-connection rate limit.
![Async Scanner Execution](async-scanner.png)
![Scan Results JSON](scan-results-json.png)

<br>
<br>
<br>
<br>
<br>
<br>
<br>
<br>

### Phase 2: Structured Nmap Parsing
The parser successfully read `scan.xml` and enriched Port 22 with cryptographic key data (`ssh-ed25519`) using external subprocesses.
![Parse Scan Execution](parse-scan-execution.png)
![Hosts JSON Enriched](hosts-json-enriched.png)

<br>
<br>
<br>
<br>

### Phase 3: Log Mining & 3-Sigma Anomaly Detection
The scripts identified a severe brute-force campaign from `185.220.101.5`, detected specific SQLi/LFI requests, and flagged `Hour 03` as a 3-Sigma anomaly (Z=3.1σ).
![Auth Analysis Log](auth-analysis-log.png)
![Log Analysis Output](log-analysis-output.png)

<br>
<br>
<br>
<br>

### Phase 4: Integrated Recon Tool
The final orchestration successfully gathered active/passive intel, maintained an audit trail, and did not crash despite any isolated tool failures.
![Recon Script Execution](recon-py-execution.png)
![Recon Audit Log](recon-audit-log.png)

---

<br>
<br>
<br>

## 4. Analytical Questions

### Q1: False Negatives at High Concurrency
**Question:** *At very high concurrency (e.g. `--rate 2000`), you may observe false negatives. Explain the mechanism behind this.*
**Answer:** High concurrency overwhelms local and remote resources. Locally, the OS may exhaust file descriptor limits (`ulimit`). On the network side, routers, firewalls, or the target's TCP listen backlog may drop packets due to state table exhaustion. Because asynchronous scanners rely on timeouts, a dropped packet is interpreted as a firewall timeout. Therefore, "the scanner did not detect it" implies a failure to complete the handshake in time, not definitively that the port is closed.

### Q2: The Value of Service Version Detection
**Question:** *Why is the service version string valuable intelligence? What is the difference between `Apache 2.4.54` and no string at all?*
**Answer:** A specific version string allows an attacker to map the service directly to known exploits (CVEs). A server returning no version string forces the attacker into "blind" exploitation—guessing memory offsets and vulnerable endpoints. This brute-force fuzzing significantly increases network noise, raising the probability of IDS detection and IP blocking.

### Q3: The 3-Sigma Rule & Periodicity
**Question:** *How does daily periodicity affect a single global baseline in 3-sigma detection? Describe a modified approach.*
**Answer:** A global baseline averages out daily peaks and troughs. Thus, normal mid-day traffic might trigger a false positive, while a dangerous 3:00 AM brute-force attack might be missed because total volume stays below the daytime average. **Modified Approach:** Implement a *time-bucketed baseline*. Compare current traffic at 3:00 AM Tuesday only to the historical mean and standard deviation of previous Tuesdays at 3:00 AM.

### Q4: Active vs. Passive Reconnaissance
**Question:** *What are the operational differences? Which is harder to detect? Scenarios?*
**Answer:** * **Differences:** Active recon (Nmap) sends packets directly to the target. Passive recon (Shodan) queries a third-party database without touching the target.
* **Detection:** Passive recon is virtually undetectable by the target. Active recon triggers firewalls and IDS alerts.
* **Scenarios:** Passive recon is ideal for initial OSINT and stealthy footprinting. Active recon is mandatory for internal network testing or discovering dynamic services not yet indexed by search engines.

--- 