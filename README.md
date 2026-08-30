# Mini SOC Platform 🛡️

A modular, real-time Cybersecurity Monitoring Platform (SOC) built with Django, Kafka, Redis, PostgreSQL, and a Rule-Based Detection Engine.

## 🏗️ Architecture

1. **Log Generator**: Simulates real-world traffic and attack patterns (Brute Force, Suspicious Logins, SQL Injection, Credential Stuffing).
2. **Kafka (Broker)**: Distributed message queue for high-throughput log streaming.
3. **Detection Engine**: 
   - **Rules Engine**: Fast, deterministic threat signature checks (Blacklisted IPs, Brute Force, Suspicious logins, SQL Injection).
4. **Django Backend**: Ingests logs, processes threats, stores alerts in PostgreSQL, and serves the REST API.
5. **WebSocket Layer**: Pushes live alerts and incident updates to the dashboard in real time via Django Channels.
6. **Dashboard UI**: Interactive visualization of security events, metrics, IP investigation, incident response, and executive reports.

## 🚀 Quick Start (Docker)

The entire system is containerized. To start everything:

```bash
docker compose up --build
```

This will launch:
- **Dashboard**: [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/)
- **Kafdrop (Kafka UI)**: [http://localhost:9000](http://localhost:9000)
- **Django Admin**: [http://localhost:8000/admin](http://localhost:8000/admin)

### Creating an Admin User
To access the Django Admin panel, create a superuser:
```bash
docker compose exec soc-backend python manage.py createsuperuser
```

## 🛠️ Manual Development Setup

If you want to run components individually without full containerization:

### 1. Start Infrastructure
```bash
docker compose up -d zookeeper kafka redis postgres
```

### 2. Backend Setup
```bash
cd soc-backend
python -m venv venv

# Linux/macOS:
source venv/bin/activate
# Windows (PowerShell):
# .\venv\Scripts\Activate.ps1

pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py run_consumer  # Terminal 1 (Kafka Consumer)
python manage.py runserver     # Terminal 2 (Django Web & Channels)
```

### 3. Log Generator
```bash
cd log-generator
python -m venv venv

# Linux/macOS:
source venv/bin/activate
# Windows (PowerShell):
# .\venv\Scripts\Activate.ps1

pip install -r requirements.txt
python generator.py
```

## 🧪 Testing

Run the test suites:
```bash
cd soc-backend
python manage.py test
```

Or run the rule engine standalone verification:
```bash
cd soc-backend
python test_analyzer.py
```

## 🛡️ Detection Rules

- **Brute Force Detection**: Flags repeated authentication failures against a target IP exceeding configured thresholds.
- **Blacklisted IP Detection**: Identifies traffic originating from known malicious or high-risk IP addresses.
- **Suspicious Login Detection**: Alerts when anomalous failed attempt patterns or rate anomalies are observed.
- **SQL Injection / Web Attacks**: Detects common malicious patterns in request payloads and query strings.
- **Normal Traffic**: Baseline events categorized and indexed for telemetry without triggering alerts.
