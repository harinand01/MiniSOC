# Mini SOC Platform 🛡️

A modular, real-time Cybersecurity Monitoring Platform (SOC) built with Django, Kafka, Redis, and a Rule-Based Detection Engine.

## 🏗️ Architecture
1. **Log Generator**: Simulates real-world traffic and attack patterns (Brute Force, Suspicious Logins).
2. **Kafka (Broker)**: Distributed message queue for high-throughput log streaming.
3. **Detection Engine**: 
   - **Rules Engine**: Fast, deterministic threat signature checks (Blacklisted IPs, Brute Force, Suspicious log attempts).
4. **Django Backend**: Processes logs, stores alerts in PostgreSQL, and serves the REST API.
5. **WebSocket Layer**: Pushes live alerts to the dashboard instantly via Django Channels.
6. **Dashboard UI**: Real-time visualization of system health and security events.

## 🚀 Quick Start (Docker)
The entire system is containerized. To start everything:

```bash
docker-compose up --build
```

This will launch:
- **Dashboard**: [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/)
- **Kafdrop (Kafka UI)**: [http://localhost:9000](http://localhost:9000)
- **Django Admin**: [http://localhost:8000/admin](http://localhost:8000/admin) (admin/admin)

## 🛠️ Manual Development Setup
If you want to run components individually:

### 1. Start Infrastructure
```bash
docker-compose up -d zookeeper kafka redis postgres
```

### 2. Backend Setup
```bash
cd soc-backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py run_consumer  # Terminal 1
python manage.py runserver     # Terminal 2
```

### 3. Log Generator
```bash
cd log-generator
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python generator.py
```

## 🧪 Testing
Run the detection module unit tests:
```bash
cd soc-backend
python logs/tests_ai.py
```
Or run the end-to-end analyzer script:
```bash
cd soc-backend
python test_analyzer.py
```

## 🛡️ Detection Rules
- **Brute Force Detection**: Verdict = `ATTACK` and Attack Type = `brute_force` if failed login attempts exceed 5.
- **Blacklisted IP Detection**: Verdict = `ATTACK` and Attack Type = `blacklisted_ip` if the IP address matches a known malicious list.
- **Suspicious Login**: Verdict = `SUSPICIOUS` if failed login attempts are between 3 and 5.
- **Normal Traffic**: Verdict = `NORMAL` for all other traffic.
