# Mini SOC Platform 

A real-time Security Operations Center (SOC) platform built with **Django, Kafka, Redis, PostgreSQL, and Docker**.

### Features

- Real-time security log monitoring
- Brute-force detection
- SQL injection detection
- Credential stuffing detection
- Suspicious login detection
- IP investigation
- Incident management
- Real-time dashboard and alerts

### Tech Stack

- **Backend:** Django, Django REST Framework
- **Messaging:** Apache Kafka
- **Database:** PostgreSQL
- **Cache:** Redis
- **Real-time:** Django Channels / WebSockets
- **Containerization:** Docker

### Run with Docker

```bash
docker compose up --build