# Network Monitoring Platform

## Project Overview
Docker Compose-based network monitoring platform for diagnosing connectivity and bandwidth issues. Ingests syslog (CEF), NetFlow/IPFIX, and PCAP data from UniFi and other network devices.

## Architecture
- **Vector** - syslog + flow ingestion, CEF parsing, routing to backends
- **GoFlow2** - NetFlow/IPFIX/sFlow collector
- **Zeek** - PCAP protocol metadata extraction
- **ClickHouse** - flow analytics, device tracking, correlated events
- **Loki** - log aggregation (syslog, Zeek logs)
- **Grafana** - unified dashboards
- **Analyzer** - custom FastAPI service (UniFi API, enrichment, correlation, alerting)

## Running the Stack

```bash
# Phase 1 only (syslog + netflow + dashboards):
docker compose up -d

# Phase 1 + 2 (adds Zeek + analyzer):
docker compose -f docker-compose.yml -f docker-compose.phase2.yml up -d

# All phases (adds InfluxDB + ntopng + alerting):
docker compose -f docker-compose.yml -f docker-compose.phase2.yml -f docker-compose.phase3.yml up -d
```

## Key Ports
| Service | Port |
|---------|------|
| Grafana | 3000 |
| Syslog (UDP) | 514 |
| NetFlow (UDP) | 2055 |
| Analyzer API | 8080 |
| ClickHouse HTTP | 8123 |
| Loki | 3100 |
| InfluxDB | 8086 |
| ntopng | 3001 |
| Alertmanager | 9093 |

## Development Commands

```bash
# Run analyzer tests:
cd analyzer && ../.venv/bin/pytest tests/ -v

# Validate docker-compose:
docker compose config --quiet

# Send test data:
./scripts/test-syslog.sh
./scripts/test-netflow.sh

# Health check:
./scripts/verify.sh

# Query ClickHouse directly:
docker exec netmon-clickhouse clickhouse-client --query "SELECT count() FROM netmon.flows"
```

## Configuration
- `.env` - passwords, UniFi credentials, ports (NOT committed)
- `config/vector/` - ingestion pipeline configs
- `config/clickhouse/init-db.sql` - all table schemas
- `config/grafana/` - datasource provisioning and dashboard JSONs
- `config/alertmanager/` - alert routing rules

## Analyzer Service (`analyzer/`)
Custom Python FastAPI service with:
- `unifi/` - UniFi controller API client + periodic poller
- `enrichment/` - IP→device name, passive DNS, GeoIP
- `correlator/` - rule-based cross-source event correlation
- `alerts/` - anomaly detection + Alertmanager integration
- `api/` - REST endpoints for Grafana and external consumers
