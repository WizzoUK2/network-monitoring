# Network Monitoring Platform

A Docker Compose-based platform for diagnosing network connectivity and bandwidth issues. Aggregates and analyzes packet captures, NetFlow data, and syslog from UniFi devices and other network equipment.

## Features

- **Syslog ingestion** with CEF parsing (UniFi SIEM format)
- **NetFlow/IPFIX/sFlow** collection and analytics
- **PCAP analysis** via Zeek (protocol metadata extraction)
- **UniFi API integration** - device inventory, client tracking, signal monitoring
- **Data enrichment** - IP-to-device-name mapping, passive DNS, GeoIP
- **Correlation engine** - cross-source event detection (DNS failures, bandwidth spikes, poor WiFi, port scans)
- **Anomaly detection** - rolling baselines with automatic alerting
- **Pre-built Grafana dashboards** - Network Overview, Syslog Explorer, Client Health, DNS Analysis, Correlated Events

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your UniFi controller details and passwords

# 2. Start everything
./scripts/setup.sh

# 3. Open Grafana
# http://localhost:3000 (admin / changeme)
```

## Architecture

```
          UniFi Devices / Network Gear
          |           |           |
      Syslog      NetFlow      PCAP
     (UDP 514)  (UDP 2055)   (file)
          |           |           |
       Vector      GoFlow2      Zeek
          |           |           |
          v           v           v
        Loki     ClickHouse   ClickHouse
          \          |          /
           +--- Grafana ---+
                   |
            Python Analyzer
         (UniFi API, enrichment,
          correlation, alerting)
```

## Phased Deployment

The stack is split into three phases so you can start simple and add complexity as needed:

### Phase 1: Syslog + NetFlow + Dashboards
```bash
docker compose up -d
```
Services: Vector, GoFlow2, ClickHouse, Loki, Grafana

### Phase 2: PCAP Analysis + UniFi Integration
```bash
docker compose -f docker-compose.yml -f docker-compose.phase2.yml up -d
```
Adds: Zeek, Analyzer (FastAPI)

### Phase 3: Alerting + Real-Time Monitoring
```bash
docker compose -f docker-compose.yml -f docker-compose.phase2.yml -f docker-compose.phase3.yml up -d
```
Adds: InfluxDB, ntopng, Alertmanager

## UniFi Configuration

1. **Syslog**: Settings > Control Plane > Integrations > SIEM Server > set to `<server-ip>:514` (UDP)
2. **NetFlow**: Settings > System > Traffic Logging > Enable NetFlow/IPFIX > collector: `<server-ip>:2055`
3. **API access**: Create a local-only admin account on your UniFi controller and add credentials to `.env`

## Dashboards

| Dashboard | Description |
|-----------|-------------|
| Network Overview | Bandwidth trends, top talkers, protocol distribution, flow table |
| Syslog Explorer | Log search, event rates by severity/source, firewall events |
| Client Health | WiFi signal tracking, client counts, device inventory, experience scores |
| DNS Analysis | Query rates, failure codes, top domains, per-client DNS health |
| Correlated Events | Detection events, severity distribution, affected IPs |

## Analyzer API

The analyzer service exposes REST endpoints at `http://localhost:8080`:

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Service health check |
| `GET /api/unifi/devices` | List UniFi infrastructure devices |
| `GET /api/unifi/clients` | List active network clients |
| `GET /api/enrichment/device/{ip}` | Look up device name by IP |
| `GET /api/enrichment/dns/{ip}` | Look up hostname from passive DNS |
| `GET /api/enrichment/geoip/{ip}` | GeoIP lookup |
| `GET /api/top-talkers?minutes=60` | Enriched top talkers |
| `GET /api/correlated-events?hours=24` | Recent correlation events |
| `GET /api/stats/summary` | System-wide statistics |
| `POST /api/alerts/test` | Fire a test alert |

## Correlation Rules

Built-in detection rules focused on connectivity and bandwidth diagnostics:

| Rule | Detects | Severity |
|------|---------|----------|
| `dns_failure_burst` | High DNS failure rate from a device | 7 |
| `bandwidth_spike` | Single device exceeding 100MB/5min | 5 |
| `client_wifi_poor_signal` | WiFi clients with signal < -75 dBm | 4 |
| `connection_flood` | Excessive new connections (>1000/5min) | 6 |
| `port_scan_detection` | Device hitting >50 distinct ports | 6 |
| `new_device_detected` | Unknown IP on the network | 3 |
| `high_retransmit_flow` | TCP flows with retransmission indicators | 5 |
| `external_data_exfil` | >500MB to a single external IP/hour | 7 |

## Testing

```bash
# Send test syslog data
./scripts/test-syslog.sh

# Generate test NetFlow data (requires Docker)
./scripts/test-netflow.sh

# Health check all services
./scripts/verify.sh

# Run analyzer unit tests
cd analyzer && ../.venv/bin/pytest tests/ -v
```
