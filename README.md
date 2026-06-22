# network-observability

> Renamed from **network-monitoring** (2026-06) to fit the `network-*` tooling family and
> make its role explicit: **network-observability** is the *passive* monitoring layer
> (flows/logs/metrics/dashboards/alerts), alongside **network-inventory** (declarative
> source-of-truth: device config/inventory → NetBox + git; formerly `wicked-collector`) and
> **network-probe** (active on-demand probing). GitHub redirects the old URL.

A self-hosted, Docker Compose-based platform for diagnosing network connectivity and bandwidth issues. Aggregates and correlates syslog, NetFlow/IPFIX, and packet capture data from UniFi devices and other network equipment, with built-in anomaly detection and enrichment.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Phased Deployment](#phased-deployment)
- [UniFi Configuration](#unifi-configuration)
- [Dashboards](#dashboards)
- [Analyzer API](#analyzer-api)
- [Correlation Rules](#correlation-rules)
- [Anomaly Detection](#anomaly-detection)
- [Testing](#testing)
- [Documentation](#documentation)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [License](#license)

## Features

**Data Collection**
- Syslog ingestion with Common Event Format (CEF) parsing for UniFi SIEM integration
- NetFlow v5/v9, IPFIX, and sFlow collection via GoFlow2
- PCAP analysis via Zeek for protocol-level metadata (DNS, HTTP, SSL, connection tracking)

**Intelligence**
- UniFi Controller API integration for device inventory and client tracking
- IP-to-device-name enrichment (turns `192.168.1.100` into `Craig's iPhone`)
- Passive DNS resolution from Zeek logs (IP-to-hostname without active lookups)
- GeoIP lookups via MaxMind GeoLite2 for external IP geolocation
- Cross-source event correlation with 8 built-in detection rules
- Anomaly detection with rolling 7-day baselines and automatic alerting

**Visualization**
- 5 pre-built Grafana dashboards covering network overview, syslog, client health, DNS, and events
- Real-time traffic visibility via ntopng (Phase 3)
- High-resolution metrics via InfluxDB with sub-5-second Grafana refresh (Phase 3)

**Operations**
- Phased deployment: start simple with Phase 1 and grow incrementally
- Fully containerized with Docker Compose
- Automated data retention with per-table TTL policies
- Alert routing via Alertmanager with Slack, webhook, and email support

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    NETWORK DEVICES                           │
│  UniFi APs, Switches, Gateways  │  Other Routers, Servers   │
└──────────┬──────────┬────────────┴──────────┬────────────────┘
           │          │                       │
       Syslog     NetFlow/IPFIX            PCAP files
      (UDP 514)   (UDP 2055)              (data/pcaps/)
           │          │                       │
           ▼          ▼                       ▼
┌──────────────┐ ┌──────────┐          ┌──────────┐
│    Vector    │ │ GoFlow2  │          │   Zeek   │
│  CEF parsing │ │ flow     │          │ protocol │
│  + routing   │ │ collector│          │ metadata │
└──────┬───┬───┘ └────┬─────┘          └────┬─────┘
       │   │          │                     │
       │   │    ┌─────▼──────────────────┐  │
       │   │    │      ClickHouse        │◄─┘
       │   │    │  flows, zeek_conn/dns, │
       │   │    │  unifi_clients/devices,│
       │   │    │  correlated_events     │
       │   │    └─────────┬──────────────┘
       │   │              │
       │   ▼              │
       │ ┌──────┐         │
       │ │ Loki │         │
       │ │ logs │         │
       │ └──┬───┘         │
       │    │             │
       │    ▼             ▼
       │  ┌─────────────────┐    ┌─────────────┐
       │  │     Grafana     │    │  Analyzer   │
       │  │  5 dashboards   │◄──►│  (FastAPI)  │
       │  └─────────────────┘    └──────┬──────┘
       │                                │
       │         ┌──────────────────────┼──────────────┐
       │         │                      │              │
       │         ▼                      ▼              ▼
       │  ┌─────────────┐    ┌────────────────┐ ┌───────────┐
       │  │ UniFi API   │    │  Enrichment    │ │ Alerting  │
       │  │ device poll │    │ device/dns/geo │ │ anomalies │
       │  └─────────────┘    └────────────────┘ └───────────┘
       │
       │  Phase 3 additions:
       ▼
┌────────────┐  ┌────────────┐  ┌──────────────┐
│  InfluxDB  │  │  ntopng    │  │ Alertmanager │
│  metrics   │  │  real-time │  │ routing      │
└────────────┘  └────────────┘  └──────────────┘
```

### Data Flow Summary

| Source | Collector | Storage | Visualization |
|--------|-----------|---------|---------------|
| Syslog (CEF) | Vector | Loki | Grafana (Syslog Explorer) |
| NetFlow/IPFIX | GoFlow2 → Vector | ClickHouse `flows` | Grafana (Network Overview) |
| PCAP files | Zeek → Vector | ClickHouse `zeek_conn`, `zeek_dns` | Grafana (DNS Analysis) |
| UniFi API | Analyzer poller | ClickHouse `unifi_clients`, `unifi_devices` | Grafana (Client Health) |
| Correlation | Analyzer engine | ClickHouse `correlated_events` | Grafana (Correlated Events) |

## Quick Start

### Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A server with at least 4 GB RAM (8+ GB recommended for all phases)
- Network access to your UniFi controller (for Phase 2+)

### 1. Clone and Configure

```bash
git clone https://github.com/WizzoUK2/network-monitoring.git
cd network-monitoring
cp .env.example .env
```

Edit `.env` with your settings:

```bash
# Required: set secure passwords
CLICKHOUSE_PASSWORD=your-secure-password
GRAFANA_ADMIN_PASSWORD=your-grafana-password

# Phase 2: UniFi controller access
UNIFI_HOST=https://192.168.1.1
UNIFI_USERNAME=admin
UNIFI_PASSWORD=your-unifi-password
```

### 2. Start the Stack

```bash
./scripts/setup.sh
```

This pulls all Docker images, starts the services, and runs a health check.

### 3. Verify and Access

```bash
./scripts/verify.sh
```

Open Grafana at **http://localhost:3000** (default login: `admin` / your configured password).

### 4. Point Your Devices

Configure your UniFi controller to send data (see [UniFi Configuration](#unifi-configuration) below), or generate test data:

```bash
./scripts/test-syslog.sh    # Send synthetic CEF syslog messages
./scripts/test-netflow.sh   # Generate synthetic NetFlow data
```

## Phased Deployment

The stack is split into three phases. Start with Phase 1 and add phases as needed.

### Phase 1: Syslog + NetFlow + Dashboards

The foundation. Gets data flowing from your network into storage with basic dashboards.

```bash
docker compose up -d
```

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| Vector | timberio/vector | UDP 514, 8686 | Syslog collection, CEF parsing, routing |
| GoFlow2 | netsampler/goflow2 | UDP 2055, 6343 | NetFlow/IPFIX/sFlow collection |
| ClickHouse | clickhouse-server:24 | 8123, 9000 | Flow analytics, structured data |
| Loki | grafana/loki:3 | 3100 | Log aggregation |
| Grafana | grafana-oss:11 | 3000 | Dashboards and exploration |

**Resource usage:** ~1.5 GB RAM

### Phase 2: PCAP Analysis + UniFi Integration

Adds deep packet analysis and the custom analyzer service for enrichment and correlation.

```bash
docker compose -f docker-compose.yml -f docker-compose.phase2.yml up -d
```

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| Zeek | zeek/zeek | - | PCAP protocol metadata extraction |
| Analyzer | custom (FastAPI) | 8080 | UniFi API, enrichment, correlation |

**Additional resource usage:** ~1 GB RAM

### Phase 3: Alerting + Real-Time Monitoring

Adds high-resolution metrics, real-time traffic visibility, and automated alerting.

```bash
docker compose -f docker-compose.yml -f docker-compose.phase2.yml -f docker-compose.phase3.yml up -d
```

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| InfluxDB | influxdb:2 | 8086 | High-resolution time-series metrics |
| ntopng | ntop/ntopng | 3001 | Real-time traffic visibility |
| Alertmanager | prom/alertmanager | 9093 | Alert routing and deduplication |

**Additional resource usage:** ~2 GB RAM

### Stopping the Stack

```bash
# Phase 1 only:
docker compose down

# All phases:
docker compose -f docker-compose.yml -f docker-compose.phase2.yml -f docker-compose.phase3.yml down

# Remove all data volumes (destructive):
docker compose down -v
```

## UniFi Configuration

### Syslog Export

1. Open your UniFi Network controller
2. Navigate to **Settings > Control Plane > Integrations**
3. Under **Activity Logging (Syslog)**, enable **SIEM Server**
4. Set the server address to your monitoring server's IP and port `514` (UDP)
5. Requires UniFi Network Application **7.3.76 or later**

Logs are exported in **Common Event Format (CEF)**, which Vector parses automatically.

### NetFlow/IPFIX Export

1. Navigate to **Settings > System > Traffic Logging**
2. Enable **NetFlow (IPFIX)**
3. Set the collector address to your monitoring server's IP and port `2055`
4. Select which VLANs/networks to monitor

**Note:** NetFlow support varies by device. UDM Pro/SE support it natively. USG requires CLI configuration:

```bash
set system flow-accounting interface eth0
set system flow-accounting netflow server <collector-ip> port 2055
set system flow-accounting netflow version 9
commit
```

### API Access (Phase 2+)

1. In your UniFi controller, create a **local-only admin account** (not a UI.com account)
2. Add the credentials to your `.env` file:

```bash
UNIFI_HOST=https://192.168.1.1     # Your controller IP
UNIFI_USERNAME=netmon-readonly      # The local admin username
UNIFI_PASSWORD=your-password        # The local admin password
UNIFI_SITE=default                  # Site name (usually "default")
UNIFI_VERIFY_SSL=false              # Set true if using valid SSL certs
```

The analyzer authenticates via cookie-based sessions and supports both legacy and UniFi OS auth endpoints.

### Packet Capture (Phase 2+)

Place `.pcap` or `.pcapng` files in the `data/pcaps/` directory. Zeek automatically detects and processes new files every 10 seconds, extracting protocol metadata (connections, DNS queries, HTTP requests, SSL certificates, etc.).

For continuous capture from a mirror/SPAN port:

```bash
# Example: capture on interface eth1 (mirror port), rotate every 100MB
tcpdump -i eth1 -w data/pcaps/capture-%Y%m%d-%H%M%S.pcap -C 100 -z gzip
```

## Dashboards

All dashboards are auto-provisioned when Grafana starts. No manual import needed.

### Network Overview (`/d/netmon-overview`)

The primary operational dashboard showing bandwidth and flow patterns across your network.

**Panels:**
- Total bandwidth over time (5-minute buckets)
- Flow count trending
- Top 10 source talkers by bytes
- Top 10 destination talkers by bytes
- Top conversations table (src → dst with protocol and port)
- Protocol distribution pie chart (TCP/UDP/ICMP)
- Top destination ports
- Recent syslog events stream

### Syslog Explorer (`/d/netmon-syslog`)

Full-text log exploration with structured field filtering.

**Panels:**
- Syslog event rate by severity (stacked bars)
- Events by source device (pie chart)
- Events by severity (stat panels)
- Events by product type
- Filtered CEF event log viewer
- Firewall event log viewer

**Variables:** Filter by source type (`unifi_cef`, `syslog_plain`)

### Client Health & Devices (`/d/netmon-clients`)

UniFi device and client monitoring. Requires Phase 2.

**Panels:**
- Active client count over time
- WiFi vs wired client distribution
- Average WiFi experience score gauge
- WiFi signal strength distribution (avg/min/max over time)
- Clients with poor signal table (< -75 dBm)
- All active clients table (name, IP, MAC, network, signal, channel, bandwidth)
- Infrastructure device status table (APs, switches, gateways with CPU, memory, client count)

### DNS Analysis (`/d/netmon-dns`)

DNS health monitoring. Requires Phase 2 (Zeek processing PCAPs).

**Panels:**
- DNS query rate over time (queries vs failures)
- DNS success rate gauge
- Top queried domains
- DNS failure codes breakdown (NXDOMAIN, SERVFAIL, etc.)
- DNS servers used
- Top clients by DNS query volume (with failure percentages)
- Failed DNS queries detail table

### Correlated Events & Alerts (`/d/netmon-events`)

Events generated by the correlation engine and anomaly detector.

**Panels:**
- Events by severity (stat: Critical, Warning, Info)
- Event rate over time by rule name
- Events by rule type (bar chart)
- Top affected IPs
- Severity distribution
- Full event detail table with color-coded severity

## Analyzer API

The analyzer service (Phase 2+) exposes a REST API at `http://localhost:8080`. Full OpenAPI documentation is auto-generated at `http://localhost:8080/docs`.

### Endpoints

#### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Service health check |
| `GET` | `/api/stats/summary` | System-wide statistics (flow counts, unique IPs, known devices) |

#### UniFi Data

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/unifi/devices` | List all adopted infrastructure devices (APs, switches, gateways) |
| `GET` | `/api/unifi/clients` | List all currently connected clients |
| `GET` | `/api/unifi/health` | Site health summary (WAN, LAN, WLAN subsystems) |

#### Enrichment

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/enrichment/device/{ip}` | Look up device name, MAC, network by IP address |
| `GET` | `/api/enrichment/dns/{ip}` | Look up hostname from passive DNS cache |
| `GET` | `/api/enrichment/geoip/{ip}` | GeoIP lookup (country, city, ASN, coordinates) |

#### Analytics

| Method | Endpoint | Parameters | Description |
|--------|----------|------------|-------------|
| `GET` | `/api/top-talkers` | `minutes` (default: 60), `limit` (default: 20) | Top talkers enriched with device names |
| `GET` | `/api/correlated-events` | `hours` (default: 24), `limit` (default: 50) | Recent correlated events |

#### Alerting

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/alerts/test` | Fire a test alert through the full pipeline |

### Example Responses

```bash
# Device enrichment
$ curl http://localhost:8080/api/enrichment/device/192.168.1.100
{
  "ip": "192.168.1.100",
  "name": "Craig's iPhone",
  "mac": "aa:bb:cc:dd:ee:ff",
  "network": "LAN",
  "is_wired": false,
  "is_infrastructure": false
}

# System summary
$ curl http://localhost:8080/api/stats/summary
{
  "flows_total": 142853,
  "flows_bytes_24h": 8573921024,
  "unique_sources_24h": 47,
  "unique_dests_24h": 1283,
  "events_24h": 12,
  "known_devices": 23,
  "dns_cache_size": 4521
}
```

## Correlation Rules

The correlation engine runs every 5 minutes, executing SQL-based rules against ClickHouse. Rules are focused on diagnosing connectivity and bandwidth issues.

| Rule | What It Detects | Severity | Window |
|------|----------------|----------|--------|
| `dns_failure_burst` | Device with >50% DNS failure rate and >20 failed queries | 7 | 10 min |
| `bandwidth_spike` | Single source exceeding 100 MB in a 5-minute window | 5 | 5 min |
| `client_wifi_poor_signal` | WiFi clients averaging signal below -75 dBm | 4 | 30 min |
| `connection_flood` | Device opening >1,000 connections in 5 minutes | 6 | 5 min |
| `port_scan_detection` | Device contacting >50 distinct destination ports | 6 | 5 min |
| `new_device_detected` | Internal IP in flows with no matching UniFi client record | 3 | 15 min |
| `high_retransmit_flow` | TCP flows with indicators of retransmission (low bytes/packet ratio) | 5 | 15 min |
| `external_data_exfil` | >500 MB transferred to a single external IP | 7 | 60 min |

### Severity Scale

| Level | Range | Meaning |
|-------|-------|---------|
| Info | 1-4 | Informational, no immediate action needed |
| Warning | 5-7 | Potential issue, investigate when convenient |
| Critical | 8-10 | Likely active problem, investigate promptly |

## Anomaly Detection

The anomaly detector (Phase 3, enabled via `ANOMALY_DETECTION_ENABLED=true`) runs alongside the correlation engine and compares current network behavior against rolling 7-day baselines.

| Check | What It Detects | Method |
|-------|----------------|--------|
| `bandwidth_anomaly` | Device using significantly more bandwidth than its baseline | Z-score > 3 standard deviations |
| `new_external_destinations` | Internal device contacting 5+ external IPs not seen in 7 days | Set difference over time |
| `device_disappeared` | Previously active device not seen in 30+ minutes | Last-seen gap detection |
| `dns_failure_rate` | Device with >30% DNS failure rate over 15 minutes | Threshold on failure ratio |
| `wifi_signal_degraded` | WiFi client signal dropped >10 dBm below its 7-day average | Baseline comparison |

Detected anomalies are:
1. Written to the `correlated_events` ClickHouse table (visible in the Events dashboard)
2. Pushed to Alertmanager for routing to Slack, email, or webhooks

## Testing

### Test Data Generation

```bash
# Send 6 synthetic CEF syslog messages (firewall events, client events, DHCP, IPS)
./scripts/test-syslog.sh

# Generate synthetic NetFlow v5 data for 30 seconds
./scripts/test-netflow.sh

# Generate for a custom duration
./scripts/test-netflow.sh localhost 2055 120
```

### Health Checks

```bash
# Check all services, endpoints, and data presence
./scripts/verify.sh
```

The verify script checks:
- All Docker containers are running
- Vector API is responsive
- Loki is ready and queryable
- ClickHouse is accessible and the schema is initialized
- Grafana is healthy
- Flow data exists in ClickHouse
- Syslog data exists in Loki

### Unit Tests

```bash
cd analyzer
../.venv/bin/pytest tests/ -v
```

Tests cover:
- Device enrichment cache (update, IP lookup, MAC lookup)
- Passive DNS parsing (Zeek JSON format, incremental reads)
- GeoIP handling (private IPs, missing database)
- Correlation rules (required fields, window placeholders, uniqueness, formatting)

## Documentation

Detailed documentation is available in the [`docs/`](docs/) directory:

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/installation.md) | Step-by-step setup instructions and prerequisites |
| [Configuration Reference](docs/configuration.md) | All environment variables, config files, and tuning options |
| [Architecture](docs/architecture.md) | Component deep-dive, data flow, storage design |
| [UniFi Setup](docs/unifi-setup.md) | Detailed UniFi controller configuration for syslog, NetFlow, and API |
| [Dashboards Guide](docs/dashboards.md) | Dashboard descriptions, key queries, and customization |
| [API Reference](docs/api-reference.md) | Full REST API documentation with examples |
| [Development Guide](docs/development.md) | Adding rules, extending the analyzer, running tests |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and their solutions |

## Project Structure

```
network-monitoring/
├── docker-compose.yml              # Phase 1: core stack (5 services)
├── docker-compose.phase2.yml       # Phase 2: +Zeek, +Analyzer
├── docker-compose.phase3.yml       # Phase 3: +InfluxDB, +ntopng, +Alertmanager
├── .env.example                    # Environment variable template
├── config/
│   ├── vector/
│   │   ├── vector.yaml             # Syslog + GoFlow2 ingestion pipeline
│   │   ├── vector-phase2.yaml      # Zeek log ingestion
│   │   └── vector-phase3.yaml      # InfluxDB metrics sink
│   ├── clickhouse/
│   │   ├── init-db.sql             # All table schemas (10 tables, 2 materialized views)
│   │   └── users.xml               # Authentication config
│   ├── loki/
│   │   └── loki-config.yaml        # Storage and retention config
│   ├── grafana/
│   │   ├── provisioning/           # Auto-provisioned datasources and dashboard config
│   │   └── dashboards/             # 5 dashboard JSON files
│   └── alertmanager/
│       └── alertmanager.yml        # Alert routing rules
├── analyzer/                       # Custom Python service (Phase 2+)
│   ├── Dockerfile
│   ├── pyproject.toml
│   ├── analyzer/
│   │   ├── main.py                 # FastAPI app with scheduled background tasks
│   │   ├── config.py               # Settings via pydantic-settings
│   │   ├── unifi/                  # UniFi controller API client + poller
│   │   ├── enrichment/             # Device, DNS, GeoIP enrichment
│   │   ├── correlator/             # Rule-based cross-source correlation
│   │   ├── alerts/                 # Anomaly detection + Alertmanager integration
│   │   └── api/                    # REST API endpoints
│   └── tests/                      # Unit tests
├── scripts/
│   ├── setup.sh                    # First-time setup
│   ├── verify.sh                   # Health check all services
│   ├── test-syslog.sh              # Generate test syslog data
│   └── test-netflow.sh             # Generate test NetFlow data
└── data/                           # Persistent data (gitignored)
    └── pcaps/                      # Drop PCAP files here for Zeek analysis
```

## Requirements

- **Docker Engine** 24.0+ with Docker Compose v2
- **RAM:** 4 GB minimum (Phase 1), 8 GB recommended (all phases)
- **Disk:** 10 GB+ depending on traffic volume and retention settings
- **Network:** UDP ports 514 (syslog) and 2055 (NetFlow) accessible from your network devices
- **UniFi Controller** 7.3.76+ for CEF syslog export (Phase 2+ for API access)
- **Optional:** MaxMind GeoLite2 database for GeoIP enrichment ([free registration](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data))

## License

This project is open source. See individual component licenses:
- Vector: MPL-2.0
- GoFlow2: BSD-3-Clause
- Zeek: BSD-3-Clause
- ClickHouse: Apache-2.0
- Loki: AGPL-3.0
- Grafana OSS: AGPL-3.0
- InfluxDB: MIT
- ntopng: GPL-3.0
