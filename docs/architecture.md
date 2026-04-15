# Architecture

This document describes the system architecture, component responsibilities, data flow, and storage design.

## Design Principles

1. **Open-source only** - every component is free and open source
2. **Incremental deployment** - start with Phase 1 and add complexity as needed
3. **Right tool for each data type** - ClickHouse for analytical queries on structured data, Loki for log search, InfluxDB for high-resolution real-time metrics
4. **Configuration over code** - most of the platform is configured tools; custom code is limited to the analyzer service where off-the-shelf tools don't cover the use case
5. **Docker-native** - fully containerized, reproducible, portable

## Component Overview

### Data Collection Layer

#### Vector (Syslog + Routing)

[Vector](https://vector.dev) is a high-performance observability data pipeline written in Rust. It serves as the central data router for the platform.

**Responsibilities:**
- Listens on UDP 514 for syslog from network devices
- Parses CEF (Common Event Format) from UniFi SIEM integration using the built-in `parse_cef!()` VRL function
- Reads GoFlow2's JSON output from a shared Docker volume
- Reads Zeek's JSON log files (Phase 2)
- Routes parsed data to appropriate backends (Loki for logs, ClickHouse for structured data, InfluxDB for metrics)

**Why Vector over alternatives:**
- Native CEF parsing (Fluentd and Logstash require plugins)
- Both Loki and ClickHouse sinks built in
- Single ~15 MB binary, ~50 MB RAM footprint (vs Logstash's 1+ GB JVM)
- VRL (Vector Remap Language) for flexible data transformation

#### GoFlow2 (NetFlow/IPFIX/sFlow)

[GoFlow2](https://github.com/netsampler/goflow2) is a high-performance flow collector written in Go.

**Responsibilities:**
- Receives NetFlow v5, v9, IPFIX, and sFlow on UDP 2055/6343
- Normalizes flow records to a common JSON format
- Writes JSON lines to a file on a shared Docker volume

**Architecture note:** GoFlow2 does not have a direct ClickHouse transport. The data path is:
```
Network devices → GoFlow2 (UDP) → JSON file → Vector (file source) → ClickHouse (HTTP)
```
This avoids adding Kafka to the stack while maintaining data integrity through Vector's checkpointing.

#### Zeek (PCAP Analysis)

[Zeek](https://zeek.org) (formerly Bro) is a network analysis framework that extracts protocol-level metadata from packet captures.

**Responsibilities:**
- Watches `data/pcaps/` for new `.pcap` and `.pcapng` files
- Processes packets and generates structured logs: `conn.log`, `dns.log`, `http.log`, `ssl.log`, etc.
- Outputs logs in JSON format (configured via `LogAscii::use_json=T`)

**What Zeek extracts (examples):**
- Connection records: duration, bytes, packets, connection state
- DNS queries: query name, response code, answers, TTLs
- HTTP requests: method, URI, response code, user agent
- SSL/TLS: server name, certificate details, JA3 fingerprints

### Storage Layer

#### ClickHouse (Analytical Data)

[ClickHouse](https://clickhouse.com) is a columnar database optimized for analytical queries (OLAP).

**Why ClickHouse for network data:**
- Flow data is append-only, wide (many columns), and queried with aggregations (top-N, sum, group-by, time ranges)
- ClickHouse is 10-100x faster than PostgreSQL for these query patterns
- Columnar storage compresses network data extremely well (IP addresses, port numbers have low cardinality)
- MergeTree engine supports automatic data expiry via TTL
- Materialized views pre-aggregate data at insert time for fast dashboard queries

**Tables and their purposes:**

```
netmon database
├── flows                  ← Raw NetFlow/IPFIX records (90-day TTL)
├── flows_5m               ← 5-minute aggregates (auto-populated, 365-day TTL)
├── flows_5m_mv            ← Materialized view: flows → flows_5m
├── flows_hourly           ← Hourly aggregates (auto-populated, 730-day TTL)
├── flows_hourly_mv        ← Materialized view: flows → flows_hourly
├── zeek_conn              ← Zeek connection logs (60-day TTL)
├── zeek_dns               ← Zeek DNS logs (60-day TTL)
├── unifi_devices          ← Infrastructure device snapshots (90-day TTL)
├── unifi_clients          ← Client connection snapshots (90-day TTL)
└── correlated_events      ← Correlation + anomaly events (180-day TTL)
```

**Aggregation strategy:**

Raw flow data goes into `flows`. Two materialized views automatically aggregate at insert time:

```
                  INSERT
                    │
                    ▼
              ┌──────────┐
              │  flows   │  ← Raw data (90 days)
              └────┬─────┘
                   │
          ┌────────┴────────┐
          ▼                 ▼
    ┌───────────┐    ┌─────────────┐
    │ flows_5m  │    │flows_hourly │
    │ (365 days)│    │ (730 days)  │
    └───────────┘    └─────────────┘
```

Dashboard queries hit `flows_5m` and `flows_hourly` for fast response times. Only detailed drill-downs query the raw `flows` table.

#### Loki (Log Data)

[Grafana Loki](https://grafana.com/oss/loki/) is a log aggregation system designed for cost-effective log storage.

**Why Loki over Elasticsearch:**
- Indexes only labels (source, vendor, severity), not full text
- Uses 50-100 MB RAM vs Elasticsearch's 2-4 GB minimum
- Sufficient for syslog where we extract structured fields via Vector
- Native Grafana integration

**Label strategy:**
```
{source="unifi_cef", vendor="Ubiquiti", product="UniFi", severity="7"}
{source="syslog_plain", vendor="switch01", product="kernel", severity="info"}
{source="zeek", log_type="tcp"}
```

#### InfluxDB (Real-Time Metrics - Phase 3)

[InfluxDB](https://www.influxdata.com) provides high-resolution time-series storage for real-time dashboards.

**Role:** Stores per-flow and per-event metrics at sub-second resolution for Grafana dashboards with 5-second auto-refresh. ClickHouse handles analytics; InfluxDB handles real-time.

**Retention:** 7 days (high-resolution data is ephemeral; long-term trends use ClickHouse aggregates).

### Intelligence Layer

#### Analyzer Service (Custom Python/FastAPI)

The analyzer is the only custom-coded component. It fills gaps that off-the-shelf tools don't cover:

```
analyzer/
├── main.py              # FastAPI app + background task scheduling
├── config.py            # pydantic-settings configuration
├── unifi/
│   ├── client.py        # UniFi REST API wrapper
│   └── poller.py        # Periodic device/client data collection
├── enrichment/
│   ├── device.py        # IP → device name mapping
│   ├── dns.py           # Passive DNS from Zeek logs
│   └── geoip.py         # MaxMind GeoLite2 lookups
├── correlator/
│   ├── engine.py        # Rule execution engine
│   └── rules.py         # SQL-based correlation rules
├── alerts/
│   ├── detector.py      # Anomaly detection (baseline comparison)
│   └── notifier.py      # Alertmanager + ClickHouse push
└── api/
    └── routes.py        # REST API endpoints
```

**Background tasks** (managed by APScheduler):

| Task | Interval | Purpose |
|------|----------|---------|
| UniFi poller | 60s | Fetch devices/clients, update enrichment cache, write to ClickHouse |
| DNS cache refresh | 120s | Read new entries from Zeek dns.log files |
| Correlation engine | 300s | Execute all correlation rules against ClickHouse |
| Anomaly detector | 300s | Compare current behavior against 7-day baselines (Phase 3) |

### Visualization Layer

#### Grafana

[Grafana](https://grafana.com/grafana/) provides unified dashboards across all data backends.

**Datasource connections:**
```
Grafana ──► Loki (syslog queries)
       ──► ClickHouse (flow analytics, device data, events)
       ──► InfluxDB (real-time metrics, Phase 3)
       ──► Analyzer API (enriched data via Infinity plugin, Phase 2)
```

#### ntopng (Phase 3)

[ntopng](https://www.ntop.org/products/traffic-analysis/ntopng/) provides a separate real-time traffic analysis UI with:
- Live flow visualization
- Application-level traffic classification
- Network topology view
- Host and device identification

## Data Retention Summary

| Data Type | Storage | Raw Retention | Aggregated Retention |
|-----------|---------|---------------|---------------------|
| NetFlow records | ClickHouse `flows` | 90 days | 5-min: 365 days, hourly: 730 days |
| Syslog | Loki | 30 days | - |
| Zeek connections | ClickHouse `zeek_conn` | 60 days | - |
| Zeek DNS | ClickHouse `zeek_dns` | 60 days | - |
| UniFi snapshots | ClickHouse `unifi_*` | 90 days | - |
| Correlated events | ClickHouse `correlated_events` | 180 days | - |
| Real-time metrics | InfluxDB | 7 days | - |

## Network Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Host                               │
│                                                              │
│  ┌─────────┐  ┌─────────┐  ┌────────┐  ┌──────┐  ┌──────┐ │
│  │ Vector  │  │ GoFlow2 │  │  Zeek  │  │Loki  │  │Grafana│ │
│  │ :514/udp│  │:2055/udp│  │        │  │:3100 │  │:3000  │ │
│  └────┬────┘  └────┬────┘  └───┬────┘  └──┬───┘  └──┬────┘ │
│       │            │           │           │         │      │
│       │      ┌─────▼───────────▼───────────▼─┐       │      │
│       │      │         netmon network        │       │      │
│       │      └─────────────┬─────────────────┘       │      │
│       │                    │                         │      │
│  ┌────▼────────────────────▼─────────────────────────▼────┐ │
│  │                   ClickHouse :8123/:9000                │ │
│  │                   (netmon database)                     │ │
│  └────────────────────────────┬───────────────────────────┘ │
│                               │                              │
│                    ┌──────────▼──────────┐                   │
│                    │     Analyzer :8080  │                   │
│                    │  UniFi API poller   │                   │
│                    │  Enrichment cache   │                   │
│                    │  Correlation engine │                   │
│                    └────────────────────┘                   │
│                                                              │
│  Phase 3:                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐              │
│  │InfluxDB  │  │ ntopng   │  │ Alertmanager │              │
│  │:8086     │  │:3001     │  │:9093         │              │
│  └──────────┘  └──────────┘  └──────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

All services communicate over the `netmon` Docker bridge network. Only explicitly mapped ports are accessible from the host.
