# Configuration Reference

All configuration is managed through environment variables (`.env` file) and YAML/SQL config files.

## Environment Variables

### Core Settings

| Variable | Default | Phase | Description |
|----------|---------|-------|-------------|
| `SYSLOG_PORT` | `514` | 1 | UDP port for syslog reception |
| `NETFLOW_PORT` | `2055` | 1 | UDP port for NetFlow/IPFIX reception |
| `CLICKHOUSE_USER` | `netmon` | 1 | ClickHouse database username |
| `CLICKHOUSE_PASSWORD` | `changeme` | 1 | ClickHouse database password |
| `CLICKHOUSE_DB` | `netmon` | 1 | ClickHouse database name |
| `GRAFANA_ADMIN_PASSWORD` | `changeme` | 1 | Grafana admin password |
| `GF_INSTALL_PLUGINS` | `grafana-clickhouse-datasource` | 1 | Grafana plugins to install on startup |

### UniFi Controller (Phase 2+)

| Variable | Default | Description |
|----------|---------|-------------|
| `UNIFI_HOST` | `https://192.168.1.1` | UniFi controller URL (include protocol) |
| `UNIFI_USERNAME` | `admin` | Local admin username (not a UI.com account) |
| `UNIFI_PASSWORD` | `changeme` | Admin password |
| `UNIFI_SITE` | `default` | UniFi site name |
| `UNIFI_VERIFY_SSL` | `false` | Verify SSL certificate (set `true` for valid certs) |

### InfluxDB (Phase 3)

| Variable | Default | Description |
|----------|---------|-------------|
| `INFLUXDB_USER` | `netmon` | InfluxDB admin username |
| `INFLUXDB_PASSWORD` | `changeme123` | InfluxDB admin password (min 8 chars) |
| `INFLUXDB_ORG` | `netmon` | InfluxDB organization name |
| `INFLUXDB_BUCKET` | `network` | InfluxDB bucket name |
| `INFLUXDB_TOKEN` | `netmon-influx-token` | InfluxDB API token |

### Alerting (Phase 3)

| Variable | Default | Description |
|----------|---------|-------------|
| `ANOMALY_DETECTION_ENABLED` | `false` | Enable anomaly detection and alerting |
| `ALERTMANAGER_URL` | `http://alertmanager:9093` | Alertmanager endpoint |

## Configuration Files

### Vector Pipeline (`config/vector/`)

Vector handles all data ingestion and routing. The pipeline is split across three files, one per phase.

#### `vector.yaml` (Phase 1)

Defines two sources and two sinks:

| Component | Type | Description |
|-----------|------|-------------|
| Source: `syslog_udp` | `syslog` | Listens on UDP 514 for syslog messages |
| Source: `goflow2_files` | `file` | Reads GoFlow2 JSON output from shared volume |
| Transform: `parse_syslog` | `remap` | Parses CEF format, extracts fields (src/dst IP, port, protocol, action) |
| Transform: `parse_flows` | `remap` | Normalizes GoFlow2 JSON field names to match ClickHouse schema |
| Sink: `loki_syslog` | `loki` | Sends parsed syslog to Loki with structured labels |
| Sink: `clickhouse_flows` | `http` | Sends flow data to ClickHouse via HTTP JSONEachRow interface |

**CEF Parsing:** Vector uses its built-in `parse_cef!()` VRL function. Non-CEF syslog messages are passed through as plain text with hostname and appname extracted from the syslog header.

**Loki Labels:** Events are labeled with `source` (unifi_cef or syslog_plain), `vendor`, `product`, and `severity` for efficient filtering in Grafana.

#### `vector-phase2.yaml` (Phase 2)

Adds Zeek log ingestion:

| Component | Type | Description |
|-----------|------|-------------|
| Source: `zeek_conn_logs` | `file` | Reads Zeek conn.log files |
| Source: `zeek_dns_logs` | `file` | Reads Zeek dns.log files |
| Transform: `parse_zeek_conn` | `remap` | Parses Zeek JSON conn format |
| Transform: `parse_zeek_dns` | `remap` | Parses Zeek JSON dns format, joins answer arrays |
| Sink: `clickhouse_zeek_conn` | `http` | Conn logs → ClickHouse |
| Sink: `clickhouse_zeek_dns` | `http` | DNS logs → ClickHouse |
| Sink: `loki_zeek` | `loki` | Both log types → Loki for searchability |

#### `vector-phase3.yaml` (Phase 3)

Adds InfluxDB metrics output:

| Component | Type | Description |
|-----------|------|-------------|
| Transform: `flow_metrics` | `remap` | Shapes flow data as InfluxDB line protocol |
| Transform: `syslog_metrics` | `remap` | Shapes syslog event counts as metrics |
| Sink: `influxdb_flows` | `influxdb_metrics` | Flow metrics → InfluxDB |
| Sink: `influxdb_syslog` | `influxdb_metrics` | Syslog metrics → InfluxDB |

### ClickHouse Schema (`config/clickhouse/init-db.sql`)

All tables are created in the `netmon` database. The init script runs automatically on first container start.

| Table | Engine | Partition | TTL | Phase | Purpose |
|-------|--------|-----------|-----|-------|---------|
| `flows` | MergeTree | Monthly | 90 days | 1 | Raw NetFlow/IPFIX records |
| `flows_5m` | SummingMergeTree | Monthly | 365 days | 1 | 5-minute flow aggregates (materialized view) |
| `flows_hourly` | SummingMergeTree | Monthly | 730 days | 1 | Hourly flow aggregates (materialized view) |
| `zeek_conn` | MergeTree | Monthly | 60 days | 2 | Zeek connection metadata |
| `zeek_dns` | MergeTree | Monthly | 60 days | 2 | Zeek DNS query/response logs |
| `unifi_devices` | MergeTree | Monthly | 90 days | 2 | Infrastructure device snapshots |
| `unifi_clients` | MergeTree | Monthly | 90 days | 2 | Client connection snapshots |
| `correlated_events` | MergeTree | Monthly | 180 days | 2 | Correlation and anomaly detection events |

**Materialized views** (`flows_5m_mv`, `flows_hourly_mv`) automatically aggregate incoming flow data. Grafana queries the pre-aggregated tables for fast dashboard rendering.

### Loki (`config/loki/loki-config.yaml`)

| Setting | Value | Description |
|---------|-------|-------------|
| Storage backend | Filesystem | Chunks and index stored in `/loki` volume |
| Schema | v13 (TSDB) | Current recommended schema |
| Retention | 720 hours (30 days) | Automatic log expiry |
| Ingestion rate | 10 MB/s | Rate limit per tenant |
| Ingestion burst | 20 MB | Burst allowance |
| Structured metadata | Enabled | CEF fields queryable as metadata |

### Grafana (`config/grafana/`)

#### Datasource Provisioning (`provisioning/datasources/datasources.yaml`)

Four datasources are auto-provisioned:

| Name | Type | Backend | Phase |
|------|------|---------|-------|
| Loki | `loki` | Loki at port 3100 | 1 (default) |
| ClickHouse | `grafana-clickhouse-datasource` | ClickHouse native at port 9000 | 1 |
| InfluxDB | `influxdb` (Flux) | InfluxDB at port 8086 | 3 |
| Analyzer | `yesoreyeram-infinity-datasource` | Analyzer API at port 8080 | 2 |

#### Dashboard Provisioning (`provisioning/dashboards/dashboards.yaml`)

Dashboards are loaded from `/var/lib/grafana/dashboards` (mapped to `config/grafana/dashboards/` on the host). Grafana checks for changes every 30 seconds. Dashboards can also be edited in the UI.

### Alertmanager (`config/alertmanager/alertmanager.yml`)

Default configuration logs alerts only. To enable notifications, uncomment and configure one of the receiver blocks:

**Slack:**
```yaml
receivers:
  - name: "default"
    slack_configs:
      - api_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        channel: "#network-alerts"
        title: "{{ .GroupLabels.alertname }}"
        text: "{{ range .Alerts }}{{ .Annotations.summary }}\n{{ end }}"
```

**Generic Webhook:**
```yaml
receivers:
  - name: "default"
    webhook_configs:
      - url: "http://your-endpoint:8080/alerts"
        send_resolved: true
```

**Email:**
```yaml
global:
  smtp_smarthost: "smtp.gmail.com:587"
  smtp_from: "alerts@yourdomain.com"
  smtp_auth_username: "alerts@yourdomain.com"
  smtp_auth_password: "app-password"

receivers:
  - name: "default"
    email_configs:
      - to: "admin@yourdomain.com"
```

Alert grouping: alerts are grouped by `alertname` and `source_ip`. Same alert repeats every 4 hours (critical: 1 hour, info: 12 hours).

## Tuning Data Retention

Edit `config/clickhouse/init-db.sql` to change TTL values. To apply changes to existing tables:

```bash
docker exec netmon-clickhouse clickhouse-client --query \
  "ALTER TABLE netmon.flows MODIFY TTL time_received + INTERVAL 30 DAY"
```

For Loki, edit `retention_period` in `config/loki/loki-config.yaml` and restart:

```bash
docker compose restart loki
```

## Tuning Polling Intervals

The analyzer's polling and correlation intervals are configured in `analyzer/analyzer/config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `unifi_poll_interval` | 60s | How often to poll UniFi for device/client data |
| `correlation_interval` | 300s (5 min) | How often to run correlation rules |

To change these, set environment variables in the analyzer service:

```yaml
# In docker-compose.phase2.yml
analyzer:
  environment:
    UNIFI_POLL_INTERVAL: 30
    CORRELATION_INTERVAL: 120
```
