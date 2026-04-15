# Dashboards Guide

All dashboards are auto-provisioned from JSON files in `config/grafana/dashboards/`. They appear automatically when Grafana starts. You can also edit dashboards directly in the Grafana UI.

## Accessing Dashboards

Open Grafana at `http://localhost:3000` and navigate to **Dashboards** > **Network Monitoring**.

Default credentials: `admin` / your `GRAFANA_ADMIN_PASSWORD` from `.env`.

Anonymous read-only access is enabled by default.

## Dashboard Inventory

| Dashboard | UID | Datasources | Phase Required |
|-----------|-----|-------------|----------------|
| [Network Overview](#network-overview) | `netmon-overview` | ClickHouse, Loki | 1 |
| [Syslog Explorer](#syslog-explorer) | `netmon-syslog` | Loki | 1 |
| [Client Health & Devices](#client-health--devices) | `netmon-clients` | ClickHouse | 2 |
| [DNS Analysis](#dns-analysis) | `netmon-dns` | ClickHouse | 2 |
| [Correlated Events & Alerts](#correlated-events--alerts) | `netmon-events` | ClickHouse | 2 |

Direct links (replace `localhost` with your server IP):
- http://localhost:3000/d/netmon-overview
- http://localhost:3000/d/netmon-syslog
- http://localhost:3000/d/netmon-clients
- http://localhost:3000/d/netmon-dns
- http://localhost:3000/d/netmon-events

## Network Overview

**File:** `config/grafana/dashboards/network-overview.json`
**Refresh:** 30 seconds
**Default time range:** Last 6 hours

This is the primary operational dashboard. It answers: "What's happening on my network right now?"

### Panels

| Panel | Type | Query Source | What It Shows |
|-------|------|-------------|---------------|
| Total Bandwidth | Time series | `flows_5m` | Aggregate bytes per 5-minute bucket |
| Flow Count | Time series (bars) | `flows_5m` | Number of flow records per 5-minute bucket |
| Top 10 Talkers (Source) | Bar chart | `flows_5m` | Devices sending the most traffic |
| Top 10 Destinations | Bar chart | `flows_5m` | IPs receiving the most traffic |
| Top Conversations | Table | `flows_5m` | Source → destination pairs with protocol, bytes, packets |
| Protocol Distribution | Pie chart | `flows_5m` | TCP vs UDP vs ICMP breakdown by bytes |
| Top Destination Ports | Bar chart | `flows_5m` | Most-accessed ports with friendly names (HTTPS, DNS, SSH, etc.) |
| Recent Syslog Events | Log panel | Loki | Live stream of recent syslog messages |

### Key Queries

**Top talkers (source):**
```sql
SELECT src_addr, sum(total_bytes) AS bytes
FROM netmon.flows_5m
WHERE timeslot >= $__fromTime AND timeslot <= $__toTime
GROUP BY src_addr
ORDER BY bytes DESC LIMIT 10
```

**Top conversations:**
```sql
SELECT src_addr, dst_addr, dst_port, proto,
       sum(total_bytes) AS bytes, sum(total_packets) AS packets
FROM netmon.flows_5m
WHERE timeslot >= $__fromTime AND timeslot <= $__toTime
GROUP BY src_addr, dst_addr, dst_port, proto
ORDER BY bytes DESC LIMIT 50
```

## Syslog Explorer

**File:** `config/grafana/dashboards/syslog-explorer.json`
**Refresh:** 30 seconds
**Default time range:** Last 6 hours

Log exploration dashboard for syslog and CEF events.

### Panels

| Panel | Type | What It Shows |
|-------|------|---------------|
| Syslog Event Rate | Time series (stacked bars) | Event count per interval, colored by severity |
| Events by Source Device | Pie chart | Distribution of events across device vendors |
| Events by Severity | Stat | Count of events per severity level |
| Events by Product | Pie chart | Distribution by device product type |
| UniFi CEF Events | Log panel | Formatted CEF events with src/dst IP and action |
| Firewall Events | Log panel | CEF events matching "Firewall" keyword |

### Variables

| Variable | Values | Description |
|----------|--------|-------------|
| `source` | `unifi_cef`, `syslog_plain`, `zeek` | Filter by log source type |

### Key Queries

**Event rate by severity:**
```logql
sum by (severity) (count_over_time({source=~".+"} [$__interval]))
```

**Formatted CEF event viewer:**
```logql
{source=~"$source"} | json | line_format "{{.event_name}} src={{.src_ip}} dst={{.dst_ip}} {{.action}}"
```

## Client Health & Devices

**File:** `config/grafana/dashboards/client-health.json`
**Refresh:** 30 seconds
**Default time range:** Last 6 hours
**Requires:** Phase 2 (UniFi API poller)

Monitors WiFi client health, signal quality, and infrastructure device status.

### Panels

| Panel | Type | What It Shows |
|-------|------|---------------|
| Active Clients Over Time | Time series | Unique client count per polling interval |
| WiFi vs Wired | Pie chart | Connection type distribution |
| Average WiFi Experience | Gauge | UniFi experience score (0-100%) with color thresholds |
| WiFi Signal Distribution | Time series | Average, min, max signal strength over time |
| Poor Signal Clients | Table | Clients with average signal < -75 dBm (name, IP, signal, AP) |
| All Active Clients | Table | Full client inventory from most recent poll |
| Device Infrastructure | Table | All APs, switches, gateways with CPU, memory, client count, uptime |

### Interpreting WiFi Signals

| Signal (dBm) | Quality | Color |
|--------------|---------|-------|
| > -50 | Excellent | Green |
| -50 to -60 | Good | Green |
| -60 to -70 | Fair | Yellow |
| -70 to -80 | Poor | Orange |
| < -80 | Very poor | Red |

### Key Queries

**Clients with poor signal:**
```sql
SELECT name, hostname, ip, mac, avg(signal) AS avg_signal,
       min(signal) AS worst_signal, any(ap_mac) AS connected_ap
FROM netmon.unifi_clients
WHERE timestamp >= now() - INTERVAL 1 HOUR
  AND is_wired = 0 AND signal < -75
GROUP BY name, hostname, ip, mac
ORDER BY avg_signal ASC LIMIT 20
```

## DNS Analysis

**File:** `config/grafana/dashboards/dns-analysis.json`
**Refresh:** 1 minute
**Default time range:** Last 6 hours
**Requires:** Phase 2 (Zeek processing PCAPs with DNS traffic)

Monitors DNS health, which is a leading indicator of connectivity issues.

### Panels

| Panel | Type | What It Shows |
|-------|------|---------------|
| DNS Query Rate | Time series | Queries and failures per minute |
| DNS Success Rate | Gauge | Percentage of successful DNS lookups (last hour) |
| Top Queried Domains | Bar chart | Most frequently queried domain names |
| DNS Failure Codes | Pie chart | Breakdown of NXDOMAIN, SERVFAIL, REFUSED, etc. |
| DNS Servers Used | Bar chart | Which DNS resolvers are receiving queries |
| Top Clients by DNS | Table | Per-client query count with failure percentage |
| Failed DNS Queries | Table | Individual failed queries with timestamp, client, domain, error |

### What DNS Issues Look Like

**NXDOMAIN spike:** A device is trying to resolve domains that don't exist. Could indicate malware, misconfigured DNS suffix, or stale DNS entries.

**SERVFAIL spike:** DNS servers are failing to resolve queries. Could indicate upstream DNS issues, DNSSEC problems, or DNS server overload.

**Single client with high failure rate:** That specific device has a DNS configuration problem or is exhibiting unusual behavior.

## Correlated Events & Alerts

**File:** `config/grafana/dashboards/correlated-events.json`
**Refresh:** 1 minute
**Default time range:** Last 24 hours
**Requires:** Phase 2 (correlation engine)

Shows events detected by the correlation engine and anomaly detector.

### Panels

| Panel | Type | What It Shows |
|-------|------|---------------|
| Events by Severity (24h) | Stat | Count of Critical, Warning, Info events |
| Event Rate Over Time | Time series (stacked bars) | Events per 5-minute bucket by rule name |
| Events by Rule | Bar chart | Which rules are firing most frequently |
| Top Affected IPs | Bar chart | Which IPs appear most often in events |
| Severity Distribution | Pie chart | Critical vs Warning vs Info breakdown |
| Recent Events (Detail) | Table | Full event table with color-coded severity, description, details |

### Severity Color Coding

The detail table uses background colors to highlight severity:

| Severity | Color | Meaning |
|----------|-------|---------|
| 1-3 | Green | Informational |
| 4-5 | Yellow | Low concern |
| 6-7 | Orange | Investigate when convenient |
| 8-10 | Red | Investigate promptly |

## Customizing Dashboards

### Editing in the UI

1. Open any dashboard
2. Click the gear icon > **Make editable** (if needed)
3. Click any panel title > **Edit**
4. Modify queries, visualization settings, etc.
5. Click **Save dashboard**

Changes made in the UI are saved to Grafana's internal database. They will persist across container restarts (data is in the `grafana-data` volume) but will be overridden if you re-provision from files.

### Editing JSON Files

1. Edit the JSON file in `config/grafana/dashboards/`
2. Grafana picks up changes within 30 seconds (configured in `provisioning/dashboards/dashboards.yaml`)
3. No restart needed

### Adding New Dashboards

1. Create your dashboard in the Grafana UI
2. Click the gear icon > **JSON Model**
3. Copy the JSON
4. Save to a new file in `config/grafana/dashboards/`
5. Grafana loads it automatically

### Adding New Datasources

Edit `config/grafana/provisioning/datasources/datasources.yaml` and restart Grafana:

```bash
docker compose restart grafana
```
