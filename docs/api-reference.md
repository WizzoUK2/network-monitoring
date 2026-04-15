# API Reference

The analyzer service exposes a REST API at `http://localhost:8080`. Interactive API documentation (Swagger UI) is available at `http://localhost:8080/docs`.

## Base URL

```
http://localhost:8080
```

## Authentication

No authentication is required. The API is intended for internal use within the Docker network. If exposing externally, place behind a reverse proxy with authentication.

---

## Health & Status

### `GET /api/health`

Service health check.

**Response:**
```json
{
  "status": "ok",
  "service": "netmon-analyzer"
}
```

---

### `GET /api/stats/summary`

System-wide statistics summary.

**Response:**
```json
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

| Field | Type | Description |
|-------|------|-------------|
| `flows_total` | integer | Total flow records in the last 24 hours |
| `flows_bytes_24h` | integer | Total bytes transferred in the last 24 hours |
| `unique_sources_24h` | integer | Unique source IP addresses in the last 24 hours |
| `unique_dests_24h` | integer | Unique destination IP addresses in the last 24 hours |
| `events_24h` | integer | Correlated events generated in the last 24 hours |
| `known_devices` | integer | Devices currently in the enrichment cache |
| `dns_cache_size` | integer | Entries in the passive DNS cache |

---

## UniFi Data

### `GET /api/unifi/devices`

List all adopted UniFi infrastructure devices.

**Response:**
```json
{
  "devices": [
    {
      "mac": "aa:bb:cc:dd:ee:ff",
      "name": "Living Room AP",
      "model": "U6-LR",
      "type": "uap",
      "ip": "192.168.1.10",
      "version": "6.6.55",
      "uptime": 1234567,
      "state": 1,
      "cpu_usage": "12.5",
      "mem_usage": "45.2",
      "tx_bytes": 123456789,
      "rx_bytes": 987654321,
      "num_clients": 8
    }
  ],
  "count": 5
}
```

| Field | Type | Description |
|-------|------|-------------|
| `mac` | string | Device MAC address |
| `name` | string | User-assigned name or model name |
| `model` | string | Hardware model identifier |
| `type` | string | Device type (`uap`, `usw`, `ugw`) |
| `ip` | string | Device IP address |
| `version` | string | Firmware version |
| `uptime` | integer | Uptime in seconds |
| `state` | integer | Device state (1 = online) |
| `cpu_usage` | string | CPU usage percentage |
| `mem_usage` | string | Memory usage percentage |
| `tx_bytes` | integer | Total bytes transmitted |
| `rx_bytes` | integer | Total bytes received |
| `num_clients` | integer | Number of connected clients |

---

### `GET /api/unifi/clients`

List all currently connected clients.

**Response:**
```json
{
  "clients": [
    {
      "mac": "11:22:33:44:55:66",
      "ip": "192.168.1.100",
      "hostname": "craigs-iphone",
      "name": "Craig's iPhone",
      "oui": "Apple",
      "network": "LAN",
      "is_wired": false,
      "signal": -52,
      "channel": 36,
      "radio": "na",
      "experience": 95,
      "tx_bytes": 1234567,
      "rx_bytes": 7654321,
      "tx_rate": 866000,
      "rx_rate": 866000,
      "uptime": 3600,
      "ap_mac": "aa:bb:cc:dd:ee:ff"
    }
  ],
  "count": 23
}
```

| Field | Type | Description |
|-------|------|-------------|
| `mac` | string | Client MAC address |
| `ip` | string | Client IP address |
| `hostname` | string | Client hostname (from DHCP) |
| `name` | string | User-assigned name in UniFi controller |
| `oui` | string | Manufacturer from OUI database |
| `network` | string | Network/VLAN name |
| `is_wired` | boolean | True if connected via Ethernet |
| `signal` | integer/null | WiFi signal strength in dBm (null if wired) |
| `channel` | integer/null | WiFi channel (null if wired) |
| `radio` | string/null | WiFi radio type: `ng` (2.4GHz), `na` (5GHz), `6e` (6GHz) |
| `experience` | integer | UniFi experience score (0-100) |
| `tx_bytes` | integer | Bytes transmitted by client |
| `rx_bytes` | integer | Bytes received by client |
| `tx_rate` | integer | Current TX rate in bps |
| `rx_rate` | integer | Current RX rate in bps |
| `uptime` | integer | Connection uptime in seconds |
| `ap_mac` | string | MAC of the AP the client is connected to |

---

### `GET /api/unifi/health`

Site health summary from the UniFi controller.

**Response:**
```json
{
  "health": [
    {
      "subsystem": "wan",
      "status": "ok",
      "wan_ip": "203.0.113.1",
      "gateways": ["aa:bb:cc:dd:ee:ff"],
      ...
    },
    {
      "subsystem": "lan",
      "status": "ok",
      "num_user": 15,
      ...
    },
    {
      "subsystem": "wlan",
      "status": "ok",
      "num_user": 8,
      ...
    }
  ]
}
```

---

## Enrichment

### `GET /api/enrichment/device/{ip}`

Look up device information by IP address. Data comes from the UniFi API poller's in-memory cache.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ip` | path (string) | IP address to look up |

**Response (found):**
```json
{
  "ip": "192.168.1.100",
  "name": "Craig's iPhone",
  "mac": "11:22:33:44:55:66",
  "network": "LAN",
  "is_wired": false,
  "oui": "Apple",
  "is_infrastructure": false
}
```

**Response (not found):**
```json
{
  "ip": "10.0.0.99",
  "found": false
}
```

---

### `GET /api/enrichment/dns/{ip}`

Look up hostname from the passive DNS cache (built from Zeek dns.log).

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ip` | path (string) | IP address to look up |

**Response:**
```json
{
  "ip": "142.250.80.46",
  "hostname": "google.com"
}
```

If no hostname is known, `hostname` will be `null`.

---

### `GET /api/enrichment/geoip/{ip}`

GeoIP lookup using the MaxMind GeoLite2 database.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ip` | path (string) | IP address to look up |

**Response (external IP):**
```json
{
  "ip": "8.8.8.8",
  "country": "US",
  "country_name": "United States",
  "city": "Mountain View",
  "latitude": 37.386,
  "longitude": -122.0838,
  "asn": 15169,
  "org": "Google LLC"
}
```

**Response (private IP):**
```json
{
  "ip": "192.168.1.1",
  "private": true
}
```

**Response (no GeoIP database):**
```json
{
  "ip": "8.8.8.8",
  "available": false
}
```

---

## Analytics

### `GET /api/top-talkers`

Get the top network talkers, enriched with device names and hostnames.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `minutes` | integer | 60 | Look-back window in minutes |
| `limit` | integer | 20 | Maximum number of results |

**Response:**
```json
{
  "talkers": [
    {
      "src_addr": "192.168.1.100",
      "src_name": "Craig's iPhone",
      "dst_addr": "142.250.80.46",
      "dst_name": "google.com",
      "total_bytes": 52428800,
      "total_packets": 38000,
      "flow_count": 150
    }
  ],
  "since_minutes": 60
}
```

---

### `GET /api/correlated-events`

Get recent events from the correlation engine and anomaly detector.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | integer | 24 | Look-back window in hours |
| `limit` | integer | 50 | Maximum number of results |

**Response:**
```json
{
  "events": [
    {
      "timestamp": "2026-04-15T10:30:00+00:00",
      "rule": "dns_failure_burst",
      "severity": 7,
      "description": "Device 192.168.1.50 has 65% DNS failure rate (13/20 queries in 10m)",
      "source_ips": "192.168.1.50",
      "details": "{\"total_queries\": 20, \"failed_queries\": 13, ...}"
    }
  ],
  "count": 5
}
```

---

## Alerting

### `POST /api/alerts/test`

Fire a test alert through the full alerting pipeline (ClickHouse + Alertmanager).

**Request:** No body required.

**Response:**
```json
{
  "status": "sent",
  "message": "Test alert pushed to Alertmanager and ClickHouse"
}
```

**Response (alerting not enabled):**
```json
{
  "error": "Alerting not enabled (set ANOMALY_DETECTION_ENABLED=true)"
}
```

---

## Error Handling

All endpoints return errors in a consistent format:

```json
{
  "error": "Description of what went wrong",
  "devices": [],
  "count": 0
}
```

Common error scenarios:
- UniFi controller unreachable: endpoints return the error message with empty data arrays
- ClickHouse table not yet created: query endpoints return `{"error": "...", "count": 0}`
- GeoIP database not installed: returns `{"available": false}`

## Using with Grafana

The Analyzer API can be queried from Grafana using the **Infinity datasource** (auto-provisioned as "Analyzer"):

1. In Grafana, add a new panel
2. Select the **Analyzer** datasource
3. Set type to **JSON**
4. Enter the URL path (e.g., `/api/top-talkers?minutes=30`)
5. Configure column mappings as needed

This enables building custom Grafana panels that display enriched data (device names instead of raw IPs).
