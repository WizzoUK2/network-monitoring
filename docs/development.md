# Development Guide

How to extend the platform: add correlation rules, build new enrichment modules, create dashboards, and run tests.

## Development Setup

### Prerequisites

- Python 3.11+
- Docker and Docker Compose (for running the full stack)

### Setting Up a Local Dev Environment

```bash
cd network-monitoring

# Create a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the analyzer package in editable mode with dev dependencies
cd analyzer
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

### Running the Analyzer Locally (Outside Docker)

For faster development iteration, run the analyzer directly while the other services run in Docker:

```bash
# Start infrastructure services only
docker compose up -d clickhouse loki grafana

# Set environment variables
export CLICKHOUSE_HOST=localhost
export CLICKHOUSE_PORT=8123
export LOKI_URL=http://localhost:3100
export UNIFI_HOST=https://192.168.1.1
export UNIFI_USERNAME=admin
export UNIFI_PASSWORD=changeme
export ZEEK_LOG_DIR=./data/zeek-logs

# Run the analyzer
cd analyzer
uvicorn analyzer.main:app --host 0.0.0.0 --port 8080 --reload
```

The `--reload` flag watches for file changes and automatically restarts.

## Adding Correlation Rules

Correlation rules are defined in `analyzer/analyzer/correlator/rules.py`. Each rule is a SQL query executed against ClickHouse on a schedule.

### Rule Structure

```python
from analyzer.correlator.rules import CorrelationRule

CorrelationRule(
    name="my_rule_name",           # Unique identifier (snake_case)
    description="What this detects", # Human-readable description
    severity=5,                     # 1-10 scale
    window_minutes=15,              # How far back the query looks
    query="""
        SELECT
            src_addr,
            count() AS some_metric
        FROM flows
        WHERE time_received >= now() - INTERVAL {window} MINUTE
        GROUP BY src_addr
        HAVING some_metric > 100
        ORDER BY some_metric DESC
        LIMIT 10
    """,
)
```

### Rules Contract

- The `{window}` placeholder is replaced with `window_minutes` at execution time
- The query must return at least one column (the first column is used as `source_ip` in events)
- All columns are captured as a JSON details object
- The rule is skipped (not errored) if the queried table doesn't exist yet

### Adding a New Rule

1. Open `analyzer/analyzer/correlator/rules.py`
2. Add your `CorrelationRule` to the `RULES` list
3. Run tests to validate:
   ```bash
   pytest tests/test_correlator.py -v
   ```

### Example: Detect DHCP Exhaustion

```python
CorrelationRule(
    name="dhcp_exhaustion",
    description="Network approaching DHCP pool exhaustion (>90% utilization)",
    severity=6,
    window_minutes=10,
    query="""
        SELECT
            network,
            uniq(mac) AS active_clients
        FROM unifi_clients
        WHERE timestamp >= now() - INTERVAL {window} MINUTE
        GROUP BY network
        HAVING active_clients > 200
        ORDER BY active_clients DESC
        LIMIT 5
    """,
)
```

### Available Tables for Rules

| Table | Key Columns | Updated By |
|-------|-------------|------------|
| `flows` | `time_received`, `src_addr`, `dst_addr`, `src_port`, `dst_port`, `proto`, `bytes`, `packets` | Vector (from GoFlow2) |
| `flows_5m` | `timeslot`, `src_addr`, `dst_addr`, `proto`, `dst_port`, `total_bytes`, `total_packets` | Materialized view |
| `zeek_conn` | `ts`, `src_addr`, `dst_addr`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state` | Vector (from Zeek) |
| `zeek_dns` | `ts`, `src_addr`, `dst_addr`, `query`, `qtype_name`, `rcode_name`, `answers` | Vector (from Zeek) |
| `unifi_clients` | `timestamp`, `mac`, `ip`, `name`, `hostname`, `network`, `is_wired`, `signal`, `channel`, `experience` | Analyzer poller |
| `unifi_devices` | `timestamp`, `mac`, `ip`, `name`, `model`, `type`, `cpu_usage`, `mem_usage`, `num_clients` | Analyzer poller |

## Adding Anomaly Detection Checks

Anomaly checks are defined in `analyzer/analyzer/alerts/detector.py`. Each check is a method on the `AnomalyDetector` class that returns a list of `Anomaly` objects.

### Anomaly Structure

```python
from analyzer.alerts.detector import Anomaly

Anomaly(
    name="check_name",
    severity=5,
    description="Human-readable description of what was detected",
    source_ip="192.168.1.100",
    details={"key": "value", "metric": 42},
)
```

### Adding a New Check

1. Add a method to `AnomalyDetector` in `analyzer/analyzer/alerts/detector.py`:

```python
def _check_my_thing(self) -> list[Anomaly]:
    """Detect something unusual."""
    result = self.ch.query("""
        SELECT src_addr, some_metric
        FROM some_table
        WHERE ...
    """)

    anomalies = []
    for row in result.result_rows:
        src, metric = row
        anomalies.append(Anomaly(
            name="my_anomaly",
            severity=5,
            description=f"Device {src} has unusual metric: {metric}",
            source_ip=str(src),
            details={"metric": metric},
        ))
    return anomalies
```

2. Register it in the `run()` method's `checks` list:

```python
checks = [
    self._check_bandwidth_anomalies,
    self._check_new_external_destinations,
    self._check_device_disappearances,
    self._check_dns_health,
    self._check_wifi_degradation,
    self._check_my_thing,  # Add here
]
```

## Adding Enrichment Modules

Enrichment modules live in `analyzer/analyzer/enrichment/`. Each module follows a simple pattern:

```python
class MyEnricher:
    def __init__(self, ...):
        self._cache = {}

    def refresh(self):
        """Called periodically to update the cache."""
        ...

    def lookup(self, key: str) -> dict | None:
        """Fast lookup from the cache."""
        return self._cache.get(key)
```

To register a new enricher:

1. Create the module in `analyzer/analyzer/enrichment/`
2. Initialize it in `main.py`'s `lifespan()` function
3. Optionally schedule a `refresh()` job via APScheduler
4. Add an API endpoint in `analyzer/analyzer/api/routes.py`

## Adding API Endpoints

API routes are defined in `analyzer/analyzer/api/routes.py` using FastAPI.

```python
@router.get("/api/my-endpoint")
async def my_endpoint(request: Request, param: int = 10):
    """Description shown in the OpenAPI docs."""
    ch = request.app.state.clickhouse

    result = ch.query(
        "SELECT ... FROM ... WHERE ... LIMIT %(limit)s",
        parameters={"limit": param},
    )

    return {"data": [...], "count": len(result.result_rows)}
```

Access shared state via `request.app.state`:
- `request.app.state.clickhouse` - ClickHouse client
- `request.app.state.unifi` - UniFi API client
- `request.app.state.device_enricher` - Device name cache
- `request.app.state.dns_enricher` - Passive DNS cache
- `request.app.state.geoip_enricher` - GeoIP database

## Adding ClickHouse Tables

1. Add your `CREATE TABLE` statement to `config/clickhouse/init-db.sql`
2. For existing deployments, also run the statement manually:
   ```bash
   docker exec netmon-clickhouse clickhouse-client \
     --query "CREATE TABLE IF NOT EXISTS netmon.my_table (...) ENGINE = MergeTree() ..."
   ```

### Table Design Guidelines

- Use `MergeTree()` engine for raw data tables
- Use `SummingMergeTree()` for pre-aggregated tables
- Always include a `DateTime` column for partitioning and TTL
- Partition by `toYYYYMM(timestamp)` for monthly partitions
- Set appropriate TTL for automatic data expiry
- Use `String` for IP addresses (simpler than `IPv4`/`IPv6` types for mixed addresses)
- Add `DEFAULT` values to all non-key columns for robustness

## Adding Grafana Dashboards

### From the UI

1. Build your dashboard in Grafana
2. Click gear icon > **JSON Model**
3. Copy the JSON and save to `config/grafana/dashboards/my-dashboard.json`
4. Set a unique `uid` field in the JSON

### From Scratch (JSON)

Minimal dashboard template:

```json
{
  "editable": true,
  "panels": [
    {
      "title": "My Panel",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 0 },
      "datasource": { "type": "grafana-clickhouse-datasource", "uid": "clickhouse" },
      "targets": [
        {
          "rawSql": "SELECT toStartOfMinute(time_received) AS time, count() AS value FROM netmon.flows WHERE time_received >= $__fromTime GROUP BY time ORDER BY time",
          "format": 1,
          "refId": "A"
        }
      ]
    }
  ],
  "schemaVersion": 39,
  "title": "My Dashboard",
  "uid": "my-unique-uid"
}
```

## Adding Vector Pipelines

Vector config files in `config/vector/` are loaded based on the active phase. To add a new data source:

1. Create or edit the appropriate Vector config file
2. Define a `source` (where data comes from)
3. Define a `transform` (how to parse/shape it)
4. Define a `sink` (where to send it)

Example: adding a JSON log file source:

```yaml
sources:
  my_app_logs:
    type: file
    include:
      - /var/log/myapp/*.json
    read_from: beginning

transforms:
  parse_my_app:
    type: remap
    inputs: ["my_app_logs"]
    source: |
      . = parse_json!(.message)

sinks:
  loki_my_app:
    type: loki
    inputs: ["parse_my_app"]
    endpoint: "http://loki:3100"
    labels:
      source: "myapp"
    encoding:
      codec: json
```

## Running Tests

```bash
cd analyzer

# Run all tests
../.venv/bin/pytest tests/ -v

# Run specific test file
../.venv/bin/pytest tests/test_enrichment.py -v

# Run specific test class
../.venv/bin/pytest tests/test_enrichment.py::TestDeviceEnricher -v

# Run with coverage
../.venv/bin/pytest tests/ --cov=analyzer --cov-report=term-missing
```

### Writing Tests

Tests live in `analyzer/tests/`. Follow existing patterns:

- **Enrichment tests:** Use `tempfile.TemporaryDirectory()` for file-based tests
- **Correlator tests:** Validate rule structure and SQL formatting
- **API tests:** Use `pytest-httpx` for mocking HTTP clients

Example test:

```python
from analyzer.enrichment.device import DeviceEnricher

class TestMyFeature:
    def test_basic_operation(self):
        enricher = DeviceEnricher()
        enricher.update_from_unifi(
            devices=[],
            clients=[{"ip": "1.2.3.4", "mac": "aa:bb:cc:dd:ee:ff",
                      "name": "Test", "hostname": "", "network": "",
                      "is_wired": True, "oui": ""}],
        )
        result = enricher.lookup("1.2.3.4")
        assert result is not None
        assert result["name"] == "Test"
```

## Project Conventions

- **Python style:** Standard Python conventions, type hints where helpful
- **Config files:** YAML for Vector/Loki/Grafana provisioning, SQL for ClickHouse, JSON for Grafana dashboards
- **Naming:** snake_case for Python, snake_case for ClickHouse columns, kebab-case for Docker service names
- **Severity scale:** 1-10 (1-4 info, 5-7 warning, 8-10 critical)
- **Time windows:** Always use `{window}` placeholder in correlation rules for consistency
