# Installation Guide

Step-by-step instructions for setting up the network monitoring platform.

## Prerequisites

### Hardware Requirements

| Phase | Minimum RAM | Recommended RAM | Disk Space |
|-------|-------------|-----------------|------------|
| Phase 1 | 4 GB | 6 GB | 10 GB |
| Phase 1+2 | 6 GB | 8 GB | 20 GB |
| All phases | 8 GB | 16 GB | 50 GB+ |

Disk usage depends heavily on traffic volume and retention settings. A typical home network with 20-50 devices generates approximately:
- **NetFlow data:** 50-200 MB/day in ClickHouse
- **Syslog data:** 10-50 MB/day in Loki
- **Zeek logs:** 100-500 MB/day per GB/s of captured traffic
- **Full PCAP:** 1-10 GB/day (if capturing on a mirror port)

### Software Requirements

- **Docker Engine** 24.0 or later
- **Docker Compose** v2 (included with Docker Desktop, or install the `docker-compose-plugin` package)
- **Git** (to clone the repository)
- **netcat** (`nc`) for test scripts (usually pre-installed on Linux)

Verify your Docker installation:

```bash
docker --version          # Should be 24.0+
docker compose version    # Should be v2.x
```

### Network Requirements

The monitoring server needs to be reachable from your network devices on:

| Port | Protocol | Purpose | Required By |
|------|----------|---------|-------------|
| 514 | UDP | Syslog reception | Phase 1+ |
| 2055 | UDP | NetFlow/IPFIX reception | Phase 1+ |
| 6343 | UDP | sFlow reception | Phase 1+ (optional) |
| 3000 | TCP | Grafana web UI | All phases |
| 8080 | TCP | Analyzer REST API | Phase 2+ |
| 8123 | TCP | ClickHouse HTTP interface | All phases |
| 3100 | TCP | Loki API | All phases |
| 8086 | TCP | InfluxDB API | Phase 3 |
| 3001 | TCP | ntopng web UI | Phase 3 |
| 9093 | TCP | Alertmanager web UI | Phase 3 |

If your monitoring server has a firewall, ensure UDP ports 514 and 2055 are open for incoming traffic from your network devices.

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/WizzoUK2/network-monitoring.git
cd network-monitoring
```

### 2. Create Your Environment File

```bash
cp .env.example .env
```

Edit `.env` with your preferred editor. At minimum, change the default passwords:

```bash
# Required for all phases
CLICKHOUSE_PASSWORD=a-strong-password-here
GRAFANA_ADMIN_PASSWORD=another-strong-password

# Required for Phase 2 (UniFi API)
UNIFI_HOST=https://192.168.1.1
UNIFI_USERNAME=netmon-readonly
UNIFI_PASSWORD=your-unifi-password
```

See [Configuration Reference](configuration.md) for all available options.

### 3. Run the Setup Script

```bash
./scripts/setup.sh
```

This script:
1. Checks that Docker and Docker Compose are installed
2. Creates the `.env` file from `.env.example` if it doesn't exist
3. Creates required data directories
4. Pulls all Docker images
5. Starts the Phase 1 stack
6. Waits for services to initialize
7. Runs the health check

### 4. Verify the Installation

```bash
./scripts/verify.sh
```

You should see all services passing their health checks:

```
=== Network Monitoring Stack Health Check ===

Docker Containers:
  PASS netmon-vector is running
  PASS netmon-goflow2 is running
  PASS netmon-clickhouse is running
  PASS netmon-loki is running
  PASS netmon-grafana is running

Service Health Endpoints:
  PASS Vector API (http://localhost:8686/health)
  PASS Loki (http://localhost:3100/ready)
  PASS ClickHouse HTTP (http://localhost:8123)
  PASS ClickHouse netmon database has 5 tables
  PASS Grafana (http://localhost:3000/api/health)
```

### 5. Generate Test Data

Before configuring your actual network devices, verify the pipeline with synthetic data:

```bash
# Send test syslog messages
./scripts/test-syslog.sh

# Generate test NetFlow data (runs for 30 seconds)
./scripts/test-netflow.sh
```

Then check Grafana at `http://localhost:3000`:
- **Explore** > select **Loki** > query `{source=~".+"}` to see syslog events
- **Dashboards** > **Network Overview** to see flow data

### 6. Configure Your Network Devices

See [UniFi Setup](unifi-setup.md) for detailed instructions on pointing your UniFi devices at the monitoring server.

## Upgrading to Phase 2

Once Phase 1 is working:

```bash
# Build the analyzer image and start Phase 2 services
docker compose -f docker-compose.yml -f docker-compose.phase2.yml up -d --build
```

Verify the analyzer is running:

```bash
curl http://localhost:8080/api/health
# {"status":"ok","service":"netmon-analyzer"}
```

If you have a UniFi controller configured in `.env`, check that device polling works:

```bash
curl http://localhost:8080/api/unifi/devices
```

To process PCAP files, drop them into `data/pcaps/`:

```bash
cp /path/to/capture.pcap data/pcaps/
# Zeek processes it automatically within 10 seconds
```

## Upgrading to Phase 3

Update your `.env` to enable anomaly detection:

```bash
ANOMALY_DETECTION_ENABLED=true
```

Then start Phase 3:

```bash
docker compose -f docker-compose.yml -f docker-compose.phase2.yml -f docker-compose.phase3.yml up -d
```

Verify the alerting pipeline:

```bash
# Fire a test alert
curl -X POST http://localhost:8080/api/alerts/test

# Check Alertmanager received it
curl http://localhost:9093/api/v2/alerts
```

Access ntopng at `http://localhost:3001` for real-time traffic visibility.

## Uninstalling

```bash
# Stop all services
docker compose -f docker-compose.yml -f docker-compose.phase2.yml -f docker-compose.phase3.yml down

# Remove all data volumes (DESTROYS ALL COLLECTED DATA)
docker compose -f docker-compose.yml -f docker-compose.phase2.yml -f docker-compose.phase3.yml down -v

# Remove the project directory
cd .. && rm -rf network-monitoring
```
