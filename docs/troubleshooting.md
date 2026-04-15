# Troubleshooting

Common issues and their solutions.

## Quick Diagnostics

Run the health check script first:

```bash
./scripts/verify.sh
```

Check logs for any failing service:

```bash
docker logs netmon-vector
docker logs netmon-goflow2
docker logs netmon-clickhouse
docker logs netmon-loki
docker logs netmon-grafana
docker logs netmon-analyzer    # Phase 2+
docker logs netmon-zeek        # Phase 2+
docker logs netmon-alertmanager # Phase 3
```

## Service Issues

### Container Won't Start

**Symptom:** `docker compose up -d` shows a container restarting or exited.

**Diagnosis:**
```bash
docker compose ps                    # Check container states
docker logs <container-name>         # Check error output
docker inspect <container-name>      # Check configuration
```

**Common causes:**
- **Port already in use:** Another service is using port 514, 2055, 3000, etc.
  ```bash
  sudo ss -ulnp | grep 514    # Check what's using port 514
  ```
  Fix: Stop the conflicting service or change ports in `.env`.

- **Insufficient memory:** ClickHouse or Loki may fail with OOM.
  ```bash
  docker stats                 # Check memory usage per container
  ```
  Fix: Increase system memory or reduce the number of active phases.

- **Volume permissions:** ClickHouse or Loki can't write to volumes.
  ```bash
  docker volume ls             # List volumes
  docker compose down -v       # Reset volumes (DESTROYS DATA)
  docker compose up -d
  ```

### Vector Not Receiving Syslog

**Symptom:** No data in Loki. Grafana Syslog Explorer shows nothing.

**Checks:**
1. Vector is running and listening:
   ```bash
   docker logs netmon-vector | grep "Listening"
   curl http://localhost:8686/health
   ```

2. UDP port 514 is reachable from your network:
   ```bash
   # From the monitoring server itself:
   echo "test" | nc -u -w1 localhost 514

   # From another machine:
   echo "test" | nc -u -w1 <monitoring-server-ip> 514
   ```

3. Firewall is not blocking UDP 514:
   ```bash
   sudo iptables -L -n | grep 514
   sudo ufw status | grep 514
   ```

4. Send test data and check Loki directly:
   ```bash
   ./scripts/test-syslog.sh
   curl 'http://localhost:3100/loki/api/v1/query?query={source=~".%2B"}&limit=5'
   ```

### GoFlow2 Not Receiving NetFlow

**Symptom:** No data in ClickHouse `flows` table.

**Checks:**
1. GoFlow2 is running:
   ```bash
   docker logs netmon-goflow2
   ```

2. NetFlow data is arriving:
   ```bash
   # Check if UDP packets are arriving on port 2055
   sudo tcpdump -i any udp port 2055 -c 5
   ```

3. GoFlow2 is writing output:
   ```bash
   # Check if the JSON output file is growing
   docker exec netmon-goflow2 ls -la /var/lib/goflow2/
   ```

4. Vector is reading the output:
   ```bash
   docker logs netmon-vector | grep goflow
   ```

5. ClickHouse has data:
   ```bash
   docker exec netmon-clickhouse clickhouse-client \
     --query "SELECT count() FROM netmon.flows"
   ```

### ClickHouse Schema Not Initialized

**Symptom:** Queries fail with "Table netmon.flows doesn't exist".

**Fix:** Run the init script manually:
```bash
docker exec -i netmon-clickhouse clickhouse-client < config/clickhouse/init-db.sql
```

Or restart with a fresh volume:
```bash
docker compose down
docker volume rm network-monitoring_clickhouse-data
docker compose up -d
```

### Grafana Shows "No Data"

**Causes and fixes:**

1. **Datasource not connected:** Go to Grafana > Settings > Data Sources > test each connection.

2. **ClickHouse credentials wrong:** The Grafana datasource password must match `CLICKHOUSE_PASSWORD` in `.env`. Edit `config/grafana/provisioning/datasources/datasources.yaml` and restart:
   ```bash
   docker compose restart grafana
   ```

3. **Time range too narrow:** Expand the Grafana time picker to "Last 24 hours" or "Last 7 days".

4. **No data ingested yet:** Run test scripts:
   ```bash
   ./scripts/test-syslog.sh
   ./scripts/test-netflow.sh
   ```

5. **Dashboard queries reference Phase 2 tables but only Phase 1 is running:** The Client Health, DNS Analysis, and Correlated Events dashboards require Phase 2. Network Overview and Syslog Explorer work with Phase 1 alone.

### Loki Returns Empty Results

**Checks:**
1. Loki is ready:
   ```bash
   curl http://localhost:3100/ready
   ```

2. Data exists:
   ```bash
   curl 'http://localhost:3100/loki/api/v1/label' | python3 -m json.tool
   ```

3. Query syntax is correct. In Grafana Explore, try:
   ```
   {source=~".+"}
   ```

### ClickHouse Running Slowly

**Symptom:** Dashboard queries take more than a few seconds.

**Diagnosis:**
```bash
# Check system resources
docker exec netmon-clickhouse clickhouse-client \
  --query "SELECT * FROM system.metrics WHERE metric LIKE '%Memory%'"

# Check table sizes
docker exec netmon-clickhouse clickhouse-client \
  --query "SELECT table, formatReadableSize(sum(bytes_on_disk)) AS size, sum(rows) AS rows FROM system.parts WHERE database = 'netmon' AND active GROUP BY table ORDER BY sum(bytes_on_disk) DESC"
```

**Fixes:**
- Ensure dashboard queries use `flows_5m` or `flows_hourly` instead of raw `flows` table
- Reduce the time range in the dashboard
- Add more aggressive TTL to reduce data volume:
  ```sql
  ALTER TABLE netmon.flows MODIFY TTL time_received + INTERVAL 30 DAY
  ```

## Phase 2 Issues

### Analyzer Can't Connect to UniFi Controller

**Symptom:** `/api/unifi/devices` returns an error.

**Checks:**
1. Controller is reachable from the Docker network:
   ```bash
   docker exec netmon-analyzer curl -k https://192.168.1.1
   ```

2. Credentials are correct:
   ```bash
   docker exec netmon-analyzer curl -k -X POST \
     https://192.168.1.1/api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"your-password"}'
   ```

3. The account is a **local admin**, not a UI.com cloud account. Cloud accounts use a different auth flow that isn't supported.

4. Check analyzer logs:
   ```bash
   docker logs netmon-analyzer 2>&1 | grep -i unifi
   ```

### Zeek Not Processing PCAPs

**Symptom:** PCAP files in `data/pcaps/` but no data in ClickHouse `zeek_conn`/`zeek_dns`.

**Checks:**
1. Zeek is running:
   ```bash
   docker logs netmon-zeek
   ```

2. PCAP files are accessible:
   ```bash
   docker exec netmon-zeek ls -la /pcaps/
   ```

3. Zeek output exists:
   ```bash
   docker exec netmon-zeek ls -la /zeek-logs/
   ```

4. Vector is reading Zeek logs:
   ```bash
   docker logs netmon-vector 2>&1 | grep zeek
   ```

**Common issues:**
- PCAP files must have `.pcap` or `.pcapng` extension
- Zeek marks processed files; delete the `.processed_*` markers to reprocess:
  ```bash
  docker exec netmon-zeek rm /zeek-logs/.processed_*
  ```

### Enrichment Cache Empty

**Symptom:** API returns raw IPs instead of device names.

The enrichment cache is populated by the UniFi poller. If the controller isn't configured or reachable, the cache will be empty.

**Check:**
```bash
curl http://localhost:8080/api/stats/summary
# Look at "known_devices" and "dns_cache_size"
```

**Fixes:**
- Configure the UniFi controller in `.env`
- Wait for the next polling cycle (every 60 seconds)
- Check analyzer logs for polling errors:
  ```bash
  docker logs netmon-analyzer 2>&1 | grep poll
  ```

## Phase 3 Issues

### Alertmanager Not Receiving Alerts

**Checks:**
1. `ANOMALY_DETECTION_ENABLED=true` is set in `.env`
2. Alertmanager is running:
   ```bash
   curl http://localhost:9093/-/healthy
   ```
3. Test the pipeline:
   ```bash
   curl -X POST http://localhost:8080/api/alerts/test
   curl http://localhost:9093/api/v2/alerts
   ```

### InfluxDB Not Receiving Data

**Checks:**
1. InfluxDB is healthy:
   ```bash
   docker exec netmon-influxdb influx ping
   ```
2. Vector Phase 3 config is loaded:
   ```bash
   docker logs netmon-vector 2>&1 | grep influx
   ```
3. Query InfluxDB:
   ```bash
   docker exec netmon-influxdb influx query \
     'from(bucket:"network") |> range(start:-1h) |> count()' \
     --org netmon --token netmon-influx-token
   ```

## Data Recovery

### Restoring from Scratch

If data volumes are corrupted:

```bash
# Stop everything
docker compose -f docker-compose.yml -f docker-compose.phase2.yml -f docker-compose.phase3.yml down

# Remove all volumes
docker volume rm $(docker volume ls -q | grep netmon)

# Restart (schemas will be recreated)
docker compose up -d
```

### Backing Up ClickHouse Data

```bash
# Export a table to CSV
docker exec netmon-clickhouse clickhouse-client \
  --query "SELECT * FROM netmon.flows FORMAT CSVWithNames" > flows_backup.csv

# Export schema only
docker exec netmon-clickhouse clickhouse-client \
  --query "SHOW CREATE TABLE netmon.flows" > flows_schema.sql
```

## Getting Help

If you've checked the relevant section above and are still stuck:

1. Check the Docker logs for the specific failing service
2. Search the [GitHub Issues](https://github.com/WizzoUK2/network-monitoring/issues)
3. Open a new issue with:
   - Your Docker Compose phase (1, 2, or 3)
   - Output of `./scripts/verify.sh`
   - Relevant Docker logs
   - What you expected vs what happened
