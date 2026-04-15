#!/usr/bin/env bash
# Health check all network monitoring services
# Usage: ./scripts/verify.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC} $1"; }
fail() { echo -e "  ${RED}FAIL${NC} $1"; }
warn() { echo -e "  ${YELLOW}WARN${NC} $1"; }

echo "=== Network Monitoring Stack Health Check ==="
echo ""

# Check Docker containers are running
echo "Docker Containers:"
for svc in netmon-vector netmon-goflow2 netmon-clickhouse netmon-loki netmon-grafana; do
  if docker ps --format '{{.Names}}' | grep -q "^${svc}$"; then
    pass "$svc is running"
  else
    fail "$svc is NOT running"
  fi
done

echo ""
echo "Service Health Endpoints:"

# Vector health
if curl -sf http://localhost:8686/health > /dev/null 2>&1; then
  pass "Vector API (http://localhost:8686/health)"
else
  fail "Vector API not responding"
fi

# Loki readiness
if curl -sf http://localhost:3100/ready > /dev/null 2>&1; then
  pass "Loki (http://localhost:3100/ready)"
else
  fail "Loki not ready"
fi

# ClickHouse
CH_RESULT=$(curl -sf "http://localhost:8123/?query=SELECT+1" 2>/dev/null)
if [ "$CH_RESULT" = "1" ]; then
  pass "ClickHouse HTTP (http://localhost:8123)"
else
  fail "ClickHouse not responding"
fi

# ClickHouse schema
CH_TABLES=$(curl -sf "http://localhost:8123/?query=SELECT+count()+FROM+system.tables+WHERE+database='netmon'" 2>/dev/null)
if [ -n "$CH_TABLES" ] && [ "$CH_TABLES" -gt 0 ] 2>/dev/null; then
  pass "ClickHouse netmon database has ${CH_TABLES} tables"
else
  warn "ClickHouse netmon database may not be initialized"
fi

# Grafana
if curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
  pass "Grafana (http://localhost:3000/api/health)"
else
  fail "Grafana not responding"
fi

echo ""
echo "Data Check:"

# Check if any flows exist
FLOW_COUNT=$(curl -sf "http://localhost:8123/?user=netmon&password=changeme&query=SELECT+count()+FROM+netmon.flows" 2>/dev/null || echo "error")
if [ "$FLOW_COUNT" = "error" ]; then
  warn "Could not query flow count"
elif [ "$FLOW_COUNT" -gt 0 ] 2>/dev/null; then
  pass "Flows in ClickHouse: ${FLOW_COUNT}"
else
  warn "No flow data yet (configure NetFlow on your devices or run scripts/test-netflow.sh)"
fi

# Check if any syslog exists in Loki
LOKI_RESULT=$(curl -sf 'http://localhost:3100/loki/api/v1/query?query=count_over_time({source=~".%2B"}[24h])&limit=1' 2>/dev/null)
if echo "$LOKI_RESULT" | grep -q '"result"'; then
  pass "Loki is queryable"
else
  warn "No syslog data yet (configure syslog on your devices or run scripts/test-syslog.sh)"
fi

echo ""
echo "=== Quick Links ==="
echo "  Grafana:           http://localhost:3000  (admin / changeme)"
echo "  Network Overview:  http://localhost:3000/d/netmon-overview"
echo "  Syslog Explorer:   http://localhost:3000/d/netmon-syslog"
echo "  Vector API:        http://localhost:8686"
echo "  ClickHouse HTTP:   http://localhost:8123"
echo "  Loki:              http://localhost:3100"
