#!/usr/bin/env bash
# Send test NetFlow data to GoFlow2 using nflow-generator
# Usage: ./scripts/test-netflow.sh [host] [port] [duration]
#
# Requires Docker to run the nflow-generator container.

HOST="${1:-localhost}"
PORT="${2:-2055}"
DURATION="${3:-30}"

echo "Sending synthetic NetFlow v5 data to ${HOST}:${PORT} for ${DURATION}s..."
echo "(Using networkstatic/nflow-generator Docker image)"
echo ""

docker run --rm --network host \
  networkstatic/nflow-generator \
  -t "$HOST" -p "$PORT" &

GENERATOR_PID=$!

echo "Generator running (PID: ${GENERATOR_PID})..."
echo "Waiting ${DURATION} seconds..."
sleep "$DURATION"

kill "$GENERATOR_PID" 2>/dev/null
wait "$GENERATOR_PID" 2>/dev/null

echo ""
echo "Done! Check flows in ClickHouse:"
echo "  docker exec netmon-clickhouse clickhouse-client --query 'SELECT count() FROM netmon.flows'"
echo ""
echo "Or check Grafana Network Overview dashboard: http://localhost:3000/d/netmon-overview"
