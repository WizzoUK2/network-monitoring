#!/usr/bin/env bash
# First-time setup for the network monitoring stack
# Usage: ./scripts/setup.sh

set -e

echo "=== Network Monitoring Stack Setup ==="
echo ""

# Check prerequisites
echo "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required but not installed."; exit 1; }
command -v docker compose >/dev/null 2>&1 || { echo "ERROR: docker compose (v2) is required."; exit 1; }
echo "  docker: $(docker --version)"
echo "  docker compose: $(docker compose version)"

# Create .env from example if it doesn't exist
if [ ! -f .env ]; then
  echo ""
  echo "Creating .env from .env.example..."
  cp .env.example .env
  echo "  IMPORTANT: Edit .env to set your passwords and UniFi controller details"
fi

# Create data directories
echo ""
echo "Creating data directories..."
mkdir -p data/{clickhouse,loki,grafana,pcaps}
echo "  Created data/{clickhouse,loki,grafana,pcaps}"

# Pull images
echo ""
echo "Pulling Docker images..."
docker compose pull

# Start the stack
echo ""
echo "Starting the stack..."
docker compose up -d

# Wait for services to be ready
echo ""
echo "Waiting for services to start..."
sleep 10

# Run health check
echo ""
./scripts/verify.sh

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit .env with your UniFi controller credentials and passwords"
echo "  2. Configure UniFi syslog: Settings > Control Plane > Integrations > SIEM Server"
echo "     Set server to $(hostname -I | awk '{print $1}'):514 (UDP)"
echo "  3. Configure UniFi NetFlow: Settings > System > Traffic Logging > Enable NetFlow"
echo "     Set collector to $(hostname -I | awk '{print $1}'):2055"
echo "  4. Open Grafana: http://localhost:3000 (admin / changeme)"
echo "  5. Run test data: ./scripts/test-syslog.sh && ./scripts/test-netflow.sh"
