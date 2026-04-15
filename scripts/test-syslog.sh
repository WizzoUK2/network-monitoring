#!/usr/bin/env bash
# Send test syslog messages to Vector (UDP 514)
# Usage: ./scripts/test-syslog.sh [host] [port]

HOST="${1:-localhost}"
PORT="${2:-514}"

echo "Sending test syslog messages to ${HOST}:${PORT}..."

# Test 1: UniFi CEF firewall event
echo '<14>CEF:0|Ubiquiti|UniFi|1.0|2000|Firewall Rule Allow|3|src=192.168.1.100 dst=8.8.8.8 spt=54321 dpt=443 proto=TCP act=allow' \
  | nc -u -w1 "$HOST" "$PORT"
echo "  Sent: CEF firewall allow event (192.168.1.100 -> 8.8.8.8:443)"

# Test 2: UniFi CEF firewall block
echo '<10>CEF:0|Ubiquiti|UniFi|1.0|2001|Firewall Rule Block|7|src=10.0.0.50 dst=203.0.113.10 spt=12345 dpt=22 proto=TCP act=block reason=Intrusion' \
  | nc -u -w1 "$HOST" "$PORT"
echo "  Sent: CEF firewall block event (10.0.0.50 -> 203.0.113.10:22)"

# Test 3: UniFi CEF client event
echo '<14>CEF:0|Ubiquiti|UniFi|1.0|3000|Client Connected|3|src=192.168.1.150 shost=Craigs-iPhone' \
  | nc -u -w1 "$HOST" "$PORT"
echo "  Sent: CEF client connected event"

# Test 4: UniFi CEF IPS event
echo '<10>CEF:0|Ubiquiti|UniFi-IPS|1.0|4000|IPS Alert|8|src=198.51.100.5 dst=192.168.1.1 spt=80 dpt=443 proto=TCP act=alert reason=ET_SCAN_Nmap' \
  | nc -u -w1 "$HOST" "$PORT"
echo "  Sent: CEF IPS alert event"

# Test 5: Plain syslog (non-CEF, from a generic device)
echo '<134>Apr 15 12:00:00 switch01 kernel: eth0: link up, speed 1000 Mbps, full duplex' \
  | nc -u -w1 "$HOST" "$PORT"
echo "  Sent: Plain syslog link-up event"

# Test 6: DHCP event
echo '<14>CEF:0|Ubiquiti|UniFi|1.0|5000|DHCP Lease|3|src=192.168.1.200 shost=living-room-tv smac=AA:BB:CC:DD:EE:FF' \
  | nc -u -w1 "$HOST" "$PORT"
echo "  Sent: CEF DHCP lease event"

echo ""
echo "Done! Check Grafana Explore (http://localhost:3000/explore) with query:"
echo '  {source=~".+"}'
