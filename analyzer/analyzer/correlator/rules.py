"""Correlation rules for detecting network issues.

Each rule is a dataclass that defines:
- name: unique identifier
- description: what the rule detects
- severity: 1-10 scale
- query: ClickHouse SQL to find matching events
- window_minutes: how far back to look
"""

from dataclasses import dataclass


@dataclass
class CorrelationRule:
    name: str
    description: str
    severity: int
    query: str
    window_minutes: int = 15


# Rules focused on connectivity and bandwidth issues (user's primary concerns)
RULES: list[CorrelationRule] = [
    CorrelationRule(
        name="port_scan_detection",
        description="Device connecting to many distinct destination ports in a short window",
        severity=6,
        window_minutes=5,
        query="""
            SELECT
                src_addr,
                count(DISTINCT dst_port) AS unique_ports,
                count() AS flow_count,
                sum(bytes) AS total_bytes,
                groupArray(DISTINCT dst_addr) AS targets
            FROM flows
            WHERE time_received >= now() - INTERVAL {window} MINUTE
              AND dst_port > 0
            GROUP BY src_addr
            HAVING unique_ports > 50
            ORDER BY unique_ports DESC
            LIMIT 20
        """,
    ),
    CorrelationRule(
        name="new_device_detected",
        description="IP address seen in flows that has no matching UniFi client record",
        severity=3,
        window_minutes=15,
        query="""
            SELECT DISTINCT src_addr AS ip
            FROM flows
            WHERE time_received >= now() - INTERVAL {window} MINUTE
              AND src_addr LIKE '192.168.%' OR src_addr LIKE '10.%' OR src_addr LIKE '172.%'
            EXCEPT
            SELECT ip
            FROM unifi_clients
            WHERE timestamp >= now() - INTERVAL 1 HOUR
        """,
    ),
    CorrelationRule(
        name="bandwidth_spike",
        description="Single source exceeding 100MB in a 5-minute window (potential bandwidth hog)",
        severity=5,
        window_minutes=5,
        query="""
            SELECT
                src_addr,
                sum(total_bytes) AS bytes_5m,
                sum(total_packets) AS packets_5m
            FROM flows_5m
            WHERE timeslot >= now() - INTERVAL {window} MINUTE
            GROUP BY src_addr
            HAVING bytes_5m > 104857600
            ORDER BY bytes_5m DESC
            LIMIT 10
        """,
    ),
    CorrelationRule(
        name="dns_failure_burst",
        description="High rate of DNS queries with no answer (potential DNS resolution issues)",
        severity=7,
        window_minutes=10,
        query="""
            SELECT
                src_addr,
                count() AS query_count,
                countIf(answers = '[]' OR answers = '') AS unanswered
            FROM zeek_dns
            WHERE ts >= now() - INTERVAL {window} MINUTE
            GROUP BY src_addr
            HAVING unanswered > 20 AND unanswered > query_count * 0.5
            ORDER BY unanswered DESC
            LIMIT 10
        """,
    ),
    CorrelationRule(
        name="connection_flood",
        description="Excessive new connections from a single source (potential connectivity issue or misconfiguration)",
        severity=6,
        window_minutes=5,
        query="""
            SELECT
                src_addr,
                count() AS conn_count,
                count(DISTINCT dst_addr) AS unique_dsts,
                count(DISTINCT dst_port) AS unique_ports
            FROM flows
            WHERE time_received >= now() - INTERVAL {window} MINUTE
            GROUP BY src_addr
            HAVING conn_count > 1000
            ORDER BY conn_count DESC
            LIMIT 10
        """,
    ),
    CorrelationRule(
        name="client_wifi_poor_signal",
        description="WiFi clients with consistently poor signal strength (potential coverage issue)",
        severity=4,
        window_minutes=30,
        query="""
            SELECT
                mac,
                ip,
                name,
                hostname,
                avg(signal) AS avg_signal,
                min(signal) AS min_signal,
                count() AS sample_count,
                any(ap_mac) AS connected_ap
            FROM unifi_clients
            WHERE timestamp >= now() - INTERVAL {window} MINUTE
              AND is_wired = 0
              AND signal < 0
            GROUP BY mac, ip, name, hostname
            HAVING avg_signal < -75
            ORDER BY avg_signal ASC
            LIMIT 20
        """,
    ),
    CorrelationRule(
        name="high_retransmit_flow",
        description="Flows with TCP flags indicating retransmissions (connectivity quality issue)",
        severity=5,
        window_minutes=15,
        query="""
            SELECT
                src_addr,
                dst_addr,
                dst_port,
                count() AS flow_count,
                sum(packets) AS total_packets,
                sum(bytes) AS total_bytes
            FROM flows
            WHERE time_received >= now() - INTERVAL {window} MINUTE
              AND proto = 6
              AND packets > 0
              AND bytes / packets < 100
            GROUP BY src_addr, dst_addr, dst_port
            HAVING flow_count > 50
            ORDER BY flow_count DESC
            LIMIT 20
        """,
    ),
    CorrelationRule(
        name="external_data_exfil",
        description="Large data transfer to a single external IP (unusual outbound volume)",
        severity=7,
        window_minutes=60,
        query="""
            SELECT
                src_addr,
                dst_addr,
                sum(bytes) AS total_bytes,
                sum(packets) AS total_packets,
                count() AS flow_count
            FROM flows
            WHERE time_received >= now() - INTERVAL {window} MINUTE
              AND NOT (dst_addr LIKE '192.168.%' OR dst_addr LIKE '10.%' OR dst_addr LIKE '172.16.%')
              AND NOT (dst_addr LIKE '224.%' OR dst_addr LIKE '255.%')
            GROUP BY src_addr, dst_addr
            HAVING total_bytes > 524288000
            ORDER BY total_bytes DESC
            LIMIT 10
        """,
    ),
]
