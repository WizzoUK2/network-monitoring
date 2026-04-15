"""Anomaly detection engine.

Maintains rolling baselines of normal traffic patterns per device over 7-day
windows and flags deviations: new external IPs, unusual ports, bandwidth spikes,
device disappearances, and DNS resolution failures.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger("analyzer.alerts.detector")


@dataclass
class Anomaly:
    name: str
    severity: int  # 1-10
    description: str
    source_ip: str
    details: dict


class AnomalyDetector:
    def __init__(self, clickhouse):
        self.ch = clickhouse

    async def run(self) -> list[Anomaly]:
        """Run all anomaly detection checks and return any findings."""
        anomalies: list[Anomaly] = []

        checks = [
            self._check_bandwidth_anomalies,
            self._check_new_external_destinations,
            self._check_device_disappearances,
            self._check_dns_health,
            self._check_wifi_degradation,
        ]

        for check in checks:
            try:
                results = check()
                anomalies.extend(results)
            except Exception:
                logger.debug("Anomaly check '%s' failed", check.__name__, exc_info=True)

        if anomalies:
            logger.info("Anomaly detection found %d issues", len(anomalies))

        return anomalies

    def _check_bandwidth_anomalies(self) -> list[Anomaly]:
        """Detect devices using significantly more bandwidth than their 7-day baseline."""
        result = self.ch.query("""
            WITH baseline AS (
                SELECT
                    src_addr,
                    avg(total_bytes) AS avg_bytes,
                    stddevPop(total_bytes) AS stddev_bytes
                FROM flows_5m
                WHERE timeslot >= now() - INTERVAL 7 DAY
                  AND timeslot < now() - INTERVAL 1 HOUR
                GROUP BY src_addr
                HAVING count() > 100
            ),
            recent AS (
                SELECT
                    src_addr,
                    sum(total_bytes) AS recent_bytes
                FROM flows_5m
                WHERE timeslot >= now() - INTERVAL 30 MINUTE
                GROUP BY src_addr
            )
            SELECT
                r.src_addr,
                r.recent_bytes,
                b.avg_bytes,
                b.stddev_bytes,
                (r.recent_bytes - b.avg_bytes) / greatest(b.stddev_bytes, 1) AS z_score
            FROM recent r
            JOIN baseline b ON r.src_addr = b.src_addr
            WHERE r.recent_bytes > b.avg_bytes + 3 * greatest(b.stddev_bytes, 1000000)
            ORDER BY z_score DESC
            LIMIT 10
        """)

        anomalies = []
        for row in result.result_rows:
            src, recent, avg, stddev, z = row
            anomalies.append(Anomaly(
                name="bandwidth_anomaly",
                severity=min(8, max(4, int(z))),
                description=f"Device {src} using {recent / 1_000_000:.1f}MB in last 30m "
                            f"(baseline: {avg / 1_000_000:.1f}MB avg, z-score: {z:.1f})",
                source_ip=str(src),
                details={"recent_bytes": int(recent), "avg_bytes": float(avg),
                         "stddev_bytes": float(stddev), "z_score": float(z)},
            ))
        return anomalies

    def _check_new_external_destinations(self) -> list[Anomaly]:
        """Detect internal devices talking to external IPs not seen in the last 7 days."""
        result = self.ch.query("""
            SELECT
                src_addr,
                groupArray(dst_addr) AS new_dsts,
                sum(bytes) AS total_bytes
            FROM flows
            WHERE time_received >= now() - INTERVAL 30 MINUTE
              AND (src_addr LIKE '192.168.%' OR src_addr LIKE '10.%')
              AND NOT (dst_addr LIKE '192.168.%' OR dst_addr LIKE '10.%'
                       OR dst_addr LIKE '172.16.%' OR dst_addr LIKE '224.%'
                       OR dst_addr LIKE '255.%' OR dst_addr LIKE '239.%')
              AND dst_addr NOT IN (
                  SELECT DISTINCT dst_addr
                  FROM flows
                  WHERE time_received >= now() - INTERVAL 7 DAY
                    AND time_received < now() - INTERVAL 1 HOUR
              )
            GROUP BY src_addr
            HAVING length(new_dsts) >= 5
            ORDER BY length(new_dsts) DESC
            LIMIT 10
        """)

        anomalies = []
        for row in result.result_rows:
            src, new_dsts, total_bytes = row
            dst_list = new_dsts[:10]  # Cap display
            anomalies.append(Anomaly(
                name="new_external_destinations",
                severity=5,
                description=f"Device {src} contacted {len(new_dsts)} new external IPs "
                            f"not seen in 7 days ({total_bytes / 1_000:.0f}KB transferred)",
                source_ip=str(src),
                details={"new_destinations": [str(d) for d in dst_list],
                         "count": len(new_dsts), "total_bytes": int(total_bytes)},
            ))
        return anomalies

    def _check_device_disappearances(self) -> list[Anomaly]:
        """Detect devices that were active recently but have stopped appearing in polls."""
        result = self.ch.query("""
            SELECT
                mac, ip, name, hostname,
                max(timestamp) AS last_seen,
                dateDiff('minute', max(timestamp), now()) AS minutes_ago
            FROM unifi_clients
            WHERE timestamp >= now() - INTERVAL 24 HOUR
            GROUP BY mac, ip, name, hostname
            HAVING last_seen < now() - INTERVAL 30 MINUTE
               AND last_seen > now() - INTERVAL 6 HOUR
            ORDER BY last_seen DESC
            LIMIT 20
        """)

        anomalies = []
        for row in result.result_rows:
            mac, ip, name, hostname, last_seen, minutes_ago = row
            display_name = name or hostname or mac
            anomalies.append(Anomaly(
                name="device_disappeared",
                severity=3,
                description=f"Device '{display_name}' ({ip}) last seen {minutes_ago}m ago",
                source_ip=str(ip),
                details={"mac": str(mac), "name": str(display_name),
                         "last_seen": str(last_seen), "minutes_ago": int(minutes_ago)},
            ))
        return anomalies

    def _check_dns_health(self) -> list[Anomaly]:
        """Detect high DNS failure rates indicating resolution problems."""
        result = self.ch.query("""
            SELECT
                src_addr,
                count() AS total_queries,
                countIf(rcode_name != 'NOERROR' AND rcode_name != '') AS failed_queries,
                groupArray(10)(query) AS sample_queries
            FROM zeek_dns
            WHERE ts >= now() - INTERVAL 15 MINUTE
            GROUP BY src_addr
            HAVING total_queries > 10 AND failed_queries > total_queries * 0.3
            ORDER BY failed_queries DESC
            LIMIT 10
        """)

        anomalies = []
        for row in result.result_rows:
            src, total, failed, samples = row
            pct = (failed / total * 100) if total > 0 else 0
            anomalies.append(Anomaly(
                name="dns_failure_rate",
                severity=7 if pct > 50 else 5,
                description=f"Device {src} has {pct:.0f}% DNS failure rate "
                            f"({failed}/{total} queries in 15m)",
                source_ip=str(src),
                details={"total_queries": int(total), "failed_queries": int(failed),
                         "failure_pct": float(pct),
                         "sample_queries": [str(q) for q in (samples or [])]},
            ))
        return anomalies

    def _check_wifi_degradation(self) -> list[Anomaly]:
        """Detect WiFi clients whose signal has degraded vs their baseline."""
        result = self.ch.query("""
            WITH baseline AS (
                SELECT mac, avg(signal) AS avg_signal
                FROM unifi_clients
                WHERE timestamp >= now() - INTERVAL 7 DAY
                  AND timestamp < now() - INTERVAL 1 HOUR
                  AND is_wired = 0 AND signal < 0
                GROUP BY mac
                HAVING count() > 50
            ),
            recent AS (
                SELECT mac, ip, name, hostname, avg(signal) AS current_signal, any(ap_mac) AS ap
                FROM unifi_clients
                WHERE timestamp >= now() - INTERVAL 30 MINUTE
                  AND is_wired = 0 AND signal < 0
                GROUP BY mac, ip, name, hostname
            )
            SELECT
                r.mac, r.ip, r.name, r.hostname,
                r.current_signal, b.avg_signal,
                r.current_signal - b.avg_signal AS delta,
                r.ap
            FROM recent r
            JOIN baseline b ON r.mac = b.mac
            WHERE r.current_signal < b.avg_signal - 10
            ORDER BY delta ASC
            LIMIT 10
        """)

        anomalies = []
        for row in result.result_rows:
            mac, ip, name, hostname, current, baseline, delta, ap = row
            display = name or hostname or mac
            anomalies.append(Anomaly(
                name="wifi_signal_degraded",
                severity=4 if delta > -15 else 6,
                description=f"'{display}' WiFi signal degraded by {abs(delta):.0f}dBm "
                            f"(now: {current:.0f} dBm, baseline: {baseline:.0f} dBm)",
                source_ip=str(ip),
                details={"mac": str(mac), "current_signal": float(current),
                         "baseline_signal": float(baseline), "delta": float(delta),
                         "ap_mac": str(ap)},
            ))
        return anomalies
