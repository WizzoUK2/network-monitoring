"""Alert notifier: pushes detected anomalies and correlated events
to Alertmanager and records them in ClickHouse.
"""

import json
import logging
from datetime import datetime, timezone

import httpx

from analyzer.alerts.detector import Anomaly

logger = logging.getLogger("analyzer.alerts.notifier")


class AlertNotifier:
    def __init__(self, alertmanager_url: str, clickhouse):
        self.alertmanager_url = alertmanager_url.rstrip("/")
        self.ch = clickhouse
        self._http = httpx.AsyncClient(timeout=10.0)

    async def notify(self, anomalies: list[Anomaly]):
        """Send anomalies to Alertmanager and write to ClickHouse alerts table."""
        if not anomalies:
            return

        # Write to ClickHouse
        self._write_to_clickhouse(anomalies)

        # Push to Alertmanager
        await self._push_to_alertmanager(anomalies)

    def _write_to_clickhouse(self, anomalies: list[Anomaly]):
        now = datetime.now(tz=timezone.utc)
        rows = []
        for a in anomalies:
            rows.append([
                now,
                a.name,
                a.severity,
                a.description,
                a.source_ip,
                json.dumps(a.details),
            ])

        try:
            self.ch.insert(
                "correlated_events",
                rows,
                column_names=[
                    "timestamp", "rule_name", "severity",
                    "description", "source_ips", "details",
                ],
            )
            logger.info("Wrote %d anomaly events to ClickHouse", len(rows))
        except Exception:
            logger.error("Failed to write anomalies to ClickHouse", exc_info=True)

    async def _push_to_alertmanager(self, anomalies: list[Anomaly]):
        """Push alerts to Alertmanager's v2 API."""
        alerts = []
        for a in anomalies:
            alerts.append({
                "labels": {
                    "alertname": a.name,
                    "severity": self._severity_label(a.severity),
                    "source_ip": a.source_ip,
                    "service": "netmon",
                },
                "annotations": {
                    "summary": a.description,
                    "details": json.dumps(a.details),
                },
                "generatorURL": "http://localhost:3000/d/netmon-events",
            })

        try:
            resp = await self._http.post(
                f"{self.alertmanager_url}/api/v2/alerts",
                json=alerts,
            )
            if resp.status_code == 200:
                logger.info("Pushed %d alerts to Alertmanager", len(alerts))
            else:
                logger.warning(
                    "Alertmanager returned %d: %s", resp.status_code, resp.text
                )
        except httpx.ConnectError:
            logger.warning("Cannot reach Alertmanager at %s", self.alertmanager_url)
        except Exception:
            logger.error("Failed to push alerts to Alertmanager", exc_info=True)

    @staticmethod
    def _severity_label(severity: int) -> str:
        if severity >= 8:
            return "critical"
        if severity >= 5:
            return "warning"
        return "info"

    async def close(self):
        await self._http.aclose()
