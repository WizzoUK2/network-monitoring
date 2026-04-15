"""Periodic poller that fetches device and client data from UniFi
and writes it to ClickHouse for enrichment and historical tracking.
"""

import logging
from datetime import datetime, timezone

from analyzer.enrichment.device import DeviceEnricher
from analyzer.unifi.client import UniFiClient

logger = logging.getLogger("analyzer.unifi.poller")


class UniFiPoller:
    def __init__(self, unifi: UniFiClient, clickhouse, device_enricher: DeviceEnricher):
        self.unifi = unifi
        self.ch = clickhouse
        self.device_enricher = device_enricher

    async def poll(self):
        """Run a single poll cycle: fetch devices + clients, write to ClickHouse, update enrichment cache."""
        now = datetime.now(tz=timezone.utc)
        logger.info("Polling UniFi controller...")

        try:
            devices = await self.unifi.get_devices()
            clients = await self.unifi.get_clients()
        except Exception:
            logger.error("Failed to poll UniFi controller", exc_info=True)
            return

        logger.info("Polled %d devices, %d clients", len(devices), len(clients))

        # Update the in-memory device enrichment cache
        self.device_enricher.update_from_unifi(devices, clients)

        # Write devices to ClickHouse
        if devices:
            self._insert_devices(now, devices)

        # Write clients to ClickHouse
        if clients:
            self._insert_clients(now, clients)

    def _insert_devices(self, now: datetime, devices: list[dict]):
        rows = []
        for d in devices:
            rows.append(
                [
                    now,
                    d["mac"],
                    d["ip"],
                    d["name"],
                    d["model"],
                    d["type"],
                    d["version"],
                    d["uptime"],
                    d["state"],
                    float(d["cpu_usage"]),
                    float(d["mem_usage"]),
                    d["tx_bytes"],
                    d["rx_bytes"],
                    d["num_clients"],
                ]
            )

        try:
            self.ch.insert(
                "unifi_devices",
                rows,
                column_names=[
                    "timestamp",
                    "mac",
                    "ip",
                    "name",
                    "model",
                    "type",
                    "version",
                    "uptime",
                    "state",
                    "cpu_usage",
                    "mem_usage",
                    "tx_bytes",
                    "rx_bytes",
                    "num_clients",
                ],
            )
        except Exception:
            logger.error("Failed to insert device data into ClickHouse", exc_info=True)

    def _insert_clients(self, now: datetime, clients: list[dict]):
        rows = []
        for c in clients:
            rows.append(
                [
                    now,
                    c["mac"],
                    c["ip"],
                    c["hostname"],
                    c["name"],
                    c["network"],
                    1 if c["is_wired"] else 0,
                    c.get("signal") or 0,
                    c.get("channel") or 0,
                    c.get("radio") or "",
                    c["experience"],
                    c["tx_bytes"],
                    c["rx_bytes"],
                    c["tx_rate"],
                    c["rx_rate"],
                    c["uptime"],
                    c["ap_mac"],
                ]
            )

        try:
            self.ch.insert(
                "unifi_clients",
                rows,
                column_names=[
                    "timestamp",
                    "mac",
                    "ip",
                    "hostname",
                    "name",
                    "network",
                    "is_wired",
                    "signal",
                    "channel",
                    "radio",
                    "experience",
                    "tx_bytes",
                    "rx_bytes",
                    "tx_rate",
                    "rx_rate",
                    "uptime",
                    "ap_mac",
                ],
            )
        except Exception:
            logger.error("Failed to insert client data into ClickHouse", exc_info=True)
