"""Device enrichment: maps IP addresses to device names and metadata
using data from the UniFi controller.

Maintains an in-memory cache that is updated each polling cycle.
"""

import logging
from threading import Lock

logger = logging.getLogger("analyzer.enrichment.device")


class DeviceEnricher:
    def __init__(self):
        self._lock = Lock()
        # ip -> {name, mac, type, model, network, ...}
        self._ip_cache: dict[str, dict] = {}
        # mac -> {name, ip, type, model, ...}
        self._mac_cache: dict[str, dict] = {}

    def update_from_unifi(self, devices: list[dict], clients: list[dict]):
        """Rebuild the cache from fresh UniFi API data."""
        new_ip: dict[str, dict] = {}
        new_mac: dict[str, dict] = {}

        # Infrastructure devices (APs, switches, gateways)
        for d in devices:
            ip = d.get("ip", "")
            mac = d.get("mac", "")
            info = {
                "name": d.get("name", ""),
                "mac": mac,
                "ip": ip,
                "type": d.get("type", ""),
                "model": d.get("model", ""),
                "is_infrastructure": True,
            }
            if ip:
                new_ip[ip] = info
            if mac:
                new_mac[mac.lower()] = info

        # Client devices
        for c in clients:
            ip = c.get("ip", "")
            mac = c.get("mac", "")
            # Prefer the user-assigned name, fall back to hostname
            name = c.get("name") or c.get("hostname") or ""
            info = {
                "name": name,
                "mac": mac,
                "ip": ip,
                "network": c.get("network", ""),
                "is_wired": c.get("is_wired", False),
                "oui": c.get("oui", ""),
                "is_infrastructure": False,
            }
            if ip:
                new_ip[ip] = info
            if mac:
                new_mac[mac.lower()] = info

        with self._lock:
            self._ip_cache = new_ip
            self._mac_cache = new_mac

        logger.debug(
            "Device cache updated: %d IPs, %d MACs",
            len(new_ip),
            len(new_mac),
        )

    def lookup(self, ip: str) -> dict | None:
        """Look up device info by IP address."""
        with self._lock:
            return self._ip_cache.get(ip)

    def lookup_mac(self, mac: str) -> dict | None:
        """Look up device info by MAC address."""
        with self._lock:
            return self._mac_cache.get(mac.lower())

    def get_all_devices(self) -> dict[str, dict]:
        """Return the full IP→device mapping (snapshot)."""
        with self._lock:
            return dict(self._ip_cache)
