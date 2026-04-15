"""UniFi Controller REST API client.

Handles authentication (cookie-based sessions) and provides methods to
retrieve devices, active clients, and alerts from the controller.
"""

import logging

import httpx

logger = logging.getLogger("analyzer.unifi")


class UniFiClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        site: str = "default",
        verify_ssl: bool = False,
    ):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.site = site
        self._client = httpx.AsyncClient(verify=verify_ssl, timeout=30.0)
        self._logged_in = False

    async def close(self):
        await self._client.aclose()

    async def _login(self):
        """Authenticate with the UniFi controller and store the session cookie."""
        url = f"{self.host}/api/login"
        payload = {"username": self.username, "password": self.password}

        resp = await self._client.post(url, json=payload)
        if resp.status_code == 200:
            self._logged_in = True
            logger.info("Logged in to UniFi controller at %s", self.host)
        else:
            # Try the newer UniFi OS auth endpoint
            url = f"{self.host}/api/auth/login"
            resp = await self._client.post(url, json=payload)
            if resp.status_code == 200:
                self._logged_in = True
                logger.info("Logged in to UniFi OS controller at %s", self.host)
            else:
                raise ConnectionError(
                    f"UniFi login failed (status {resp.status_code}): {resp.text}"
                )

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        """Make an authenticated request, re-logging in if the session expired."""
        if not self._logged_in:
            await self._login()

        url = f"{self.host}{path}"
        resp = await self._client.request(method, url, **kwargs)

        # Session expired - re-authenticate and retry
        if resp.status_code == 401:
            self._logged_in = False
            await self._login()
            resp = await self._client.request(method, url, **kwargs)

        resp.raise_for_status()
        data = resp.json()

        # UniFi API wraps data in {"meta": {"rc": "ok"}, "data": [...]}
        if isinstance(data, dict) and "data" in data:
            return data["data"]
        return data

    async def get_devices(self) -> list[dict]:
        """Get all adopted devices (APs, switches, gateways)."""
        raw = await self._request("GET", f"/api/s/{self.site}/stat/device")
        devices = []
        for d in raw:
            devices.append(
                {
                    "mac": d.get("mac", ""),
                    "name": d.get("name", d.get("model", "Unknown")),
                    "model": d.get("model", ""),
                    "type": d.get("type", ""),
                    "ip": d.get("ip", ""),
                    "version": d.get("version", ""),
                    "uptime": d.get("uptime", 0),
                    "state": d.get("state", 0),
                    "cpu_usage": d.get("system-stats", {}).get("cpu", "0"),
                    "mem_usage": d.get("system-stats", {}).get("mem", "0"),
                    "tx_bytes": d.get("tx_bytes", 0),
                    "rx_bytes": d.get("rx_bytes", 0),
                    "num_clients": d.get("num_sta", 0),
                }
            )
        return devices

    async def get_clients(self) -> list[dict]:
        """Get all currently active clients."""
        raw = await self._request("GET", f"/api/s/{self.site}/stat/sta")
        clients = []
        for c in raw:
            clients.append(
                {
                    "mac": c.get("mac", ""),
                    "ip": c.get("ip", ""),
                    "hostname": c.get("hostname", c.get("name", "")),
                    "name": c.get("name", c.get("hostname", "")),
                    "oui": c.get("oui", ""),
                    "network": c.get("network", ""),
                    "is_wired": c.get("is_wired", False),
                    "signal": c.get("signal", 0) if not c.get("is_wired") else None,
                    "channel": c.get("channel", 0) if not c.get("is_wired") else None,
                    "radio": c.get("radio", "") if not c.get("is_wired") else None,
                    "experience": c.get("satisfaction", 0),
                    "tx_bytes": c.get("tx_bytes", 0),
                    "rx_bytes": c.get("rx_bytes", 0),
                    "tx_rate": c.get("tx_rate", 0),
                    "rx_rate": c.get("rx_rate", 0),
                    "uptime": c.get("uptime", 0),
                    "ap_mac": c.get("ap_mac", ""),
                }
            )
        return clients

    async def get_alerts(self, limit: int = 50) -> list[dict]:
        """Get recent alerts/events from the controller."""
        raw = await self._request(
            "GET",
            f"/api/s/{self.site}/stat/alarm",
            params={"_limit": limit, "_sort": "-time"},
        )
        alerts = []
        for a in raw:
            alerts.append(
                {
                    "id": a.get("_id", ""),
                    "time": a.get("time", 0),
                    "type": a.get("key", ""),
                    "message": a.get("msg", ""),
                    "device_mac": a.get("device_mac", ""),
                    "subsystem": a.get("subsystem", ""),
                    "archived": a.get("archived", False),
                }
            )
        return alerts

    async def get_site_health(self) -> list[dict]:
        """Get site health summary (WAN, LAN, WLAN subsystems)."""
        return await self._request("GET", f"/api/s/{self.site}/stat/health")

    async def get_sysinfo(self) -> dict:
        """Get controller system info (version, uptime, etc)."""
        data = await self._request("GET", f"/api/s/{self.site}/stat/sysinfo")
        return data[0] if data else {}
