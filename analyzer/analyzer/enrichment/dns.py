"""Passive DNS enrichment: reads Zeek dns.log files to build an
IP-to-hostname cache. This avoids active DNS lookups and gives
historical context for connections.
"""

import json
import logging
from pathlib import Path
from threading import Lock

logger = logging.getLogger("analyzer.enrichment.dns")


class DnsEnricher:
    def __init__(self, zeek_log_dir: str):
        self.log_dir = Path(zeek_log_dir)
        self._lock = Lock()
        # ip -> hostname (most recent answer wins)
        self._cache: dict[str, str] = {}
        self._last_position: dict[str, int] = {}

    def refresh(self):
        """Read new entries from Zeek dns.log files and update the cache."""
        dns_logs = sorted(self.log_dir.glob("dns*.log"))
        if not dns_logs:
            return

        new_entries = 0
        for log_path in dns_logs:
            path_key = str(log_path)
            last_pos = self._last_position.get(path_key, 0)

            try:
                with open(log_path) as f:
                    f.seek(last_pos)
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            # Zeek TSV format fallback - skip for now
                            continue

                        query = record.get("query", "")
                        answers = record.get("answers", [])
                        qtype = record.get("qtype_name", "")

                        # Only cache A and AAAA records
                        if qtype not in ("A", "AAAA", ""):
                            continue

                        # Map each answer IP back to the query name
                        if isinstance(answers, list):
                            for answer in answers:
                                if self._is_ip(answer):
                                    with self._lock:
                                        self._cache[answer] = query
                                    new_entries += 1

                    self._last_position[path_key] = f.tell()

            except (OSError, PermissionError):
                logger.warning("Cannot read Zeek DNS log: %s", log_path)

        if new_entries:
            logger.info(
                "DNS cache refreshed: +%d entries, %d total",
                new_entries,
                len(self._cache),
            )

    def lookup(self, ip: str) -> str | None:
        """Look up the hostname for an IP from passive DNS data."""
        with self._lock:
            return self._cache.get(ip)

    def get_cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    @staticmethod
    def _is_ip(value: str) -> bool:
        """Quick check if a string looks like an IP address."""
        if not value:
            return False
        # IPv4
        parts = value.split(".")
        if len(parts) == 4:
            return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        # IPv6 (contains colons)
        return ":" in value
