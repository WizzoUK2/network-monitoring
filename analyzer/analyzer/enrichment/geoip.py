"""GeoIP enrichment using MaxMind GeoLite2 database.

Provides country, city, and ASN lookups for external IP addresses.
Requires a GeoLite2-City.mmdb file (free from MaxMind with registration).
"""

import ipaddress
import logging

logger = logging.getLogger("analyzer.enrichment.geoip")

try:
    import geoip2.database
    import geoip2.errors

    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False
    logger.warning("geoip2 not available - GeoIP enrichment disabled")


# RFC 1918 / RFC 6598 private ranges
_PRIVATE_PREFIXES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "100.64.",
    "127.",
    "169.254.",
)


class GeoIPEnricher:
    def __init__(self, db_path: str):
        self._reader = None
        if HAS_GEOIP:
            try:
                self._reader = geoip2.database.Reader(db_path)
                logger.info("GeoIP database loaded from %s", db_path)
            except FileNotFoundError:
                logger.warning(
                    "GeoIP database not found at %s - enrichment disabled. "
                    "Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
                    db_path,
                )

    def lookup(self, ip: str) -> dict:
        """Look up GeoIP info for an IP. Returns empty dict for private IPs."""
        if self._is_private(ip):
            return {"private": True}

        if not self._reader:
            return {"available": False}

        try:
            resp = self._reader.city(ip)
            return {
                "country": resp.country.iso_code or "",
                "country_name": resp.country.name or "",
                "city": resp.city.name or "",
                "latitude": resp.location.latitude,
                "longitude": resp.location.longitude,
                "asn": getattr(resp.traits, "autonomous_system_number", None),
                "org": getattr(resp.traits, "autonomous_system_organization", None),
            }
        except geoip2.errors.AddressNotFoundError:
            return {"found": False}
        except Exception as e:
            logger.debug("GeoIP lookup failed for %s: %s", ip, e)
            return {"error": str(e)}

    @staticmethod
    def _is_private(ip: str) -> bool:
        if ip.startswith(_PRIVATE_PREFIXES):
            return True
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
