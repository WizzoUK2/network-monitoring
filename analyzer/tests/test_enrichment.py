"""Tests for enrichment modules."""

import json
import tempfile
from pathlib import Path

from analyzer.enrichment.device import DeviceEnricher
from analyzer.enrichment.dns import DnsEnricher
from analyzer.enrichment.geoip import GeoIPEnricher


class TestDeviceEnricher:
    def test_empty_cache(self):
        enricher = DeviceEnricher()
        assert enricher.lookup("192.168.1.1") is None

    def test_update_and_lookup(self):
        enricher = DeviceEnricher()
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "name": "Gateway", "type": "ugw", "model": "UDM-Pro"}
        ]
        clients = [
            {
                "ip": "192.168.1.100",
                "mac": "11:22:33:44:55:66",
                "name": "Craig's iPhone",
                "hostname": "craigs-iphone",
                "network": "LAN",
                "is_wired": False,
                "oui": "Apple",
            }
        ]
        enricher.update_from_unifi(devices, clients)

        gw = enricher.lookup("192.168.1.1")
        assert gw is not None
        assert gw["name"] == "Gateway"
        assert gw["is_infrastructure"] is True

        phone = enricher.lookup("192.168.1.100")
        assert phone is not None
        assert phone["name"] == "Craig's iPhone"
        assert phone["is_infrastructure"] is False

        assert enricher.lookup("10.0.0.1") is None

    def test_mac_lookup(self):
        enricher = DeviceEnricher()
        enricher.update_from_unifi(
            [],
            [{"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:FF", "name": "Test", "hostname": "", "network": "", "is_wired": True, "oui": ""}],
        )
        result = enricher.lookup_mac("aa:bb:cc:dd:ee:ff")
        assert result is not None
        assert result["name"] == "Test"


class TestDnsEnricher:
    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            enricher = DnsEnricher(tmpdir)
            enricher.refresh()
            assert enricher.lookup("8.8.8.8") is None

    def test_parse_zeek_json_dns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dns_log = Path(tmpdir) / "dns.log"
            records = [
                {"ts": 1700000000.0, "query": "example.com", "qtype_name": "A", "answers": ["93.184.216.34"]},
                {"ts": 1700000001.0, "query": "google.com", "qtype_name": "A", "answers": ["142.250.80.46"]},
            ]
            dns_log.write_text("\n".join(json.dumps(r) for r in records))

            enricher = DnsEnricher(tmpdir)
            enricher.refresh()

            assert enricher.lookup("93.184.216.34") == "example.com"
            assert enricher.lookup("142.250.80.46") == "google.com"
            assert enricher.lookup("1.1.1.1") is None

    def test_incremental_read(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dns_log = Path(tmpdir) / "dns.log"
            dns_log.write_text(json.dumps({"ts": 1.0, "query": "a.com", "qtype_name": "A", "answers": ["1.2.3.4"]}))

            enricher = DnsEnricher(tmpdir)
            enricher.refresh()
            assert enricher.get_cache_size() == 1

            # Append a new record
            with open(dns_log, "a") as f:
                f.write("\n" + json.dumps({"ts": 2.0, "query": "b.com", "qtype_name": "A", "answers": ["5.6.7.8"]}))

            enricher.refresh()
            assert enricher.get_cache_size() == 2
            assert enricher.lookup("5.6.7.8") == "b.com"


class TestGeoIPEnricher:
    def test_private_ip(self):
        enricher = GeoIPEnricher("/nonexistent/path.mmdb")
        result = enricher.lookup("192.168.1.1")
        assert result.get("private") is True

    def test_missing_db(self):
        enricher = GeoIPEnricher("/nonexistent/path.mmdb")
        result = enricher.lookup("8.8.8.8")
        assert result.get("available") is False
