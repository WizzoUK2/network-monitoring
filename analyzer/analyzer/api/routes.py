import hmac
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from analyzer.config import settings
from analyzer.models import PROBE_RESULTS_COLUMNS, ProbeResult

router = APIRouter()
logger = logging.getLogger("analyzer.api")


def require_probe_token(request: Request) -> None:
    """Bearer guard for the probe write endpoint (network-monitoring spec §6.3)."""
    expected = settings.probe_ingest_token
    if not expected:
        raise HTTPException(
            status_code=503, detail="probe ingest disabled (set PROBE_INGEST_TOKEN)"
        )
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme != "Bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="unauthorized")


@router.get("/api/health")
async def health():
    return {"status": "ok", "service": "netmon-analyzer"}


@router.get("/api/unifi/devices")
async def get_devices(request: Request):
    """List all UniFi devices from the controller."""
    unifi = request.app.state.unifi
    try:
        devices = await unifi.get_devices()
        return {"devices": devices, "count": len(devices)}
    except Exception as e:
        logger.error("Failed to fetch UniFi devices: %s", e)
        return {"error": str(e), "devices": [], "count": 0}


@router.get("/api/unifi/clients")
async def get_clients(request: Request):
    """List all active clients from the UniFi controller."""
    unifi = request.app.state.unifi
    try:
        clients = await unifi.get_clients()
        return {"clients": clients, "count": len(clients)}
    except Exception as e:
        logger.error("Failed to fetch UniFi clients: %s", e)
        return {"error": str(e), "clients": [], "count": 0}


@router.get("/api/enrichment/device/{ip}")
async def enrich_device(ip: str, request: Request):
    """Look up device info by IP address."""
    enricher = request.app.state.device_enricher
    info = enricher.lookup(ip)
    if info:
        return {"ip": ip, **info}
    return {"ip": ip, "found": False}


@router.get("/api/enrichment/dns/{ip}")
async def enrich_dns(ip: str, request: Request):
    """Look up hostname by IP from passive DNS cache."""
    dns = request.app.state.dns_enricher
    hostname = dns.lookup(ip)
    return {"ip": ip, "hostname": hostname}


@router.get("/api/enrichment/geoip/{ip}")
async def enrich_geoip(ip: str, request: Request):
    """Look up GeoIP data for an IP address."""
    geoip = request.app.state.geoip_enricher
    info = geoip.lookup(ip)
    return {"ip": ip, **info}


@router.get("/api/top-talkers")
async def top_talkers(request: Request, minutes: int = 60, limit: int = 20):
    """Get top talkers by bytes over the last N minutes, enriched with device names."""
    ch = request.app.state.clickhouse
    device_enricher = request.app.state.device_enricher
    dns_enricher = request.app.state.dns_enricher

    since = datetime.now(tz=timezone.utc) - timedelta(minutes=minutes)

    rows = ch.query(
        """
        SELECT src_addr, dst_addr, sum(bytes) AS total_bytes,
               sum(packets) AS total_packets, count() AS flow_count
        FROM flows
        WHERE time_received >= %(since)s
        GROUP BY src_addr, dst_addr
        ORDER BY total_bytes DESC
        LIMIT %(limit)s
        """,
        parameters={"since": since, "limit": limit},
    )

    results = []
    for row in rows.result_rows:
        src, dst, total_bytes, total_packets, flow_count = row
        src_info = device_enricher.lookup(src)
        dst_info = device_enricher.lookup(dst)
        results.append(
            {
                "src_addr": src,
                "src_name": src_info.get("name", src) if src_info else src,
                "dst_addr": dst,
                "dst_name": dst_info.get("name", dst)
                if dst_info
                else dns_enricher.lookup(dst) or dst,
                "total_bytes": total_bytes,
                "total_packets": total_packets,
                "flow_count": flow_count,
            }
        )

    return {"talkers": results, "since_minutes": minutes}


@router.get("/api/correlated-events")
async def correlated_events(request: Request, hours: int = 24, limit: int = 50):
    """Get recent correlated events."""
    ch = request.app.state.clickhouse

    since = datetime.now(tz=timezone.utc) - timedelta(hours=hours)

    try:
        rows = ch.query(
            """
            SELECT timestamp, rule_name, severity, description, source_ips, details
            FROM correlated_events
            WHERE timestamp >= %(since)s
            ORDER BY timestamp DESC
            LIMIT %(limit)s
            """,
            parameters={"since": since, "limit": limit},
        )

        events = []
        for row in rows.result_rows:
            ts, rule, severity, desc, ips, details = row
            events.append(
                {
                    "timestamp": ts.isoformat(),
                    "rule": rule,
                    "severity": severity,
                    "description": desc,
                    "source_ips": ips,
                    "details": details,
                }
            )

        return {"events": events, "count": len(events)}
    except Exception as e:
        logger.error("Failed to query correlated events: %s", e)
        return {"events": [], "count": 0, "error": str(e)}


@router.post("/api/alerts/test")
async def test_alert(request: Request):
    """Fire a test alert to verify the alerting pipeline."""
    from analyzer.alerts.detector import Anomaly

    notifier = getattr(request.app.state, "notifier", None)
    if not notifier:
        return {"error": "Alerting not enabled (set ANOMALY_DETECTION_ENABLED=true)"}

    test_anomaly = Anomaly(
        name="test_alert",
        severity=3,
        description="Test alert from netmon analyzer - alerting pipeline is working",
        source_ip="127.0.0.1",
        details={"test": True, "message": "If you see this, alerts are flowing correctly"},
    )

    await notifier.notify([test_anomaly])
    return {"status": "sent", "message": "Test alert pushed to Alertmanager and ClickHouse"}


@router.get("/api/unifi/health")
async def unifi_health(request: Request):
    """Get UniFi site health summary."""
    unifi = request.app.state.unifi
    try:
        health = await unifi.get_site_health()
        return {"health": health}
    except Exception as e:
        logger.error("Failed to fetch site health: %s", e)
        return {"error": str(e)}


@router.get("/api/stats/summary")
async def stats_summary(request: Request):
    """Get a quick summary of all data in the system."""
    ch = request.app.state.clickhouse
    device_enricher = request.app.state.device_enricher
    dns_enricher = request.app.state.dns_enricher

    stats = {}

    queries = {
        "flows_total": "SELECT count() FROM flows WHERE time_received >= now() - INTERVAL 24 HOUR",
        "flows_bytes_24h": "SELECT sum(bytes) FROM flows WHERE time_received >= now() - INTERVAL 24 HOUR",
        "unique_sources_24h": "SELECT uniq(src_addr) FROM flows WHERE time_received >= now() - INTERVAL 24 HOUR",
        "unique_dests_24h": "SELECT uniq(dst_addr) FROM flows WHERE time_received >= now() - INTERVAL 24 HOUR",
        "events_24h": "SELECT count() FROM correlated_events WHERE timestamp >= now() - INTERVAL 24 HOUR",
    }

    for key, query in queries.items():
        try:
            result = ch.query(query)
            stats[key] = result.result_rows[0][0] if result.result_rows else 0
        except Exception:
            stats[key] = None

    stats["known_devices"] = len(device_enricher.get_all_devices())
    stats["dns_cache_size"] = dns_enricher.get_cache_size()

    return stats


@router.post("/api/probe-results", dependencies=[Depends(require_probe_token)])
async def post_probe_result(payload: ProbeResult, request: Request):
    """Receive an on-demand probe result from the network-probe LXC.

    Writes one row to netmon.probe_results, reusing the established clickhouse_connect
    client (ch.insert — the first write path on the analyzer; reads use ch.query).
    """
    ch = request.app.state.clickhouse
    ch.insert(
        "probe_results",
        [payload.to_clickhouse_row()],
        column_names=PROBE_RESULTS_COLUMNS,
    )
    return {"status": "stored", "stored_at": datetime.now(tz=timezone.utc).isoformat()}


@router.get("/api/probe-results")
async def get_probe_results(
    request: Request,
    vlan: int | None = None,
    test_type: str | None = None,
    target: str | None = None,
    hours: int = 24,
    limit: int = 100,
):
    """Probe history for the Investigation Agent (network-probe get_probe_history).

    Filters are optional; results are newest-first. The filter clauses are static
    strings — only values are parameterised, so there is no SQL injection surface.
    """
    ch = request.app.state.clickhouse

    conditions = ["timestamp >= now() - INTERVAL %(hours)s HOUR"]
    params: dict = {"hours": hours, "limit": limit}
    if vlan is not None:
        conditions.append("vlan = %(vlan)s")
        params["vlan"] = vlan
    if test_type:
        conditions.append("test_type = %(test_type)s")
        params["test_type"] = test_type
    if target:
        conditions.append("target = %(target)s")
        params["target"] = target
    where = " AND ".join(conditions)

    try:
        rows = ch.query(
            f"""
            SELECT timestamp, probe_host, vlan, vlan_name, test_type, target,
                   duration_ms, ok, error, raw_result
            FROM probe_results
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT %(limit)s
            """,
            parameters=params,
        )
    except Exception as e:
        logger.error("Failed to query probe_results: %s", e)
        return {"results": [], "count": 0, "error": str(e)}

    results = []
    for row in rows.result_rows:
        ts, host, vlan_id, vlan_name, ttype, tgt, dur, ok, err, raw = row
        results.append(
            {
                "timestamp": ts.isoformat(),
                "probe_host": host,
                "vlan": vlan_id,
                "vlan_name": vlan_name,
                "test_type": ttype,
                "target": tgt,
                "duration_ms": dur,
                "ok": bool(ok),
                "error": err,
                "raw_result": raw,
            }
        )
    return {"results": results, "count": len(results)}
