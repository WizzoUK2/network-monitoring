import logging
import os
from contextlib import asynccontextmanager

import clickhouse_connect
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI

from analyzer.alerts.detector import AnomalyDetector
from analyzer.alerts.notifier import AlertNotifier
from analyzer.api.routes import router
from analyzer.config import settings
from analyzer.correlator.engine import CorrelationEngine
from analyzer.enrichment.device import DeviceEnricher
from analyzer.enrichment.dns import DnsEnricher
from analyzer.enrichment.geoip import GeoIPEnricher
from analyzer.unifi.client import UniFiClient
from analyzer.unifi.poller import UniFiPoller

logger = logging.getLogger("analyzer")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

# Shared state accessible via app.state
scheduler = AsyncIOScheduler()


def get_clickhouse():
    return clickhouse_connect.get_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        username=settings.clickhouse_user,
        password=settings.clickhouse_password,
        database=settings.clickhouse_db,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting analyzer service...")

    # Initialize ClickHouse client
    ch = get_clickhouse()
    app.state.clickhouse = ch
    logger.info(
        "Connected to ClickHouse at %s:%s",
        settings.clickhouse_host,
        settings.clickhouse_port,
    )

    # Initialize UniFi client
    unifi = UniFiClient(
        host=settings.unifi_host,
        username=settings.unifi_username,
        password=settings.unifi_password,
        site=settings.unifi_site,
        verify_ssl=settings.unifi_verify_ssl,
    )
    app.state.unifi = unifi

    # Initialize enrichment modules
    app.state.device_enricher = DeviceEnricher()
    app.state.dns_enricher = DnsEnricher(settings.zeek_log_dir)
    app.state.geoip_enricher = GeoIPEnricher(settings.geoip_db_path)

    # Initialize poller and correlation engine
    poller = UniFiPoller(unifi=unifi, clickhouse=ch, device_enricher=app.state.device_enricher)
    app.state.poller = poller

    correlator = CorrelationEngine(clickhouse=ch)
    app.state.correlator = correlator

    # Schedule background tasks
    scheduler.add_job(
        poller.poll,
        "interval",
        seconds=settings.unifi_poll_interval,
        id="unifi_poller",
        name="UniFi device/client poller",
    )
    scheduler.add_job(
        correlator.run,
        "interval",
        seconds=settings.correlation_interval,
        id="correlator",
        name="Event correlation engine",
    )
    scheduler.add_job(
        app.state.dns_enricher.refresh,
        "interval",
        seconds=120,
        id="dns_refresh",
        name="Passive DNS cache refresh",
    )
    # Phase 3: Anomaly detection and alerting (opt-in via env var)
    notifier = None
    if os.environ.get("ANOMALY_DETECTION_ENABLED", "").lower() == "true":
        alertmanager_url = os.environ.get("ALERTMANAGER_URL", "http://alertmanager:9093")
        detector = AnomalyDetector(clickhouse=ch)
        notifier = AlertNotifier(alertmanager_url=alertmanager_url, clickhouse=ch)
        app.state.detector = detector
        app.state.notifier = notifier

        async def anomaly_cycle():
            anomalies = await detector.run()
            if anomalies:
                await notifier.notify(anomalies)

        scheduler.add_job(
            anomaly_cycle,
            "interval",
            seconds=settings.correlation_interval,
            id="anomaly_detector",
            name="Anomaly detection and alerting",
        )
        logger.info("Anomaly detection enabled (Alertmanager: %s)", alertmanager_url)
    else:
        logger.info("Anomaly detection disabled (set ANOMALY_DETECTION_ENABLED=true to enable)")

    scheduler.start()
    logger.info("Background schedulers started")

    # Run an initial poll immediately
    try:
        await poller.poll()
    except Exception:
        logger.warning("Initial UniFi poll failed (controller may not be configured yet)", exc_info=True)

    yield

    # Shutdown
    scheduler.shutdown(wait=False)
    if notifier:
        await notifier.close()
    if hasattr(unifi, "_client"):
        await unifi.close()
    ch.close()
    logger.info("Analyzer service stopped")


app = FastAPI(
    title="Network Monitor Analyzer",
    description="UniFi API integration, data enrichment, and event correlation",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(router)
