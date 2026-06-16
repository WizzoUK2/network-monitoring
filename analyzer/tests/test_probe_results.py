"""Tests for the POST /api/probe-results ingest endpoint (network-probe Phase 3)."""

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from analyzer.api.routes import router
from analyzer.config import settings

PAYLOAD = {
    "vlan": 40,
    "vlan_name": "guest",
    "test_type": "http_get",
    "target": "https://netflix.com",
    "duration_ms": 412,
    "ok": True,
    "result": {"status_code": 200},
    "probe_host": "netprobe-01",
    "probe_version": "0.1.0",
}


class FakeClickHouse:
    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[Any], list[str]]] = []

    def insert(self, table: str, data: list[Any], column_names: list[str]) -> None:
        self.inserts.append((table, data, column_names))


def _client(token: str) -> tuple[TestClient, FastAPI]:
    settings.probe_ingest_token = token
    app = FastAPI()
    app.include_router(router)
    app.state.clickhouse = FakeClickHouse()
    return TestClient(app), app


def test_rejects_without_bearer_when_configured() -> None:
    client, _ = _client(token="secret")
    assert client.post("/api/probe-results", json=PAYLOAD).status_code == 401


def test_rejects_wrong_bearer() -> None:
    client, _ = _client(token="secret")
    r = client.post("/api/probe-results", json=PAYLOAD, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_503_when_ingest_disabled() -> None:
    client, _ = _client(token="")
    r = client.post("/api/probe-results", json=PAYLOAD, headers={"Authorization": "Bearer x"})
    assert r.status_code == 503


def test_stores_row_and_flattens_result() -> None:
    client, app = _client(token="secret")
    r = client.post("/api/probe-results", json=PAYLOAD, headers={"Authorization": "Bearer secret"})
    assert r.status_code == 200
    assert r.json()["status"] == "stored"

    inserts = app.state.clickhouse.inserts
    assert len(inserts) == 1
    table, rows, cols = inserts[0]
    assert table == "probe_results"
    assert len(rows) == 1
    row = rows[0]
    assert len(row) == len(cols)
    # the per-test field is flattened out of `result` into its own column
    assert row[cols.index("status_code")] == 200
    assert row[cols.index("ok")] == 1
    assert row[cols.index("vlan")] == 40
    assert row[cols.index("test_type")] == "http_get"
