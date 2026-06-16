"""Pydantic models for analyzer write endpoints.

``ProbeResult`` mirrors the typed result envelope emitted by the network-probe LXC
(see network-probe spec §4). ``to_clickhouse_row`` flattens it into the column
order of ``netmon.probe_results`` — pulling the per-test fields out of the
test-specific ``result`` payload where present and keeping the full payload in
``raw_result``.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# Column order for ch.insert("probe_results", rows, column_names=PROBE_RESULTS_COLUMNS).
PROBE_RESULTS_COLUMNS = [
    "timestamp",
    "probe_host",
    "probe_version",
    "vlan",
    "vlan_name",
    "test_type",
    "target",
    "duration_ms",
    "ok",
    "error",
    "rtt_min_ms",
    "rtt_avg_ms",
    "rtt_max_ms",
    "loss_pct",
    "status_code",
    "egress_ip",
    "egress_asn",
    "egress_country",
    "dns_rcode",
    "dns_answers",
    "tls_subject",
    "tls_issuer",
    "raw_result",
]


class ProbeResult(BaseModel):
    """The probe's result envelope, as received over POST /api/probe-results."""

    vlan: int
    vlan_name: str = ""
    test_type: str
    target: str
    started_at: datetime | None = None
    duration_ms: int
    ok: bool
    error: str | None = None
    result: dict[str, Any] | None = None
    probe_host: str
    probe_version: str

    def to_clickhouse_row(self) -> list[Any]:
        r = self.result or {}
        answers = r.get("answers")
        return [
            self.started_at or datetime.now(),
            self.probe_host,
            self.probe_version,
            self.vlan,
            self.vlan_name,
            self.test_type,
            self.target,
            self.duration_ms,
            1 if self.ok else 0,
            self.error or "",
            r.get("rtt_min_ms"),
            r.get("rtt_avg_ms"),
            r.get("rtt_max_ms"),
            r.get("loss_pct"),
            r.get("status_code"),
            r.get("egress_ip"),
            r.get("egress_asn"),
            r.get("egress_country"),
            r.get("rcode"),
            json.dumps(answers) if answers is not None else None,
            r.get("tls_subject"),
            r.get("tls_issuer"),
            json.dumps(r),
        ]


class ProbeStored(BaseModel):
    status: str = "stored"
    stored_at: str = Field(...)
