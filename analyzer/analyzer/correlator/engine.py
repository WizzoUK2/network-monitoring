"""Correlation engine: runs rules against ClickHouse on a schedule
and writes detected events to the correlated_events table.
"""

import json
import logging
from datetime import datetime, timezone

from analyzer.correlator.rules import RULES

logger = logging.getLogger("analyzer.correlator")


class CorrelationEngine:
    def __init__(self, clickhouse):
        self.ch = clickhouse

    async def run(self):
        """Execute all correlation rules and store results."""
        now = datetime.now(tz=timezone.utc)
        total_events = 0

        for rule in RULES:
            try:
                events = self._run_rule(rule, now)
                total_events += events
            except Exception:
                logger.error("Rule '%s' failed", rule.name, exc_info=True)

        if total_events:
            logger.info("Correlation cycle complete: %d events generated", total_events)

    def _run_rule(self, rule, now: datetime) -> int:
        """Run a single correlation rule and insert any results."""
        query = rule.query.format(window=rule.window_minutes)

        try:
            result = self.ch.query(query)
        except Exception:
            # Table might not exist yet (e.g. zeek_dns before any pcaps processed)
            logger.debug("Rule '%s' query failed (table may not exist yet)", rule.name)
            return 0

        if not result.result_rows:
            return 0

        rows_to_insert = []
        for row in result.result_rows:
            # Extract source IPs from the first column (most rules return src_addr first)
            source_ip = str(row[0]) if row else ""

            # Build a details dict from all columns
            details = {}
            for i, col_name in enumerate(result.column_names):
                val = row[i]
                # Convert non-serializable types
                if isinstance(val, (list, tuple)):
                    val = [str(v) for v in val]
                elif isinstance(val, datetime):
                    val = val.isoformat()
                else:
                    val = str(val) if not isinstance(val, (int, float, bool)) else val
                details[col_name] = val

            description = f"{rule.description}: {source_ip}"

            rows_to_insert.append(
                [
                    now,
                    rule.name,
                    rule.severity,
                    description,
                    source_ip,
                    json.dumps(details),
                ]
            )

        if rows_to_insert:
            try:
                self.ch.insert(
                    "correlated_events",
                    rows_to_insert,
                    column_names=[
                        "timestamp",
                        "rule_name",
                        "severity",
                        "description",
                        "source_ips",
                        "details",
                    ],
                )
                logger.info(
                    "Rule '%s' generated %d events",
                    rule.name,
                    len(rows_to_insert),
                )
            except Exception:
                logger.error(
                    "Failed to insert events for rule '%s'",
                    rule.name,
                    exc_info=True,
                )
                return 0

        return len(rows_to_insert)
