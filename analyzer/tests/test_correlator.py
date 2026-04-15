"""Tests for correlation rules and engine."""

from analyzer.correlator.rules import RULES, CorrelationRule


class TestCorrelationRules:
    def test_all_rules_have_required_fields(self):
        for rule in RULES:
            assert rule.name, f"Rule missing name"
            assert rule.description, f"Rule {rule.name} missing description"
            assert 1 <= rule.severity <= 10, f"Rule {rule.name} severity out of range"
            assert rule.query.strip(), f"Rule {rule.name} missing query"
            assert rule.window_minutes > 0, f"Rule {rule.name} invalid window"

    def test_all_rules_use_window_placeholder(self):
        for rule in RULES:
            assert "{window}" in rule.query, (
                f"Rule {rule.name} query does not use {{window}} placeholder"
            )

    def test_rule_names_unique(self):
        names = [r.name for r in RULES]
        assert len(names) == len(set(names)), "Duplicate rule names found"

    def test_connectivity_rules_present(self):
        """Ensure we have rules targeting the user's primary concerns."""
        rule_names = {r.name for r in RULES}
        assert "dns_failure_burst" in rule_names, "Missing DNS failure detection"
        assert "client_wifi_poor_signal" in rule_names, "Missing WiFi signal detection"
        assert "bandwidth_spike" in rule_names, "Missing bandwidth spike detection"

    def test_rule_query_formatting(self):
        """Ensure queries can be formatted without error."""
        for rule in RULES:
            formatted = rule.query.format(window=rule.window_minutes)
            assert "INTERVAL" in formatted
