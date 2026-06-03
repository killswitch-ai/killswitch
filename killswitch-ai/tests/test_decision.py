import pytest
from killswitch_ai.core.scanner import Finding
from killswitch_ai.core.policy import resolve_action
from killswitch_ai.exceptions import KillswitchBlocked


def _make_finding(finding_type: str = "openai_key", severity: str = "critical") -> Finding:
    return Finding(
        severity=severity,
        finding_type=finding_type,
        description="test finding",
    )


class TestResolveAction:
    def test_no_findings_returns_allow(self):
        action = resolve_action([], {}, default_mode="kill")
        assert action == "allow"

    def test_kill_action_for_critical_finding(self):
        actions = {"openai_key": "kill"}
        f = _make_finding("openai_key", "critical")
        action = resolve_action([f], actions)
        assert action == "kill"

    def test_pause_action(self):
        actions = {"database_url": "pause"}
        f = _make_finding("database_url", "high")
        action = resolve_action([f], actions)
        assert action == "pause"

    def test_most_restrictive_wins(self):
        actions = {"prohibited_term": "report_only", "openai_key": "kill"}
        findings = [
            _make_finding("prohibited_term", "medium"),
            _make_finding("openai_key", "critical"),
        ]
        action = resolve_action(findings, actions)
        assert action == "kill"

    def test_default_mode_fallback(self):
        f = _make_finding("unknown_type", "low")
        action = resolve_action([f], {}, default_mode="pause")
        assert action == "pause"

    def test_report_only_action(self):
        actions = {"high_entropy_string": "report_only"}
        f = _make_finding("high_entropy_string", "low")
        action = resolve_action([f], actions)
        assert action == "report_only"


class TestKillswitchBlocked:
    def test_exception_message_contains_finding_id(self):
        f = _make_finding()
        exc = KillswitchBlocked(f, "KAI-E-20260602-test01")
        assert f.finding_id in str(exc)
        assert "KAI-E-20260602-test01" in str(exc)

    def test_exception_has_finding_attribute(self):
        f = _make_finding()
        exc = KillswitchBlocked(f, "KAI-E-test")
        assert exc.finding is f

    def test_exception_is_exception_subclass(self):
        f = _make_finding()
        exc = KillswitchBlocked(f, "KAI-E-test")
        assert isinstance(exc, Exception)
