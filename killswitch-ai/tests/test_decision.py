import pytest
from killswitch.core.decision import execute_decision
from killswitch.core.scanner import Finding
from killswitch.core.policy import resolve_action
from killswitch.exceptions import KillswitchBlocked


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

    def test_drop_action_resolves(self):
        actions = {"openai_key": "drop"}
        f = _make_finding("openai_key", "critical")
        action = resolve_action([f], actions)
        assert action == "drop"

    def test_off_mode_disables_actions(self):
        actions = {"openai_key": "kill"}
        f = _make_finding("openai_key", "critical")
        action = resolve_action([f], actions, default_mode="off")
        assert action == "allow"


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


class TestExecuteDecision:
    def test_drop_returns_drop_without_raising(self):
        f = _make_finding()
        action, payload = execute_decision(
            "drop",
            {"input": "dummy"},
            [f],
            "KAI-E-test",
            provider="openai",
            operation="responses.create",
        )
        assert action == "drop"
        assert payload == {"input": "dummy"}
