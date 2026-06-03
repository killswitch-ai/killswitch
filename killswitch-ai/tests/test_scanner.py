import pytest
from killswitch_ai.core.scanner import scan_text, scan_units, Finding
from killswitch_ai.core.normalizer import ScanUnit


class TestSecretPatterns:
    def test_openai_key_detected(self):
        findings = scan_text("Here is my key: sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "openai_key" in types

    def test_anthropic_key_detected(self):
        findings = scan_text("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCD", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "anthropic_key" in types

    def test_aws_access_key_detected(self):
        findings = scan_text("AKIAIOSFODNN7EXAMPLE", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "aws_access_key" in types

    def test_github_token_detected(self):
        findings = scan_text("token: ghp_1234567890abcdefghijklmnopqrstuvwxyz", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "github_token" in types

    def test_stripe_key_detected(self):
        findings = scan_text("sk_live_ABCDEFGHIJKLMNOPQRSTUVWX", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "stripe_key" in types

    def test_private_key_detected(self):
        findings = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "private_key" in types

    def test_database_url_detected(self):
        findings = scan_text("postgres://admin:s3cr3tp@ss@prod-db.example.com/app", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "database_url" in types

    def test_jwt_detected(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = scan_text(token, entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "jwt_token" in types

    def test_dummy_value_not_flagged(self):
        findings = scan_text("sk-example", entropy_enabled=False)
        pattern_findings = [f for f in findings if f.finding_type == "openai_key"]
        assert len(pattern_findings) == 0

    def test_placeholder_not_flagged(self):
        findings = scan_text("your_api_key_here", entropy_enabled=False)
        assert len(findings) == 0

    def test_no_false_positive_on_clean_text(self):
        findings = scan_text("Hello, how are you doing today?", entropy_enabled=False)
        assert len(findings) == 0


class TestProhibitedTerms:
    def test_api_key_term_detected(self):
        findings = scan_text("Please use your API_KEY to authenticate", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "prohibited_term" in types

    def test_custom_prohibited_term(self):
        findings = scan_text(
            "This is PATIENT_NAME data",
            extra_prohibited_terms=["PATIENT_NAME"],
            entropy_enabled=False,
        )
        types = [f.finding_type for f in findings]
        assert "prohibited_term" in types

    def test_confidential_detected(self):
        findings = scan_text("CONFIDENTIAL: do not share", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "prohibited_term" in types


class TestEntropyDetection:
    def test_high_entropy_detected(self):
        high_entropy = "f92aKdj29sLxQp88vN1bTz0qM9pZx7Le"
        findings = scan_text(high_entropy, entropy_enabled=True)
        types = [f.finding_type for f in findings]
        assert "high_entropy_string" in types

    def test_low_entropy_not_flagged(self):
        low_entropy = "aaaabbbbccccddddeeeeffffgggghhhh"
        findings = scan_text(low_entropy, entropy_enabled=True)
        types = [f.finding_type for f in findings]
        assert "high_entropy_string" not in types

    def test_entropy_disabled(self):
        high_entropy = "f92aKdj29sLxQp88vN1bTz0qM9pZx7Le"
        findings = scan_text(high_entropy, entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "high_entropy_string" not in types


class TestSensitiveFilePaths:
    def test_env_file_in_source(self):
        findings = scan_text("reading from .env file", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "sensitive_file_path" in types

    def test_pem_file_reference(self):
        findings = scan_text("cert = open('server.pem').read()", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "sensitive_file_path" in types

    def test_source_file_env(self):
        findings = scan_text("DATABASE_URL=postgres://u:p@host/db", source_file=".env", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "sensitive_file_path" in types

    def test_clean_text_no_file_finding(self):
        findings = scan_text("Just a regular message with no file refs", entropy_enabled=False)
        types = [f.finding_type for f in findings]
        assert "sensitive_file_path" not in types


class TestScanUnits:
    def test_multiple_units_scanned(self):
        units = [
            ScanUnit(path="system", content="You are a helpful assistant."),
            ScanUnit(path="user", content="My key is sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456"),
        ]
        result = scan_units(units, entropy_enabled=False)
        assert result.has_findings
        assert result.scanned_units == 2

    def test_empty_units(self):
        result = scan_units([])
        assert not result.has_findings
        assert result.scanned_units == 0

    def test_severity_ranking(self):
        units = [ScanUnit(path="msg", content="sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456")]
        result = scan_units(units, entropy_enabled=False)
        assert result.max_severity == "critical"
