import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models.hybrid_detector import HybridDetector, SecurityRuleSet


@pytest.fixture
def detector():
    return HybridDetector(
        model_high_confidence_threshold=0.85,
        malicious_override_threshold=0.70,
        suspicious_override_threshold=0.55,
        enable_rule_fallback=True,
    )


@pytest.fixture
def detector_no_rules():
    return HybridDetector(enable_rule_fallback=False)


# ─── Rule Matching Tests ───────────────────────────────────────────────────

class TestSQLInjection:
    def test_or_1_1(self):
        hits, weight, label = SecurityRuleSet.scan("OR 1=1 in request")
        assert "sql_injection" in hits
        assert weight >= 0.90

    def test_union_select(self):
        hits, _, _ = SecurityRuleSet.scan("UNION SELECT * FROM users")
        assert "sql_injection" in hits

    def test_drop_table(self):
        hits, _, _ = SecurityRuleSet.scan("DROP TABLE users")
        assert "sql_injection" in hits

    def test_single_quote_or(self):
        hits, _, _ = SecurityRuleSet.scan("' OR '1'='1'")
        assert "sql_injection" in hits


class TestXSS:
    def test_script_tag(self):
        hits, weight, _ = SecurityRuleSet.scan("<script>alert('xss')</script>")
        assert "xss" in hits
        assert weight >= 0.95

    def test_onerror(self):
        hits, _, _ = SecurityRuleSet.scan("<img src=x onerror=alert(1)>")
        assert "xss" in hits

    def test_javascript_protocol(self):
        hits, _, _ = SecurityRuleSet.scan("javascript:void(0)")
        assert "xss" in hits


class TestPathTraversal:
    def test_unix_dotdot(self):
        hits, _, _ = SecurityRuleSet.scan("../../etc/passwd")
        assert "path_traversal" in hits

    def test_windows_dotdot(self):
        hits, _, _ = SecurityRuleSet.scan("..\\windows\\system32")
        assert "path_traversal" in hits

    def test_etc_passwd(self):
        hits, _, _ = SecurityRuleSet.scan("/etc/passwd")
        assert "path_traversal" in hits


class TestBruteForce:
    def test_failed_login(self):
        hits, _, _ = SecurityRuleSet.scan("failed login attempt detected")
        assert "brute_force" in hits

    def test_invalid_password(self):
        hits, _, _ = SecurityRuleSet.scan("invalid password for user admin")
        assert "brute_force" in hits

    def test_auth_failure(self):
        hits, _, _ = SecurityRuleSet.scan("authentication failure")
        assert "brute_force" in hits


class TestCommandInjection:
    def test_rm_rf(self):
        hits, _, _ = SecurityRuleSet.scan("rm -rf /")
        assert "command_injection" in hits

    def test_cat_passwd(self):
        hits, _, _ = SecurityRuleSet.scan("cat /etc/passwd")
        assert "command_injection" in hits


class TestScanningRecon:
    def test_nmap(self):
        hits, _, _ = SecurityRuleSet.scan("nmap scan detected")
        assert "scanning_recon" in hits

    def test_sqlmap(self):
        hits, _, _ = SecurityRuleSet.scan("sqlmap injection attempt")
        assert "scanning_recon" in hits


class TestMalwareRansomware:
    def test_reverse_shell(self):
        hits, _, _ = SecurityRuleSet.scan("reverse shell connection")
        assert "malware_ransomware" in hits

    def test_payload(self):
        hits, _, _ = SecurityRuleSet.scan("malicious payload detected")
        assert "malware_ransomware" in hits


class TestSuspiciousNetwork:
    def test_exfiltration(self):
        hits, _, _ = SecurityRuleSet.scan("data exfiltration attempt blocked")
        assert "suspicious_network" in hits

    def test_dns_tunnel(self):
        hits, _, _ = SecurityRuleSet.scan("dns tunneling detected")
        assert "suspicious_network" in hits


# ─── Benign logs should not be falsely marked malicious ────────────────────

class TestBenignNoFalsePositive:
    def test_normal_web_traffic(self, detector):
        model_result = {"threat": "benign", "confidence": 0.95, "all_scores": {"benign": 0.95, "suspicious": 0.03, "malicious": 0.02}}
        text = "Permitted HTTP request recorded by application log accessing standard path with minimal data transfer."
        result = detector.analyze(model_result, text)
        assert result["final_label"] == "benign"

    def test_normal_dns(self, detector):
        model_result = {"threat": "benign", "confidence": 0.92, "all_scores": {"benign": 0.92, "suspicious": 0.05, "malicious": 0.03}}
        text = "Permitted DNS query recorded by network log accessing standard path with minimal data transfer."
        result = detector.analyze(model_result, text)
        assert result["final_label"] == "benign"

    def test_normal_file_transfer(self, detector):
        model_result = {"threat": "benign", "confidence": 0.88, "all_scores": {"benign": 0.88, "suspicious": 0.07, "malicious": 0.05}}
        text = "Allowed FTP file transfer recorded by network log accessing standard path with moderate data transfer."
        result = detector.analyze(model_result, text)
        assert result["final_label"] == "benign"


# ─── Malicious detection via rules ─────────────────────────────────────────

class TestMaliciousDetection:
    def test_sql_injection_caught(self, detector):
        model_result = {"threat": "benign", "confidence": 0.62, "all_scores": {"benign": 0.62, "suspicious": 0.25, "malicious": 0.13}}
        text = "Blocked HTTP request containing OR 1=1 SQL injection targeting authentication path."
        result = detector.analyze(model_result, text)
        assert result["final_label"] == "malicious"
        assert "sql_injection" in result["rule_hits"]

    def test_xss_caught(self, detector):
        model_result = {"threat": "benign", "confidence": 0.55, "all_scores": {"benign": 0.55, "suspicious": 0.30, "malicious": 0.15}}
        text = "Blocked HTTP request containing <script>alert('xss')</script> XSS attack."
        result = detector.analyze(model_result, text)
        assert result["final_label"] == "malicious"
        assert "xss" in result["rule_hits"]

    def test_path_traversal_caught(self, detector):
        model_result = {"threat": "benign", "confidence": 0.70, "all_scores": {"benign": 0.70, "suspicious": 0.18, "malicious": 0.12}}
        text = "Blocked request with ../ path traversal attempt."
        result = detector.analyze(model_result, text)
        assert result["final_label"] == "malicious"
        assert "path_traversal" in result["rule_hits"]


# ─── API response contains new fields ──────────────────────────────────────

class TestAPIResponseFields:
    def test_hybrid_fields_present(self, detector):
        model_result = {"threat": "benign", "confidence": 0.50, "all_scores": {"benign": 0.50, "suspicious": 0.30, "malicious": 0.20}}
        text = "Some log text here"
        result = detector.analyze(model_result, text)
        expected_fields = [
            "final_label", "confidence", "model_label", "model_confidence",
            "rule_label", "rule_hits", "explanation", "risk_score",
            "recommendation", "latency_ms", "all_scores",
        ]
        for field in expected_fields:
            assert field in result, f"Missing field: {field}"

    def test_explanation_not_empty(self, detector):
        model_result = {"threat": "malicious", "confidence": 0.90, "all_scores": {"benign": 0.05, "suspicious": 0.05, "malicious": 0.90}}
        result = detector.analyze(model_result, "malicious content here")
        assert len(result["explanation"]) > 0


# ─── Rule fallback can be disabled ─────────────────────────────────────────

class TestRuleFallbackDisabled:
    def test_no_rules_applied(self, detector_no_rules):
        model_result = {"threat": "benign", "confidence": 0.50, "all_scores": {"benign": 0.50, "suspicious": 0.30, "malicious": 0.20}}
        text = "OR 1=1 in request with ../ path traversal"
        result = detector_no_rules.analyze(model_result, text)
        assert result["final_label"] == "benign"
        assert result["rule_hits"] == []


# ─── Risk score ranges ─────────────────────────────────────────────────────

class TestRiskScoreRanges:
    def test_benign_risk_range(self, detector):
        for score in [0, 15, 30]:
            result = detector._build_response(
                "benign", 0.9, "benign", 0.9, "benign", [], [], "", {}, 0.0
            )
            assert 0 <= result["risk_score"] <= 30

    def test_suspicious_risk_range(self, detector):
        result = detector._build_response(
            "suspicious", 0.7, "suspicious", 0.7, "suspicious", [], [], "", {}, 0.0
        )
        assert 31 <= result["risk_score"] <= 70

    def test_malicious_risk_range(self, detector):
        result = detector._build_response(
            "malicious", 0.9, "malicious", 0.9, "malicious", [], [], "", {}, 0.0
        )
        assert 71 <= result["risk_score"] <= 100


# ─── Configurable thresholds ───────────────────────────────────────────────

class TestThresholds:
    def test_custom_thresholds(self):
        d = HybridDetector(
            model_high_confidence_threshold=0.90,
            malicious_override_threshold=0.80,
            suspicious_override_threshold=0.60,
        )
        assert d.model_high_conf == 0.90
        assert d.malicious_override == 0.80
        assert d.suspicious_override == 0.60


# ─── Edge cases ────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_text(self, detector):
        model_result = {"threat": "benign", "confidence": 0.50, "all_scores": {"benign": 0.50, "suspicious": 0.30, "malicious": 0.20}}
        result = detector.analyze(model_result, "")
        assert result["final_label"] in ("benign", "suspicious", "malicious")

    def test_high_conf_malicious_model(self, detector):
        model_result = {"threat": "malicious", "confidence": 0.95, "all_scores": {"benign": 0.02, "suspicious": 0.03, "malicious": 0.95}}
        text = "Some aggressive traffic"
        result = detector.analyze(model_result, text)
        assert result["final_label"] == "malicious"
        assert result["confidence"] >= 0.95
