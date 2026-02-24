"""Tests for the compliance checklist generator."""

import pytest

from src.compliance_checker import ComplianceChecker


class TestComplianceChecker:
    def setup_method(self):
        self.checker = ComplianceChecker()

    def test_eu_ai_act_high_risk_checklist(self):
        checklist = self.checker.generate_checklist(
            regulation="eu_ai_act",
            risk_level="high",
        )
        assert checklist.regulation == "eu_ai_act"
        assert len(checklist.items) > 0
        assert all(i.regulation == "eu_ai_act" for i in checklist.items)

    def test_eu_ai_act_limited_risk_checklist(self):
        checklist = self.checker.generate_checklist(
            regulation="eu_ai_act",
            risk_level="limited",
        )
        assert len(checklist.items) > 0
        assert len(checklist.items) < 12  # Fewer than high risk

    def test_nist_checklist(self):
        checklist = self.checker.generate_checklist(
            regulation="nist_ai_rmf",
        )
        assert len(checklist.items) > 0
        assert any("NIST" in item.id for item in checklist.items)

    def test_iso_42001_checklist(self):
        checklist = self.checker.generate_checklist(
            regulation="iso_42001",
        )
        assert len(checklist.items) > 0
        assert any("ISO" in item.id for item in checklist.items)

    def test_unknown_regulation_raises_error(self):
        with pytest.raises(ValueError, match="Unknown regulation"):
            self.checker.generate_checklist(regulation="unknown_reg")

    def test_completion_rate_initial_zero(self):
        checklist = self.checker.generate_checklist(
            regulation="eu_ai_act",
            risk_level="high",
        )
        assert checklist.completion_rate == 0.0

    def test_completion_rate_after_marking(self):
        checklist = self.checker.generate_checklist(
            regulation="eu_ai_act",
            risk_level="high",
        )
        checklist.items[0].completed = True
        assert checklist.completion_rate > 0

    def test_combined_checklist(self):
        checklist = self.checker.generate_combined_checklist(
            regulations=["eu_ai_act", "nist_ai_rmf"],
            risk_level="high",
        )
        has_eu = any("EU" in i.id for i in checklist.items)
        has_nist = any("NIST" in i.id for i in checklist.items)
        assert has_eu and has_nist

    def test_check_compliance_status(self):
        checklist = self.checker.generate_checklist(
            regulation="eu_ai_act",
            risk_level="high",
        )
        status = self.checker.check_compliance(checklist)
        assert "overall_completion" in status
        assert status["is_compliant"] is False

    def test_critical_items_exist(self):
        checklist = self.checker.generate_checklist(
            regulation="eu_ai_act",
            risk_level="high",
        )
        assert len(checklist.critical_items) > 0

    def test_to_markdown(self):
        checklist = self.checker.generate_checklist(
            regulation="eu_ai_act",
            risk_level="high",
        )
        md = checklist.to_markdown()
        assert "Compliance Checklist" in md
        assert "CRITICAL" in md

    def test_available_regulations(self):
        regs = ComplianceChecker.available_regulations()
        assert "eu_ai_act" in regs
        assert "nist_ai_rmf" in regs
        assert "iso_42001" in regs
