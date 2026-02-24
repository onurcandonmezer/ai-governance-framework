"""Tests for the risk assessment engine."""

from src.risk_assessor import RiskAssessor, RiskLevel


class TestRiskAssessor:
    def setup_method(self):
        self.assessor = RiskAssessor()

    def test_high_risk_employment_system(self):
        result = self.assessor.assess(
            system_name="Resume Screener",
            domain="employment",
            uses_personal_data=True,
            autonomy_level="semi_autonomous",
            affected_population_size="large",
        )
        assert result.risk_level == RiskLevel.HIGH
        assert result.risk_score >= 60
        assert "Annex III" in result.eu_ai_act_category

    def test_minimal_risk_internal_tool(self):
        result = self.assessor.assess(
            system_name="Code Review Helper",
            domain="internal_tools",
            uses_personal_data=False,
            autonomy_level="advisory_only",
            affected_population_size="small",
        )
        assert result.risk_level == RiskLevel.MINIMAL
        assert result.risk_score < 40

    def test_prohibited_social_scoring(self):
        result = self.assessor.assess(
            system_name="Citizen Score",
            domain="social_scoring",
            uses_personal_data=True,
            uses_biometric_data=True,
            autonomy_level="fully_autonomous",
            affected_population_size="public",
        )
        assert result.risk_level == RiskLevel.UNACCEPTABLE
        assert "Article 5" in result.eu_ai_act_category
        assert any("PROHIBITED" in r for r in result.key_risks)

    def test_limited_risk_customer_service(self):
        result = self.assessor.assess(
            system_name="Support Chatbot",
            domain="customer_service",
            uses_personal_data=False,
            autonomy_level="human_in_the_loop",
            affected_population_size="medium",
        )
        assert result.risk_level in (RiskLevel.LIMITED, RiskLevel.MINIMAL)

    def test_result_has_mitigations(self):
        result = self.assessor.assess(
            system_name="HR Analyzer",
            domain="employment",
            uses_personal_data=True,
        )
        assert len(result.recommended_mitigations) > 0

    def test_result_to_dict(self):
        result = self.assessor.assess(
            system_name="Test System",
            domain="data_analysis",
        )
        d = result.to_dict()
        assert d["system_name"] == "Test System"
        assert "risk_level" in d
        assert "risk_score" in d
        assert isinstance(d["dimensions"], list)

    def test_result_to_markdown(self):
        result = self.assessor.assess(
            system_name="Test System",
            domain="education",
            uses_personal_data=True,
        )
        md = result.to_markdown()
        assert "# Risk Assessment: Test System" in md
        assert "Risk Level" in md
        assert "Key Risks" in md

    def test_biometric_data_increases_risk(self):
        result_no_bio = self.assessor.assess(
            system_name="System A",
            domain="data_analysis",
            uses_biometric_data=False,
        )
        result_bio = self.assessor.assess(
            system_name="System B",
            domain="data_analysis",
            uses_biometric_data=True,
        )
        assert result_bio.risk_score > result_no_bio.risk_score

    def test_safety_critical_increases_risk(self):
        result_safe = self.assessor.assess(
            system_name="System A",
            domain="data_analysis",
            is_safety_critical=False,
        )
        result_critical = self.assessor.assess(
            system_name="System B",
            domain="data_analysis",
            is_safety_critical=True,
        )
        assert result_critical.risk_score > result_safe.risk_score
