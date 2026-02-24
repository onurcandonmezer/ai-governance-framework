"""Risk assessment engine based on EU AI Act risk categories.

Provides automated risk scoring for AI systems across multiple dimensions
including data sensitivity, autonomy level, affected population, and domain.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class RiskLevel(str, Enum):
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


@dataclass
class RiskDimension:
    name: str
    score: float  # 0-100
    weight: float  # 0-1
    description: str


@dataclass
class RiskAssessmentResult:
    system_name: str
    risk_level: RiskLevel
    risk_score: float
    dimensions: list[RiskDimension]
    key_risks: list[str]
    recommended_mitigations: list[str]
    eu_ai_act_category: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "system_name": self.system_name,
            "risk_level": self.risk_level.value,
            "risk_score": round(self.risk_score, 1),
            "dimensions": [
                {"name": d.name, "score": d.score, "weight": d.weight, "description": d.description}
                for d in self.dimensions
            ],
            "key_risks": self.key_risks,
            "recommended_mitigations": self.recommended_mitigations,
            "eu_ai_act_category": self.eu_ai_act_category,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# Risk Assessment: {self.system_name}",
            "",
            f"**Risk Level:** {self.risk_level.value.upper()}",
            f"**Risk Score:** {self.risk_score:.1f}/100",
            f"**EU AI Act Category:** {self.eu_ai_act_category}",
            "",
            "## Risk Dimensions",
            "",
            "| Dimension | Score | Weight | Description |",
            "|-----------|-------|--------|-------------|",
        ]
        for d in self.dimensions:
            lines.append(f"| {d.name} | {d.score:.0f}/100 | {d.weight:.0%} | {d.description} |")

        lines.extend(["", "## Key Risks", ""])
        for risk in self.key_risks:
            lines.append(f"- {risk}")

        lines.extend(["", "## Recommended Mitigations", ""])
        for m in self.recommended_mitigations:
            lines.append(f"- {m}")

        return "\n".join(lines)


# EU AI Act prohibited domains and high-risk categories
PROHIBITED_DOMAINS = {
    "social_scoring": "Government social scoring systems",
    "real_time_biometric_public": "Real-time biometric identification in public spaces",
    "subliminal_manipulation": "Subliminal manipulation techniques",
    "exploitation_vulnerable": "Exploitation of vulnerable groups",
}

HIGH_RISK_DOMAINS = {
    "employment": "HR and recruitment decisions",
    "education": "Educational access and assessment",
    "critical_infrastructure": "Critical infrastructure management",
    "law_enforcement": "Law enforcement and judicial",
    "migration": "Migration and border control",
    "credit_scoring": "Credit and financial assessment",
    "healthcare_diagnosis": "Medical diagnosis support",
    "biometric_identification": "Biometric categorization",
}

DOMAIN_RISK_SCORES = {
    "social_scoring": 100,
    "real_time_biometric_public": 100,
    "subliminal_manipulation": 100,
    "exploitation_vulnerable": 100,
    "employment": 75,
    "education": 70,
    "critical_infrastructure": 85,
    "law_enforcement": 80,
    "migration": 75,
    "credit_scoring": 70,
    "healthcare_diagnosis": 80,
    "biometric_identification": 75,
    "customer_service": 30,
    "content_creation": 25,
    "data_analysis": 35,
    "internal_tools": 20,
    "marketing": 30,
    "research": 25,
}

AUTONOMY_SCORES = {
    "fully_autonomous": 90,
    "semi_autonomous": 60,
    "human_in_the_loop": 35,
    "human_on_the_loop": 50,
    "advisory_only": 20,
}

POPULATION_SCORES = {
    "individual": 15,
    "small": 30,
    "medium": 50,
    "large": 75,
    "public": 90,
}


class RiskAssessor:
    """Multi-dimensional risk assessment engine for AI systems."""

    def __init__(self, config_path: str | Path | None = None):
        self.config: dict[str, Any] = {}
        if config_path:
            path = Path(config_path)
            self.config = yaml.safe_load(path.read_text()) or {}

    def assess(
        self,
        system_name: str,
        domain: str,
        uses_personal_data: bool = False,
        uses_biometric_data: bool = False,
        is_safety_critical: bool = False,
        autonomy_level: str = "human_in_the_loop",
        affected_population_size: str = "small",
        description: str = "",
    ) -> RiskAssessmentResult:
        """Run a full risk assessment on an AI system."""
        dimensions = self._calculate_dimensions(
            domain=domain,
            uses_personal_data=uses_personal_data,
            uses_biometric_data=uses_biometric_data,
            is_safety_critical=is_safety_critical,
            autonomy_level=autonomy_level,
            affected_population_size=affected_population_size,
        )

        weighted_score = sum(d.score * d.weight for d in dimensions)
        total_weight = sum(d.weight for d in dimensions)
        risk_score = weighted_score / total_weight if total_weight > 0 else 0

        risk_level = self._determine_risk_level(risk_score, domain)
        eu_category = self._determine_eu_category(domain, risk_level)
        key_risks = self._identify_key_risks(dimensions, domain, uses_personal_data)
        mitigations = self._recommend_mitigations(risk_level, key_risks, domain)

        return RiskAssessmentResult(
            system_name=system_name,
            risk_level=risk_level,
            risk_score=risk_score,
            dimensions=dimensions,
            key_risks=key_risks,
            recommended_mitigations=mitigations,
            eu_ai_act_category=eu_category,
            metadata={"domain": domain, "description": description},
        )

    def _calculate_dimensions(
        self,
        domain: str,
        uses_personal_data: bool,
        uses_biometric_data: bool,
        is_safety_critical: bool,
        autonomy_level: str,
        affected_population_size: str,
    ) -> list[RiskDimension]:
        dimensions = []

        # Domain risk
        domain_score = DOMAIN_RISK_SCORES.get(domain, 40)
        dimensions.append(
            RiskDimension(
                name="Domain Sensitivity",
                score=domain_score,
                weight=0.25,
                description=HIGH_RISK_DOMAINS.get(
                    domain, PROHIBITED_DOMAINS.get(domain, f"Domain: {domain}")
                ),
            )
        )

        # Data sensitivity
        data_score = 20
        if uses_personal_data:
            data_score += 35
        if uses_biometric_data:
            data_score += 30
        dimensions.append(
            RiskDimension(
                name="Data Sensitivity",
                score=min(data_score, 100),
                weight=0.20,
                description="Assessment of data types processed by the system",
            )
        )

        # Autonomy level
        autonomy_score = AUTONOMY_SCORES.get(autonomy_level, 50)
        dimensions.append(
            RiskDimension(
                name="Autonomy Level",
                score=autonomy_score,
                weight=0.20,
                description=f"System autonomy: {autonomy_level.replace('_', ' ')}",
            )
        )

        # Affected population
        pop_score = POPULATION_SCORES.get(affected_population_size, 50)
        dimensions.append(
            RiskDimension(
                name="Affected Population",
                score=pop_score,
                weight=0.15,
                description=f"Population size: {affected_population_size}",
            )
        )

        # Safety criticality
        safety_score = 85 if is_safety_critical else 20
        dimensions.append(
            RiskDimension(
                name="Safety Impact",
                score=safety_score,
                weight=0.20,
                description="Potential impact on physical safety"
                if is_safety_critical
                else "Non safety-critical application",
            )
        )

        return dimensions

    def _determine_risk_level(self, score: float, domain: str) -> RiskLevel:
        if domain in PROHIBITED_DOMAINS:
            return RiskLevel.UNACCEPTABLE
        if score >= 70:
            return RiskLevel.HIGH
        if score >= 40:
            return RiskLevel.LIMITED
        return RiskLevel.MINIMAL

    def _determine_eu_category(self, domain: str, risk_level: RiskLevel) -> str:
        if domain in PROHIBITED_DOMAINS:
            return "Article 5 — Prohibited AI Practices"
        if risk_level == RiskLevel.HIGH or domain in HIGH_RISK_DOMAINS:
            return "Annex III — High-Risk AI Systems"
        if risk_level == RiskLevel.LIMITED:
            return "Article 52 — Transparency Obligations"
        return "Minimal Risk — No specific obligations"

    def _identify_key_risks(
        self, dimensions: list[RiskDimension], domain: str, uses_personal_data: bool
    ) -> list[str]:
        risks = []
        for dim in dimensions:
            if dim.score >= 70:
                risks.append(f"High {dim.name.lower()} risk ({dim.score:.0f}/100)")

        if uses_personal_data:
            risks.append("GDPR compliance requirements due to personal data processing")
        if domain in HIGH_RISK_DOMAINS:
            risks.append(f"EU AI Act high-risk classification: {HIGH_RISK_DOMAINS[domain]}")
        if domain in PROHIBITED_DOMAINS:
            risks.append(f"PROHIBITED under EU AI Act: {PROHIBITED_DOMAINS[domain]}")

        return risks or ["No significant risks identified at this time"]

    def _recommend_mitigations(
        self, risk_level: RiskLevel, key_risks: list[str], domain: str
    ) -> list[str]:
        mitigations = []

        if risk_level == RiskLevel.UNACCEPTABLE:
            mitigations.append("STOP: This AI application is prohibited under the EU AI Act")
            mitigations.append("Consult legal counsel before any further development")
            return mitigations

        if risk_level == RiskLevel.HIGH:
            mitigations.extend([
                "Implement conformity assessment procedures (Article 43)",
                "Establish quality management system (Article 17)",
                "Maintain technical documentation (Article 11)",
                "Implement human oversight measures (Article 14)",
                "Register system in EU database (Article 60)",
                "Conduct fundamental rights impact assessment",
            ])

        if risk_level == RiskLevel.LIMITED:
            mitigations.extend([
                "Implement transparency obligations — inform users of AI interaction",
                "Document system capabilities and limitations",
                "Establish monitoring procedures for output quality",
            ])

        if any("personal data" in r.lower() for r in key_risks):
            mitigations.append("Conduct Data Protection Impact Assessment (DPIA)")
            mitigations.append("Ensure GDPR Article 22 compliance for automated decisions")

        if domain in HIGH_RISK_DOMAINS:
            mitigations.append("Implement bias testing and fairness monitoring")
            mitigations.append("Establish regular audit schedule")

        return mitigations or ["Continue monitoring and periodic review"]

    def assess_from_yaml(self, config_path: str | Path) -> RiskAssessmentResult:
        """Run risk assessment from a YAML configuration file."""
        path = Path(config_path)
        config = yaml.safe_load(path.read_text())
        return self.assess(**config)


def main():
    parser = argparse.ArgumentParser(description="AI Risk Assessment Engine")
    parser.add_argument("--name", required=True, help="AI system name")
    parser.add_argument("--domain", required=True, help="Application domain")
    parser.add_argument("--uses-personal-data", action="store_true")
    parser.add_argument("--uses-biometric-data", action="store_true")
    parser.add_argument("--is-safety-critical", action="store_true")
    parser.add_argument("--autonomy-level", default="human_in_the_loop",
                        choices=list(AUTONOMY_SCORES.keys()))
    parser.add_argument("--population-size", default="small",
                        choices=list(POPULATION_SCORES.keys()))
    parser.add_argument("--output", choices=["json", "markdown"], default="markdown")
    args = parser.parse_args()

    assessor = RiskAssessor()
    result = assessor.assess(
        system_name=args.name,
        domain=args.domain,
        uses_personal_data=args.uses_personal_data,
        uses_biometric_data=args.uses_biometric_data,
        is_safety_critical=args.is_safety_critical,
        autonomy_level=args.autonomy_level,
        affected_population_size=args.population_size,
    )

    if args.output == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.to_markdown())


if __name__ == "__main__":
    main()
