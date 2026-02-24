"""Compliance checklist generator for AI regulations.

Generates regulatory compliance checklists based on the applicable regulation
(EU AI Act, NIST AI RMF, ISO 42001) and the system's risk level.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ChecklistItem:
    id: str
    requirement: str
    description: str
    regulation: str
    article: str
    priority: str  # critical, high, medium, low
    completed: bool = False
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "requirement": self.requirement,
            "description": self.description,
            "regulation": self.regulation,
            "article": self.article,
            "priority": self.priority,
            "completed": self.completed,
        }


@dataclass
class ComplianceChecklist:
    regulation: str
    risk_level: str
    system_type: str
    items: list[ChecklistItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def completion_rate(self) -> float:
        if not self.items:
            return 0.0
        return sum(1 for i in self.items if i.completed) / len(self.items) * 100

    @property
    def critical_items(self) -> list[ChecklistItem]:
        return [i for i in self.items if i.priority == "critical"]

    def to_markdown(self) -> str:
        lines = [
            f"# Compliance Checklist: {self.regulation.upper().replace('_', ' ')}",
            "",
            f"**Risk Level:** {self.risk_level.upper()}",
            f"**System Type:** {self.system_type}",
            f"**Completion:** {self.completion_rate:.0f}%",
            "",
        ]

        current_priority = None
        for item in sorted(self.items, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}[x.priority]):
            if item.priority != current_priority:
                current_priority = item.priority
                lines.extend([f"## {current_priority.upper()} Priority", ""])

            checkbox = "x" if item.completed else " "
            lines.append(f"- [{checkbox}] **{item.id}**: {item.requirement}")
            lines.append(f"  - {item.description}")
            lines.append(f"  - *Reference: {item.article}*")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "regulation": self.regulation,
            "risk_level": self.risk_level,
            "system_type": self.system_type,
            "completion_rate": self.completion_rate,
            "total_items": len(self.items),
            "items": [item.to_dict() for item in self.items],
        }


# Regulation-specific requirements
EU_AI_ACT_HIGH_RISK = [
    ChecklistItem(
        id="EU-HR-01",
        requirement="Risk Management System",
        description="Establish and maintain a risk management system throughout the AI system lifecycle",
        regulation="eu_ai_act",
        article="Article 9",
        priority="critical",
    ),
    ChecklistItem(
        id="EU-HR-02",
        requirement="Data Governance",
        description="Training, validation, and testing datasets must meet quality criteria",
        regulation="eu_ai_act",
        article="Article 10",
        priority="critical",
    ),
    ChecklistItem(
        id="EU-HR-03",
        requirement="Technical Documentation",
        description="Prepare technical documentation before the system is placed on the market",
        regulation="eu_ai_act",
        article="Article 11",
        priority="critical",
    ),
    ChecklistItem(
        id="EU-HR-04",
        requirement="Record-Keeping",
        description="System must allow automatic recording of events (logging)",
        regulation="eu_ai_act",
        article="Article 12",
        priority="high",
    ),
    ChecklistItem(
        id="EU-HR-05",
        requirement="Transparency & Information",
        description="Provide clear information to deployers about system capabilities and limitations",
        regulation="eu_ai_act",
        article="Article 13",
        priority="high",
    ),
    ChecklistItem(
        id="EU-HR-06",
        requirement="Human Oversight",
        description="Design system to allow effective human oversight during use",
        regulation="eu_ai_act",
        article="Article 14",
        priority="critical",
    ),
    ChecklistItem(
        id="EU-HR-07",
        requirement="Accuracy, Robustness, Cybersecurity",
        description="Achieve appropriate levels of accuracy, robustness, and cybersecurity",
        regulation="eu_ai_act",
        article="Article 15",
        priority="high",
    ),
    ChecklistItem(
        id="EU-HR-08",
        requirement="Quality Management System",
        description="Establish a quality management system ensuring compliance",
        regulation="eu_ai_act",
        article="Article 17",
        priority="high",
    ),
    ChecklistItem(
        id="EU-HR-09",
        requirement="Conformity Assessment",
        description="Complete conformity assessment procedure before market placement",
        regulation="eu_ai_act",
        article="Article 43",
        priority="critical",
    ),
    ChecklistItem(
        id="EU-HR-10",
        requirement="EU Database Registration",
        description="Register the high-risk AI system in the EU database",
        regulation="eu_ai_act",
        article="Article 60",
        priority="high",
    ),
    ChecklistItem(
        id="EU-HR-11",
        requirement="Post-Market Monitoring",
        description="Establish a post-market monitoring system",
        regulation="eu_ai_act",
        article="Article 61",
        priority="medium",
    ),
    ChecklistItem(
        id="EU-HR-12",
        requirement="Serious Incident Reporting",
        description="Report serious incidents to relevant market surveillance authorities",
        regulation="eu_ai_act",
        article="Article 62",
        priority="high",
    ),
]

EU_AI_ACT_LIMITED = [
    ChecklistItem(
        id="EU-LR-01",
        requirement="AI Interaction Transparency",
        description="Inform users they are interacting with an AI system",
        regulation="eu_ai_act",
        article="Article 52(1)",
        priority="critical",
    ),
    ChecklistItem(
        id="EU-LR-02",
        requirement="Emotion Recognition Disclosure",
        description="If applicable, inform subjects about emotion recognition system use",
        regulation="eu_ai_act",
        article="Article 52(2)",
        priority="high",
    ),
    ChecklistItem(
        id="EU-LR-03",
        requirement="Deep Fake Labeling",
        description="If applicable, label AI-generated or manipulated content",
        regulation="eu_ai_act",
        article="Article 52(3)",
        priority="high",
    ),
    ChecklistItem(
        id="EU-LR-04",
        requirement="Documentation",
        description="Maintain basic documentation of system purpose and capabilities",
        regulation="eu_ai_act",
        article="General",
        priority="medium",
    ),
]

NIST_AI_RMF_REQUIREMENTS = [
    ChecklistItem(
        id="NIST-GOV-01",
        requirement="AI Governance Structure",
        description="Establish organizational AI governance structure with clear roles and responsibilities",
        regulation="nist_ai_rmf",
        article="GOVERN 1.1",
        priority="critical",
    ),
    ChecklistItem(
        id="NIST-GOV-02",
        requirement="Risk Tolerance Definition",
        description="Define organizational risk tolerance for AI systems",
        regulation="nist_ai_rmf",
        article="GOVERN 1.2",
        priority="high",
    ),
    ChecklistItem(
        id="NIST-MAP-01",
        requirement="Context Mapping",
        description="Map AI system context including stakeholders, requirements, and constraints",
        regulation="nist_ai_rmf",
        article="MAP 1.1",
        priority="high",
    ),
    ChecklistItem(
        id="NIST-MAP-02",
        requirement="Impact Assessment",
        description="Assess potential impacts on individuals, groups, and society",
        regulation="nist_ai_rmf",
        article="MAP 2.1",
        priority="critical",
    ),
    ChecklistItem(
        id="NIST-MEA-01",
        requirement="Performance Metrics",
        description="Define and track appropriate performance metrics",
        regulation="nist_ai_rmf",
        article="MEASURE 1.1",
        priority="high",
    ),
    ChecklistItem(
        id="NIST-MEA-02",
        requirement="Bias Testing",
        description="Test for and mitigate harmful bias across demographic groups",
        regulation="nist_ai_rmf",
        article="MEASURE 2.6",
        priority="critical",
    ),
    ChecklistItem(
        id="NIST-MAN-01",
        requirement="Risk Response",
        description="Implement risk response strategies (accept, mitigate, transfer, avoid)",
        regulation="nist_ai_rmf",
        article="MANAGE 1.1",
        priority="high",
    ),
    ChecklistItem(
        id="NIST-MAN-02",
        requirement="Continuous Monitoring",
        description="Establish continuous monitoring of AI system performance and risks",
        regulation="nist_ai_rmf",
        article="MANAGE 4.1",
        priority="medium",
    ),
]

ISO_42001_REQUIREMENTS = [
    ChecklistItem(
        id="ISO-01",
        requirement="AI Policy",
        description="Establish an organizational AI policy approved by top management",
        regulation="iso_42001",
        article="Clause 5.2",
        priority="critical",
    ),
    ChecklistItem(
        id="ISO-02",
        requirement="AI Risk Assessment Process",
        description="Define and apply an AI risk assessment process",
        regulation="iso_42001",
        article="Clause 6.1",
        priority="critical",
    ),
    ChecklistItem(
        id="ISO-03",
        requirement="AI Objectives",
        description="Establish measurable AI objectives consistent with the AI policy",
        regulation="iso_42001",
        article="Clause 6.2",
        priority="high",
    ),
    ChecklistItem(
        id="ISO-04",
        requirement="Competence & Awareness",
        description="Ensure competence of personnel involved in AI system lifecycle",
        regulation="iso_42001",
        article="Clause 7.2",
        priority="high",
    ),
    ChecklistItem(
        id="ISO-05",
        requirement="AI System Impact Assessment",
        description="Conduct impact assessment for AI systems",
        regulation="iso_42001",
        article="Annex B",
        priority="high",
    ),
    ChecklistItem(
        id="ISO-06",
        requirement="Internal Audit",
        description="Conduct internal audits of the AI management system",
        regulation="iso_42001",
        article="Clause 9.2",
        priority="medium",
    ),
]

REGULATION_MAP = {
    "eu_ai_act": {"high": EU_AI_ACT_HIGH_RISK, "limited": EU_AI_ACT_LIMITED},
    "nist_ai_rmf": {"all": NIST_AI_RMF_REQUIREMENTS},
    "iso_42001": {"all": ISO_42001_REQUIREMENTS},
}


class ComplianceChecker:
    """Generate compliance checklists based on regulation and risk level."""

    def __init__(self, templates_dir: str | Path | None = None):
        self.templates_dir = Path(templates_dir) if templates_dir else None

    def generate_checklist(
        self,
        regulation: str,
        risk_level: str = "high",
        system_type: str = "general",
    ) -> ComplianceChecklist:
        """Generate a compliance checklist for the given regulation and risk level."""
        if regulation not in REGULATION_MAP:
            available = ", ".join(REGULATION_MAP.keys())
            raise ValueError(f"Unknown regulation: {regulation}. Available: {available}")

        reg_items = REGULATION_MAP[regulation]

        # Get items for the specific risk level or all items
        items: list[ChecklistItem] = []
        if risk_level in reg_items:
            items = [self._copy_item(i) for i in reg_items[risk_level]]
        elif "all" in reg_items:
            items = [self._copy_item(i) for i in reg_items["all"]]
        else:
            # Fall back to the highest risk level available
            for level in ["high", "limited", "minimal"]:
                if level in reg_items:
                    items = [self._copy_item(i) for i in reg_items[level]]
                    break

        return ComplianceChecklist(
            regulation=regulation,
            risk_level=risk_level,
            system_type=system_type,
            items=items,
        )

    def generate_combined_checklist(
        self,
        regulations: list[str],
        risk_level: str = "high",
        system_type: str = "general",
    ) -> ComplianceChecklist:
        """Generate a combined checklist from multiple regulations."""
        all_items: list[ChecklistItem] = []
        for reg in regulations:
            checklist = self.generate_checklist(reg, risk_level, system_type)
            all_items.extend(checklist.items)

        return ComplianceChecklist(
            regulation=" + ".join(regulations),
            risk_level=risk_level,
            system_type=system_type,
            items=all_items,
        )

    def check_compliance(self, checklist: ComplianceChecklist) -> dict[str, Any]:
        """Analyze compliance status of a checklist."""
        total = len(checklist.items)
        completed = sum(1 for i in checklist.items if i.completed)
        critical_total = len(checklist.critical_items)
        critical_done = sum(1 for i in checklist.critical_items if i.completed)

        return {
            "overall_completion": f"{completed}/{total} ({checklist.completion_rate:.0f}%)",
            "critical_completion": f"{critical_done}/{critical_total}",
            "is_compliant": completed == total,
            "critical_compliant": critical_done == critical_total,
            "pending_items": [i.id for i in checklist.items if not i.completed],
            "pending_critical": [i.id for i in checklist.critical_items if not i.completed],
        }

    @staticmethod
    def _copy_item(item: ChecklistItem) -> ChecklistItem:
        return ChecklistItem(
            id=item.id,
            requirement=item.requirement,
            description=item.description,
            regulation=item.regulation,
            article=item.article,
            priority=item.priority,
        )

    @staticmethod
    def available_regulations() -> list[str]:
        return list(REGULATION_MAP.keys())


def main():
    parser = argparse.ArgumentParser(description="AI Compliance Checklist Generator")
    parser.add_argument("--regulation", required=True,
                        choices=ComplianceChecker.available_regulations())
    parser.add_argument("--risk-level", default="high",
                        choices=["high", "limited", "minimal"])
    parser.add_argument("--system-type", default="general")
    parser.add_argument("--output", choices=["json", "markdown"], default="markdown")
    args = parser.parse_args()

    checker = ComplianceChecker()
    checklist = checker.generate_checklist(
        regulation=args.regulation,
        risk_level=args.risk_level,
        system_type=args.system_type,
    )

    if args.output == "json":
        print(json.dumps(checklist.to_dict(), indent=2))
    else:
        print(checklist.to_markdown())


if __name__ == "__main__":
    main()
