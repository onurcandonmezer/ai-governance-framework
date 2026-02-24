<h1 align="center">🏛️ AI Governance Framework</h1>

<p align="center">
  <strong>Enterprise AI governance and compliance toolkit</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/EU_AI_Act-Compliant-00875A?style=flat-square" alt="EU AI Act"/>
  <img src="https://img.shields.io/badge/NIST_AI_RMF-Aligned-1A73E8?style=flat-square" alt="NIST"/>
  <img src="https://img.shields.io/badge/ISO_42001-Ready-EA4335?style=flat-square" alt="ISO 42001"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/github/actions/workflow/status/onurcandonmezer/ai-governance-framework/ci.yml?style=flat-square&label=CI" alt="CI"/>
</p>

---

## Overview

A comprehensive toolkit for establishing and maintaining AI governance within organizations. As AI regulations like the **EU AI Act** become enforceable, organizations need structured approaches to compliance, risk assessment, and audit readiness.

This framework provides **automated risk scoring**, **compliance checklist generation**, **model card creation**, and **audit trail logging** — aligned with EU AI Act, NIST AI Risk Management Framework, and ISO/IEC 42001 standards.

## Key Features

- **Risk Assessment Engine** — Automated risk scoring based on EU AI Act risk categories (Unacceptable, High, Limited, Minimal) with multi-dimensional analysis
- **Compliance Checker** — Generate regulatory compliance checklists tailored to your AI system's risk level and applicable regulations
- **Model Card Generator** — Structured documentation for AI models following industry best practices
- **Audit Trail Logger** — Immutable logging of governance decisions, assessments, and compliance activities
- **Policy Templates** — Ready-to-use AI governance policy templates in YAML/Markdown
- **FastAPI Service** — REST API for integrating governance checks into CI/CD pipelines

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Governance Framework                    │
├──────────────┬──────────────┬───────────────┬───────────────┤
│   Risk       │  Compliance  │  Model Card   │    Audit      │
│  Assessor    │   Checker    │  Generator    │   Logger      │
├──────────────┴──────────────┴───────────────┴───────────────┤
│                     Template Engine (Jinja2)                  │
├─────────────────────────────────────────────────────────────┤
│              Policy & Checklist Templates (YAML)             │
├─────────────────────────────────────────────────────────────┤
│                   Audit Storage (SQLite)                      │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/onurcandonmezer/ai-governance-framework.git
cd ai-governance-framework

# Install dependencies
make install

# Run risk assessment on an AI system
python -m src.risk_assessor --name "Customer Chatbot" --domain "customer_service" --uses-personal-data

# Generate compliance checklist
python -m src.compliance_checker --regulation eu-ai-act --risk-level high

# Generate a model card
python -m src.model_card_generator --config examples/model_config.yaml

# Run the API server
make run
```

## Usage Examples

### Risk Assessment

```python
from src.risk_assessor import RiskAssessor

assessor = RiskAssessor()
result = assessor.assess(
    system_name="HR Resume Screener",
    domain="employment",
    uses_personal_data=True,
    uses_biometric_data=False,
    is_safety_critical=False,
    autonomy_level="semi_autonomous",
    affected_population_size="large",
)

print(f"Risk Level: {result.risk_level}")        # HIGH
print(f"Risk Score: {result.risk_score}/100")     # 78/100
print(f"Key Risks: {result.key_risks}")
print(f"Mitigations: {result.recommended_mitigations}")
```

### Compliance Checklist Generation

```python
from src.compliance_checker import ComplianceChecker

checker = ComplianceChecker()
checklist = checker.generate_checklist(
    regulation="eu_ai_act",
    risk_level="high",
    system_type="decision_support",
)

for item in checklist.items:
    print(f"[{'x' if item.completed else ' '}] {item.requirement}")
```

### Audit Logging

```python
from src.audit_logger import AuditLogger

logger = AuditLogger(db_path="governance_audit.db")
logger.log_event(
    event_type="risk_assessment",
    system_name="HR Resume Screener",
    actor="governance_team",
    details={"risk_level": "high", "score": 78},
)
```

## Tech Stack

<p>
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/Jinja2-B41717?style=flat-square&logo=jinja&logoColor=white" alt="Jinja2"/>
  <img src="https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite"/>
  <img src="https://img.shields.io/badge/YAML-CB171E?style=flat-square&logo=yaml&logoColor=white" alt="YAML"/>
  <img src="https://img.shields.io/badge/Pydantic-E92063?style=flat-square&logo=pydantic&logoColor=white" alt="Pydantic"/>
</p>

## Project Structure

```
ai-governance-framework/
├── README.md
├── pyproject.toml
├── Makefile
├── src/
│   ├── __init__.py
│   ├── risk_assessor.py          # Risk scoring engine
│   ├── compliance_checker.py      # Checklist generator
│   ├── model_card_generator.py    # Model card creator
│   └── audit_logger.py           # Audit trail system
├── templates/
│   ├── policies/                  # AI governance policy templates
│   ├── checklists/               # Compliance checklists
│   └── model_cards/              # Model card templates
├── tests/
│   ├── test_risk_assessor.py
│   ├── test_compliance_checker.py
│   └── test_audit_logger.py
├── docs/
│   └── architecture.md
├── assets/
└── .github/
    └── workflows/
        └── ci.yml
```

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with a governance-first mindset by <a href="https://github.com/onurcandonmezer">Onurcan Dönmezer</a>
</p>
