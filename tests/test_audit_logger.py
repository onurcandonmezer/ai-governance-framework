"""Tests for the audit logging system."""

import json
import tempfile
from pathlib import Path

import pytest

from src.audit_logger import AuditLogger


class TestAuditLogger:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.logger = AuditLogger(db_path=self.tmp.name)

    def teardown_method(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_log_event(self):
        event = self.logger.log_event(
            event_type="risk_assessment",
            system_name="Test System",
            actor="test_user",
            details={"risk_level": "high"},
        )
        assert event.id is not None
        assert event.event_type == "risk_assessment"
        assert event.checksum is not None

    def test_invalid_event_type_raises(self):
        with pytest.raises(ValueError, match="Invalid event type"):
            self.logger.log_event(
                event_type="invalid_type",
                system_name="Test",
                actor="test",
            )

    def test_query_events(self):
        self.logger.log_event("risk_assessment", "System A", "user1")
        self.logger.log_event("compliance_check", "System B", "user2")
        self.logger.log_event("risk_assessment", "System A", "user1")

        all_events = self.logger.get_events()
        assert len(all_events) == 3

        system_a = self.logger.get_events(system_name="System A")
        assert len(system_a) == 2

        risk_events = self.logger.get_events(event_type="risk_assessment")
        assert len(risk_events) == 2

    def test_chain_integrity_valid(self):
        self.logger.log_event("risk_assessment", "System A", "user1")
        self.logger.log_event("compliance_check", "System B", "user2")
        self.logger.log_event("review_completed", "System A", "user3")

        result = self.logger.verify_integrity()
        assert result["valid"] is True
        assert result["total_events"] == 3

    def test_empty_log_integrity(self):
        result = self.logger.verify_integrity()
        assert result["valid"] is True
        assert result["total_events"] == 0

    def test_event_to_dict(self):
        event = self.logger.log_event(
            event_type="model_card_generated",
            system_name="ML Model",
            actor="data_scientist",
            details={"model_version": "2.0"},
        )
        d = event.to_dict()
        assert d["system_name"] == "ML Model"
        assert d["details"]["model_version"] == "2.0"

    def test_export_markdown(self):
        self.logger.log_event("risk_assessment", "System A", "user1")
        self.logger.log_event("compliance_check", "System A", "user2")

        md = self.logger.export_markdown(system_name="System A")
        assert "Audit Trail Report" in md
        assert "System A" in md

    def test_checksum_differs_between_events(self):
        e1 = self.logger.log_event("risk_assessment", "System A", "user1")
        e2 = self.logger.log_event("risk_assessment", "System A", "user1")
        assert e1.checksum != e2.checksum

    def test_details_stored_correctly(self):
        details = {"score": 85, "level": "high", "tags": ["critical"]}
        self.logger.log_event("risk_assessment", "System", "user", details=details)

        events = self.logger.get_events(system_name="System")
        assert events[0].details == details
