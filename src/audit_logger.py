"""Audit trail logging system for AI governance activities.

Provides immutable logging of governance decisions, risk assessments,
compliance checks, and other governance activities with SQLite storage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class AuditEvent:
    id: int
    timestamp: str
    event_type: str
    system_name: str
    actor: str
    details: dict[str, Any]
    checksum: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "system_name": self.system_name,
            "actor": self.actor,
            "details": self.details,
            "checksum": self.checksum,
        }


class AuditLogger:
    """Immutable audit logger with integrity verification."""

    VALID_EVENT_TYPES = {
        "risk_assessment",
        "compliance_check",
        "model_card_generated",
        "policy_update",
        "incident_report",
        "review_completed",
        "approval_granted",
        "approval_denied",
        "system_registered",
        "system_decommissioned",
    }

    def __init__(self, db_path: str | Path = "governance_audit.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    system_name TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    details TEXT NOT NULL,
                    prev_checksum TEXT,
                    checksum TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_system
                ON audit_log(system_name)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_type
                ON audit_log(event_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp)
            """)

    def _compute_checksum(
        self, timestamp: str, event_type: str, system_name: str, actor: str,
        details: str, prev_checksum: str | None
    ) -> str:
        """Compute SHA-256 checksum for chain integrity."""
        payload = f"{timestamp}|{event_type}|{system_name}|{actor}|{details}|{prev_checksum or ''}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def _get_last_checksum(self) -> str | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT checksum FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return row[0] if row else None

    def log_event(
        self,
        event_type: str,
        system_name: str,
        actor: str,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log an immutable audit event."""
        if event_type not in self.VALID_EVENT_TYPES:
            valid = ", ".join(sorted(self.VALID_EVENT_TYPES))
            raise ValueError(f"Invalid event type: {event_type}. Valid types: {valid}")

        timestamp = datetime.utcnow().isoformat() + "Z"
        details_json = json.dumps(details or {}, sort_keys=True)
        prev_checksum = self._get_last_checksum()

        checksum = self._compute_checksum(
            timestamp, event_type, system_name, actor, details_json, prev_checksum
        )

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO audit_log
                   (timestamp, event_type, system_name, actor, details, prev_checksum, checksum)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, event_type, system_name, actor, details_json, prev_checksum, checksum),
            )
            event_id = cursor.lastrowid

        return AuditEvent(
            id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            system_name=system_name,
            actor=actor,
            details=details or {},
            checksum=checksum,
        )

    def get_events(
        self,
        system_name: str | None = None,
        event_type: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events with optional filters."""
        query = "SELECT id, timestamp, event_type, system_name, actor, details, checksum FROM audit_log WHERE 1=1"
        params: list[Any] = []

        if system_name:
            query += " AND system_name = ?"
            params.append(system_name)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            AuditEvent(
                id=row[0],
                timestamp=row[1],
                event_type=row[2],
                system_name=row[3],
                actor=row[4],
                details=json.loads(row[5]),
                checksum=row[6],
            )
            for row in rows
        ]

    def verify_integrity(self) -> dict[str, Any]:
        """Verify the integrity of the entire audit chain."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT timestamp, event_type, system_name, actor, details, prev_checksum, checksum "
                "FROM audit_log ORDER BY id ASC"
            ).fetchall()

        if not rows:
            return {"valid": True, "total_events": 0, "message": "No events in log"}

        broken_links = []
        prev_checksum = None

        for i, row in enumerate(rows):
            timestamp, event_type, system_name, actor, details, stored_prev, stored_checksum = row

            # Verify previous checksum link
            if stored_prev != prev_checksum:
                broken_links.append({"index": i, "issue": "broken_chain_link"})

            # Verify checksum calculation
            expected = self._compute_checksum(
                timestamp, event_type, system_name, actor, details, stored_prev
            )
            if expected != stored_checksum:
                broken_links.append({"index": i, "issue": "checksum_mismatch"})

            prev_checksum = stored_checksum

        return {
            "valid": len(broken_links) == 0,
            "total_events": len(rows),
            "broken_links": broken_links,
            "message": "Audit chain integrity verified" if not broken_links else "INTEGRITY VIOLATION DETECTED",
        }

    def export_markdown(self, system_name: str | None = None) -> str:
        """Export audit log as Markdown."""
        events = self.get_events(system_name=system_name, limit=1000)
        lines = [
            "# Audit Trail Report",
            "",
            f"**Generated:** {datetime.utcnow().isoformat()}Z",
            f"**Total Events:** {len(events)}",
            "",
            "| # | Timestamp | Event Type | System | Actor | Checksum |",
            "|---|-----------|------------|--------|-------|----------|",
        ]

        for event in reversed(events):
            short_checksum = event.checksum[:12] + "..."
            lines.append(
                f"| {event.id} | {event.timestamp} | {event.event_type} | "
                f"{event.system_name} | {event.actor} | `{short_checksum}` |"
            )

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="AI Governance Audit Logger")
    sub = parser.add_subparsers(dest="command")

    log_parser = sub.add_parser("log", help="Log an event")
    log_parser.add_argument("--type", required=True, choices=sorted(AuditLogger.VALID_EVENT_TYPES))
    log_parser.add_argument("--system", required=True)
    log_parser.add_argument("--actor", required=True)
    log_parser.add_argument("--details", default="{}", help="JSON details")
    log_parser.add_argument("--db", default="governance_audit.db")

    query_parser = sub.add_parser("query", help="Query events")
    query_parser.add_argument("--system", default=None)
    query_parser.add_argument("--type", default=None)
    query_parser.add_argument("--limit", type=int, default=20)
    query_parser.add_argument("--db", default="governance_audit.db")

    verify_parser = sub.add_parser("verify", help="Verify chain integrity")
    verify_parser.add_argument("--db", default="governance_audit.db")

    args = parser.parse_args()

    if args.command == "log":
        logger = AuditLogger(args.db)
        event = logger.log_event(
            event_type=args.type,
            system_name=args.system,
            actor=args.actor,
            details=json.loads(args.details),
        )
        print(f"Event logged: #{event.id} [{event.event_type}] checksum={event.checksum[:16]}...")

    elif args.command == "query":
        logger = AuditLogger(args.db)
        events = logger.get_events(
            system_name=args.system,
            event_type=args.type,
            limit=args.limit,
        )
        for e in events:
            print(f"#{e.id} [{e.timestamp}] {e.event_type} — {e.system_name} by {e.actor}")

    elif args.command == "verify":
        logger = AuditLogger(args.db)
        result = logger.verify_integrity()
        print(json.dumps(result, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
