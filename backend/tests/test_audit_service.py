"""Unit tests for AuditService."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from backend.services.audit_service import (
    AuditEventType,
    AuditOutcome,
    AuditService,
)


class TestAuditService(unittest.TestCase):
    """Test suite for structured audit logging and sensitive data protection."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_audit_")
        self.log_file = Path(self.temp_dir) / "audit_test.jsonl"
        self.audit = AuditService(log_file_path=self.log_file)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_record_and_query_event(self):
        record = self.audit.record_event(
            event_type=AuditEventType.FILE_UPLOAD,
            file_id="file_001",
            outcome=AuditOutcome.SUCCESS,
            actor_ip="192.168.1.50",
            user_agent="Mozilla/5.0",
            details={"filename": "assignment.pdf", "size_bytes": 2048},
        )

        self.assertTrue(record.event_id.startswith("evt_"))
        self.assertEqual(record.event_type, "FILE_UPLOAD")
        self.assertEqual(record.outcome, "SUCCESS")
        self.assertEqual(record.file_id, "file_001")
        self.assertEqual(record.actor_ip, "192.168.1.50")
        self.assertEqual(record.details["filename"], "assignment.pdf")

        # Verify query
        results = self.audit.query_events(file_id="file_001")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].event_id, record.event_id)

    def test_sensitive_data_redaction(self):
        """Plaintext tokens, passwords, credentials, and presigned query strings must be scrubbed."""
        sensitive_url = "https://s3.amazonaws.com/bucket/file?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=vjbyPxy12"

        record = self.audit.record_event(
            event_type=AuditEventType.SHARE_LINK_CREATED,
            file_id="file_secure",
            outcome=AuditOutcome.SUCCESS,
            token_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            details={
                "raw_token": "secret_plaintext_token_12345",
                "password": "super_secret_password",
                "presigned_url": sensitive_url,
                "file_name": "data.csv",
            },
        )

        # Raw token and password must be redacted
        self.assertEqual(record.details["raw_token"], "[REDACTED_SENSITIVE_DATA]")
        self.assertEqual(record.details["password"], "[REDACTED_SENSITIVE_DATA]")

        # Presigned URL query params containing access keys must be stripped
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", record.details["presigned_url"])
        self.assertIn("[QUERY_STRIPPED_FOR_AUDIT]", record.details["presigned_url"])

        # Non-sensitive details must remain intact
        self.assertEqual(record.details["file_name"], "data.csv")

        # Token hash prefix only (not full hash, definitely not raw token)
        self.assertTrue(record.token_hash_prefix.startswith("e3b0c44298fc"))
        self.assertTrue(record.token_hash_prefix.endswith("..."))

    def test_file_persistence_and_reload(self):
        self.audit.record_event(
            event_type=AuditEventType.ACCESS_REJECTED,
            file_id="file_rejection",
            outcome=AuditOutcome.DENIED,
            reason="Token expired",
        )

        self.assertTrue(self.log_file.exists())

        # Create a new AuditService instance pointing to the same log file
        reloaded_audit = AuditService(log_file_path=self.log_file)
        events = reloaded_audit.query_events(file_id="file_rejection")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].outcome, "DENIED")
        self.assertEqual(events[0].reason, "Token expired")


if __name__ == "__main__":
    unittest.main()
