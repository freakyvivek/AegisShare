"""Integration tests demonstrating the full secure file sharing lifecycle.

Validates end-to-end interactions between StorageService, TokenService,
and AuditService:
1. File upload with audit log.
2. Expiring link creation with download limit and audit log.
3. Successful download consumption.
4. Access rejection on exhausted downloads.
5. Access rejection on expired timestamps.
6. Access rejection on token revocation.
"""

import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from backend.services.audit_service import (
    AuditEventType,
    AuditOutcome,
    AuditService,
)
from backend.services.storage_service import LocalStorageService
from backend.services.token_service import (
    TokenExhaustedError,
    TokenExpiredError,
    TokenNotFoundError,
    TokenRevokedError,
    TokenService,
)


class TestSecureFileSharingIntegration(unittest.TestCase):
    """End-to-end lifecycle integration testing."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_integ_")
        self.storage = LocalStorageService(base_directory=self.temp_dir)
        self.tokens = TokenService()
        self.audit = AuditService(log_file_path=f"{self.temp_dir}/audit.jsonl")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_upload_share_download_and_exhaustion_cycle(self):
        # 1. Upload File
        file_id = "capstone_report_final"
        file_bytes = b"%PDF-1.4 Mock Capstone Report Content"
        meta = self.storage.save_file(
            file_id=file_id,
            filename="capstone_report.pdf",
            data=file_bytes,
            content_type="application/pdf",
        )
        self.audit.record_event(
            event_type=AuditEventType.FILE_UPLOAD,
            file_id=file_id,
            outcome=AuditOutcome.SUCCESS,
            details={"filename": meta.original_filename, "size_bytes": meta.file_size_bytes},
        )

        # 2. Generate Share Token with max 1 download, 1 hour expiry
        raw_token, token_rec = self.tokens.create_token(
            file_id=file_id,
            expires_in_seconds=3600,
            max_downloads=1,
        )
        self.audit.record_event(
            event_type=AuditEventType.SHARE_LINK_CREATED,
            file_id=file_id,
            outcome=AuditOutcome.SUCCESS,
            token_hash=token_rec.token_hash,
            details={"expires_at_utc": token_rec.expires_at_utc, "max_downloads": 1},
        )

        # 3. First Download Attempt (Should Succeed)
        validated_rec = self.tokens.consume_download(raw_token)
        download_desc = self.storage.generate_download_descriptor(validated_rec.file_id)

        self.assertEqual(validated_rec.download_count, 1)
        self.assertEqual(download_desc.file_id, file_id)

        self.audit.record_event(
            event_type=AuditEventType.DOWNLOAD_SUCCESS,
            file_id=file_id,
            outcome=AuditOutcome.SUCCESS,
            token_hash=validated_rec.token_hash,
            details={"download_count": validated_rec.download_count},
        )

        # 4. Second Download Attempt (Exhausted Limit -> Rejection)
        with self.assertRaises(TokenExhaustedError):
            self.tokens.consume_download(raw_token)

        self.audit.record_event(
            event_type=AuditEventType.ACCESS_REJECTED,
            file_id=file_id,
            outcome=AuditOutcome.DENIED,
            token_hash=token_rec.token_hash,
            reason="Exceeded maximum download limit (1)",
        )

        # Verify Audit Trail for this file has exactly 4 events in order
        events = self.audit.query_events(file_id=file_id)
        # Note: query_events returns newest first
        self.assertEqual(len(events), 4)
        self.assertEqual(events[0].event_type, "ACCESS_REJECTED")
        self.assertEqual(events[0].outcome, "DENIED")
        self.assertEqual(events[1].event_type, "DOWNLOAD_SUCCESS")
        self.assertEqual(events[1].outcome, "SUCCESS")
        self.assertEqual(events[2].event_type, "SHARE_LINK_CREATED")
        self.assertEqual(events[3].event_type, "FILE_UPLOAD")

    def test_expired_token_access_rejection(self):
        file_id = "confidential_memo"
        self.storage.save_file(file_id, "memo.txt", b"Secret data")

        # Create token with 5 seconds expiry
        raw_token, token_rec = self.tokens.create_token(file_id, expires_in_seconds=5)

        # Simulate check 10 seconds later
        simulated_time = datetime.now(timezone.utc) + timedelta(seconds=10)

        with self.assertRaises(TokenExpiredError):
            self.tokens.consume_download(raw_token, current_time_utc=simulated_time)

        self.audit.record_event(
            event_type=AuditEventType.ACCESS_REJECTED,
            file_id=file_id,
            outcome=AuditOutcome.DENIED,
            token_hash=token_rec.token_hash,
            reason="Access token expired",
        )

        rejections = self.audit.query_events(file_id=file_id, event_type=AuditEventType.ACCESS_REJECTED)
        self.assertEqual(len(rejections), 1)
        self.assertEqual(rejections[0].outcome, "DENIED")

    def test_revoked_token_access_rejection(self):
        file_id = "project_spec"
        self.storage.save_file(file_id, "spec.docx", b"Spec content")

        raw_token, token_rec = self.tokens.create_token(file_id, expires_in_seconds=3600)

        # Explicitly revoke token
        self.tokens.revoke_token(raw_token)
        self.audit.record_event(
            event_type=AuditEventType.TOKEN_REVOKED,
            file_id=file_id,
            outcome=AuditOutcome.SUCCESS,
            token_hash=token_rec.token_hash,
        )

        # Attempt download with revoked token
        with self.assertRaises(TokenRevokedError):
            self.tokens.consume_download(raw_token)

        self.audit.record_event(
            event_type=AuditEventType.ACCESS_REJECTED,
            file_id=file_id,
            outcome=AuditOutcome.DENIED,
            token_hash=token_rec.token_hash,
            reason="Token was revoked by owner",
        )

        revocation_events = self.audit.query_events(file_id=file_id)
        self.assertEqual(len(revocation_events), 2)
        self.assertEqual(revocation_events[0].event_type, "ACCESS_REJECTED")
        self.assertEqual(revocation_events[1].event_type, "TOKEN_REVOKED")


if __name__ == "__main__":
    unittest.main()
