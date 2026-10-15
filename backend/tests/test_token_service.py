"""Unit tests for TokenService."""

import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from backend.services.token_service import (
    TokenError,
    TokenExhaustedError,
    TokenExpiredError,
    TokenNotFoundError,
    TokenRevokedError,
    TokenService,
    TokenStatus,
)


class TestTokenService(unittest.TestCase):
    """Test suite for token creation, hashing, expiration, and download limits."""

    def setUp(self):
        self.service = TokenService()

    def test_create_token_returns_unpredictable_token_and_hash(self):
        raw_token, record = self.service.create_token(
            file_id="file_123",
            expires_in_seconds=300,
            max_downloads=5,
        )

        self.assertIsInstance(raw_token, str)
        self.assertGreater(len(raw_token), 20)
        self.assertEqual(record.file_id, "file_123")
        self.assertEqual(record.max_downloads, 5)
        self.assertEqual(record.download_count, 0)
        self.assertFalse(record.is_revoked)

        # Verify hash match
        expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        self.assertEqual(record.token_hash, expected_hash)

        # Raw token should NOT be in the stored record
        self.assertNotIn(raw_token, record.to_dict().values())

    def test_validate_valid_token_succeeds(self):
        raw_token, record = self.service.create_token(
            file_id="doc_abc",
            expires_in_seconds=600,
        )

        validated = self.service.validate_token(raw_token)
        self.assertEqual(validated.token_hash, record.token_hash)
        self.assertEqual(validated.file_id, "doc_abc")

    def test_validate_invalid_token_raises_not_found(self):
        with self.assertRaises(TokenNotFoundError):
            self.service.validate_token("non_existent_token_string")

    def test_validate_expired_token_raises_expired_error(self):
        raw_token, record = self.service.create_token(
            file_id="doc_exp",
            expires_in_seconds=10,
        )

        # Simulate time 20 seconds later
        future_time = datetime.now(timezone.utc) + timedelta(seconds=20)

        with self.assertRaises(TokenExpiredError):
            self.service.validate_token(raw_token, current_time_utc=future_time)

        # Test inspect status as well
        status, rec = self.service.inspect_token_status(raw_token, current_time_utc=future_time)
        self.assertEqual(status, TokenStatus.EXPIRED)

    def test_validate_revoked_token_raises_revoked_error(self):
        raw_token, record = self.service.create_token(
            file_id="doc_rev",
            expires_in_seconds=600,
        )

        # Revoke the token
        self.service.revoke_token(raw_token)

        with self.assertRaises(TokenRevokedError):
            self.service.validate_token(raw_token)

        status, rec = self.service.inspect_token_status(raw_token)
        self.assertEqual(status, TokenStatus.REVOKED)
        self.assertTrue(rec.is_revoked)
        self.assertIsNotNone(rec.revoked_at_utc)

    def test_download_limit_enforcement(self):
        # Create token with max 2 downloads
        raw_token, record = self.service.create_token(
            file_id="doc_limit",
            expires_in_seconds=600,
            max_downloads=2,
        )

        # First download: success
        rec1 = self.service.consume_download(raw_token)
        self.assertEqual(rec1.download_count, 1)

        # Second download: success
        rec2 = self.service.consume_download(raw_token)
        self.assertEqual(rec2.download_count, 2)

        # Third download: should raise TokenExhaustedError
        with self.assertRaises(TokenExhaustedError):
            self.service.consume_download(raw_token)

        status, _ = self.service.inspect_token_status(raw_token)
        self.assertEqual(status, TokenStatus.EXHAUSTED)

    def test_list_tokens_for_file(self):
        token1, _ = self.service.create_token("file_multi", expires_in_seconds=60)
        token2, _ = self.service.create_token("file_multi", expires_in_seconds=120)
        token3, _ = self.service.create_token("other_file", expires_in_seconds=60)

        file_tokens = self.service.list_tokens_for_file("file_multi")
        self.assertEqual(len(file_tokens), 2)


if __name__ == "__main__":
    unittest.main()
