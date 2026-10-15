"""Unit tests for DynamoDB persistence services."""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from backend.services.audit_service import (
    AuditEventType,
    AuditOutcome,
    AuditRecord,
)
from backend.services.dynamodb_service import (
    DynamoDBAuditStore,
    DynamoDBFilesStore,
    DynamoDBTokenStore,
)
from backend.services.storage_service import FileMetadata
from backend.services.token_service import (
    TokenExhaustedError,
    TokenExpiredError,
    TokenNotFoundError,
    TokenRecord,
    TokenRevokedError,
)


class MockDynamoDBTable:
    """In-memory emulator of a boto3 DynamoDB Table for unit testing."""

    def __init__(self, key_name: str):
        self.key_name = key_name
        self.items = {}

    def put_item(self, Item):
        key = Item[self.key_name]
        self.items[key] = dict(Item)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_item(self, Key):
        key = Key[self.key_name]
        item = self.items.get(key)
        if item:
            return {"Item": dict(item)}
        return {}

    def scan(self, Limit=100, FilterExpression=None):
        return {"Items": [dict(it) for it in list(self.items.values())[:Limit]]}

    def delete_item(self, Key):
        key = Key[self.key_name]
        self.items.pop(key, None)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def update_item(self, Key, UpdateExpression, ConditionExpression=None, ExpressionAttributeValues=None, ReturnValues="ALL_NEW"):
        key = Key[self.key_name]
        if key not in self.items:
            raise Exception("ConditionalCheckFailed: item does not exist")

        item = self.items[key]

        if "is_revoked = :false" in (ConditionExpression or "") and item.get("is_revoked"):
            raise Exception("ConditionalCheckFailed: token revoked")

        if "download_count < :max" in (ConditionExpression or ""):
            max_dl = ExpressionAttributeValues.get(":max")
            if max_dl is not None and item.get("download_count", 0) >= int(max_dl):
                raise Exception("ConditionalCheckFailed: max downloads reached")

        if "download_count = download_count + :inc" in UpdateExpression:
            inc = int(ExpressionAttributeValues.get(":inc", 1))
            item["download_count"] = item.get("download_count", 0) + inc

        if "is_revoked = :true" in UpdateExpression:
            item["is_revoked"] = True
            item["revoked_at_utc"] = ExpressionAttributeValues.get(":now")

        return {"Attributes": dict(item)}


class MockDynamoDBResource:
    def __init__(self):
        self._tables = {}

    def Table(self, name):
        if name not in self._tables:
            # Determine PK based on common names
            pk = "file_id" if "files" in name.lower() else ("event_id" if "audit" in name.lower() else "token_hash")
            self._tables[name] = MockDynamoDBTable(pk)
        return self._tables[name]


class TestDynamoDBService(unittest.TestCase):
    """Test suite for DynamoDB files, tokens, and audit stores."""

    def setUp(self):
        self.resource = MockDynamoDBResource()
        self.files_store = DynamoDBFilesStore("test-files", dynamodb_resource=self.resource)
        self.tokens_store = DynamoDBTokenStore("test-tokens", dynamodb_resource=self.resource)
        self.audit_store = DynamoDBAuditStore("test-audit", dynamodb_resource=self.resource)

    def test_files_store_save_get_list_delete(self):
        meta = FileMetadata(
            file_id="doc_01",
            original_filename="thesis.pdf",
            file_size_bytes=4096,
            content_type="application/pdf",
            uploaded_at_utc=datetime.now(timezone.utc).isoformat(),
            storage_backend="aws_s3",
            storage_key_or_path="uploads/doc_01",
        )
        self.files_store.save_file_metadata(meta)

        retrieved = self.files_store.get_file_metadata("doc_01")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.file_id, "doc_01")
        self.assertEqual(retrieved.original_filename, "thesis.pdf")

        all_files = self.files_store.list_files()
        self.assertEqual(len(all_files), 1)

        self.files_store.delete_file_metadata("doc_01")
        self.assertIsNone(self.files_store.get_file_metadata("doc_01"))

    def test_token_store_lifecycle_and_atomic_consumption(self):
        now_utc = datetime.now(timezone.utc)
        expires_at = (now_utc + timedelta(seconds=600)).isoformat()

        token_rec = TokenRecord(
            token_hash="hash_abc123",
            file_id="doc_01",
            created_at_utc=now_utc.isoformat(),
            expires_at_utc=expires_at,
            max_downloads=2,
            download_count=0,
            is_revoked=False,
        )
        self.tokens_store.save_token_record(token_rec)

        # First consumption
        updated1 = self.tokens_store.consume_download("hash_abc123")
        self.assertEqual(updated1.download_count, 1)

        # Second consumption
        updated2 = self.tokens_store.consume_download("hash_abc123")
        self.assertEqual(updated2.download_count, 2)

        # Third consumption -> exhausted
        with self.assertRaises(TokenExhaustedError):
            self.tokens_store.consume_download("hash_abc123")

    def test_token_store_expiration_rejection(self):
        past_utc = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
        token_rec = TokenRecord(
            token_hash="hash_past",
            file_id="doc_01",
            created_at_utc=past_utc,
            expires_at_utc=past_utc,
            max_downloads=10,
        )
        self.tokens_store.save_token_record(token_rec)

        with self.assertRaises(TokenExpiredError):
            self.tokens_store.consume_download("hash_past")

    def test_token_store_revocation(self):
        now_utc = datetime.now(timezone.utc)
        expires_at = (now_utc + timedelta(seconds=600)).isoformat()
        token_rec = TokenRecord(
            token_hash="hash_rev",
            file_id="doc_01",
            created_at_utc=now_utc.isoformat(),
            expires_at_utc=expires_at,
            max_downloads=5,
        )
        self.tokens_store.save_token_record(token_rec)

        # Revoke
        revoked = self.tokens_store.revoke_token("hash_rev")
        self.assertTrue(revoked.is_revoked)

        # Access should be rejected
        with self.assertRaises(TokenRevokedError):
            self.tokens_store.consume_download("hash_rev")

    def test_audit_store_save_and_query(self):
        record = AuditRecord(
            event_id="evt_001",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            event_type=AuditEventType.FILE_UPLOAD.value,
            file_id="doc_audit",
            outcome=AuditOutcome.SUCCESS.value,
            actor_ip="10.0.0.1",
            user_agent="UnitTester",
            details={"action": "test_save"},
        )
        self.audit_store.record_event(record)

        events = self.audit_store.query_events(file_id="doc_audit")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_id, "evt_001")
        self.assertEqual(events[0].file_id, "doc_audit")


if __name__ == "__main__":
    unittest.main()
