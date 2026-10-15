"""DynamoDB Persistence Services for AWS Mode.

Provides persistent storage for:
1. File Metadata (`FilesTable`)
2. Ephemeral Share Tokens with TTL and atomic access counting (`TokensTable`)
3. Immutable Audit Telemetry (`AuditLogsTable`)

Security & Design Principles:
- Uses DynamoDB conditional expressions for atomic download count increments and race-condition prevention.
- Uses TTL attribute for automatic data purging in AWS.
- Plaintext tokens are NEVER stored; only SHA-256 hashes are used as primary keys.
- Requires explicit DynamoDB table configuration; NEVER silently falls back to local storage.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from backend.services.audit_service import (
    AuditEventType,
    AuditOutcome,
    AuditRecord,
)
from backend.services.storage_service import (
    FileMetadata,
    StorageConfigurationError,
)
from backend.services.token_service import (
    TokenError,
    TokenExhaustedError,
    TokenExpiredError,
    TokenNotFoundError,
    TokenRecord,
    TokenRevokedError,
    TokenStatus,
)

try:
    import boto3
    from boto3.dynamodb.conditions import Attr, Key
except ImportError:
    boto3 = None
    Key = None
    Attr = None


class DynamoDBServiceError(Exception):
    """Base exception for DynamoDB service operations."""


def _convert_floats_to_decimal(obj: Any) -> Any:
    """Helper to convert Python numeric types for DynamoDB serialization."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _convert_floats_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert_floats_to_decimal(x) for x in obj]
    return obj


def _convert_decimal_to_native(obj: Any) -> Any:
    """Helper to convert DynamoDB Decimal types back to int/float."""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, dict):
        return {k: _convert_decimal_to_native(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert_decimal_to_native(x) for x in obj]
    return obj


class DynamoDBFilesStore:
    """Persistent file metadata store backed by Amazon DynamoDB."""

    def __init__(self, table_name: str, dynamodb_resource: Optional[Any] = None):
        if not table_name:
            raise StorageConfigurationError("DynamoDB files table_name must be configured.")
        self.table_name = table_name

        if dynamodb_resource is not None:
            self._table = dynamodb_resource.Table(table_name)
        else:
            if boto3 is None:
                raise StorageConfigurationError(
                    "boto3 is not installed. To use DynamoDB in AWS mode, install boto3 or run in AWS Lambda."
                )
            dynamodb = boto3.resource("dynamodb")
            self._table = dynamodb.Table(table_name)

    def save_file_metadata(self, meta: FileMetadata) -> None:
        """Persist file metadata record."""
        item = _convert_floats_to_decimal(meta.to_dict())
        self._table.put_item(Item=item)

    def get_file_metadata(self, file_id: str) -> Optional[FileMetadata]:
        """Retrieve file metadata by file_id."""
        response = self._table.get_item(Key={"file_id": file_id})
        item = response.get("Item")
        if not item:
            return None
        return FileMetadata(**_convert_decimal_to_native(item))

    def list_files(self, limit: int = 100) -> List[FileMetadata]:
        """Scan stored file metadata records."""
        response = self._table.scan(Limit=limit)
        items = response.get("Items", [])
        return [FileMetadata(**_convert_decimal_to_native(item)) for item in items]

    def delete_file_metadata(self, file_id: str) -> bool:
        """Remove file metadata record."""
        self._table.delete_item(Key={"file_id": file_id})
        return True


class DynamoDBTokenStore:
    """Persistent expiring share tokens store backed by Amazon DynamoDB.
    
    Stores SHA-256 token hashes, enforcing TTL expiration and atomic download counts.
    """

    def __init__(self, table_name: str, dynamodb_resource: Optional[Any] = None):
        if not table_name:
            raise StorageConfigurationError("DynamoDB tokens table_name must be configured.")
        self.table_name = table_name

        if dynamodb_resource is not None:
            self._table = dynamodb_resource.Table(table_name)
        else:
            if boto3 is None:
                raise StorageConfigurationError(
                    "boto3 is not installed. To use DynamoDB in AWS mode, install boto3 or run in AWS Lambda."
                )
            dynamodb = boto3.resource("dynamodb")
            self._table = dynamodb.Table(table_name)

    def save_token_record(self, record: TokenRecord) -> None:
        """Persist token record with TTL attribute."""
        item = _convert_floats_to_decimal(record.to_dict())
        # Calculate epoch seconds for DynamoDB TTL feature
        expires_at_dt = datetime.fromisoformat(record.expires_at_utc)
        item["ttl"] = int(expires_at_dt.timestamp())
        self._table.put_item(Item=item)

    def get_token_record(self, token_hash: str) -> Optional[TokenRecord]:
        """Fetch token record by hash."""
        response = self._table.get_item(Key={"token_hash": token_hash})
        item = response.get("Item")
        if not item:
            return None
        clean_item = _convert_decimal_to_native(item)
        clean_item.pop("ttl", None)
        return TokenRecord.from_dict(clean_item)

    def consume_download(self, token_hash: str, current_time_utc: Optional[datetime] = None) -> TokenRecord:
        """Atomically validate and increment download count.
        
        Enforces:
        - Token existence
        - Not revoked
        - Not expired
        - Download count under max_downloads ceiling
        """
        now_dt = current_time_utc or datetime.now(timezone.utc)
        record = self.get_token_record(token_hash)
        if not record:
            raise TokenNotFoundError("Access token is invalid or does not exist.")

        if record.is_revoked:
            raise TokenRevokedError(f"Access token for file '{record.file_id}' was revoked.")

        expires_at_dt = datetime.fromisoformat(record.expires_at_utc)
        if now_dt >= expires_at_dt:
            raise TokenExpiredError(
                f"Access token for file '{record.file_id}' expired at {record.expires_at_utc}."
            )

        if record.max_downloads is not None and record.download_count >= record.max_downloads:
            raise TokenExhaustedError(
                f"Access token reached maximum download limit ({record.max_downloads})."
            )

        # Atomic increment in DynamoDB
        update_expr = "SET download_count = download_count + :inc"
        expr_attr_vals: Dict[str, Any] = {":inc": 1}

        # If max_downloads is specified, add condition expression to prevent race conditions
        cond_expr = "attribute_exists(token_hash) AND is_revoked = :false"
        expr_attr_vals[":false"] = False

        if record.max_downloads is not None:
            cond_expr += " AND download_count < :max"
            expr_attr_vals[":max"] = record.max_downloads

        try:
            response = self._table.update_item(
                Key={"token_hash": token_hash},
                UpdateExpression=update_expr,
                ConditionExpression=cond_expr,
                ExpressionAttributeValues=_convert_floats_to_decimal(expr_attr_vals),
                ReturnValues="ALL_NEW",
            )
            updated_item = _convert_decimal_to_native(response.get("Attributes", {}))
            updated_item.pop("ttl", None)
            return TokenRecord.from_dict(updated_item)
        except Exception as err:
            # If conditional check fails, re-check state to raise proper specific exception
            latest = self.get_token_record(token_hash)
            if latest and latest.max_downloads and latest.download_count >= latest.max_downloads:
                raise TokenExhaustedError(
                    f"Access token reached maximum download limit ({latest.max_downloads})."
                )
            if latest and latest.is_revoked:
                raise TokenRevokedError(f"Access token was revoked.")
            raise DynamoDBServiceError(f"Atomic download consumption failed: {err}")

    def revoke_token(self, token_hash: str) -> TokenRecord:
        """Mark token as explicitly revoked."""
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            response = self._table.update_item(
                Key={"token_hash": token_hash},
                UpdateExpression="SET is_revoked = :true, revoked_at_utc = :now",
                ConditionExpression="attribute_exists(token_hash)",
                ExpressionAttributeValues={":true": True, ":now": now_iso},
                ReturnValues="ALL_NEW",
            )
            updated_item = _convert_decimal_to_native(response.get("Attributes", {}))
            updated_item.pop("ttl", None)
            return TokenRecord.from_dict(updated_item)
        except Exception as err:
            if "ConditionalCheckFailed" in str(err):
                raise TokenNotFoundError(f"Token hash {token_hash} not found.")
            raise DynamoDBServiceError(f"Failed to revoke token: {err}")

    def list_tokens_for_file(self, file_id: str) -> List[TokenRecord]:
        """Scan or query tokens associated with a file."""
        response = self._table.scan(
            FilterExpression=Attr("file_id").eq(file_id) if Attr is not None else "file_id = :fid"
        )
        items = response.get("Items", [])
        clean_items = [_convert_decimal_to_native(item) for item in items]
        for it in clean_items:
            it.pop("ttl", None)
        return [TokenRecord.from_dict(it) for it in clean_items]

    def list_all_tokens(self, limit: int = 100) -> List[TokenRecord]:
        """Scan all stored token records."""
        response = self._table.scan(Limit=limit)
        items = response.get("Items", [])
        clean_items = [_convert_decimal_to_native(item) for item in items]
        for it in clean_items:
            it.pop("ttl", None)
        return [TokenRecord.from_dict(it) for it in clean_items]


class DynamoDBAuditStore:
    """Persistent audit trail store backed by Amazon DynamoDB."""

    def __init__(self, table_name: str, dynamodb_resource: Optional[Any] = None):
        if not table_name:
            raise StorageConfigurationError("DynamoDB audit table_name must be configured.")
        self.table_name = table_name

        if dynamodb_resource is not None:
            self._table = dynamodb_resource.Table(table_name)
        else:
            if boto3 is None:
                raise StorageConfigurationError(
                    "boto3 is not installed. To use DynamoDB in AWS mode, install boto3 or run in AWS Lambda."
                )
            dynamodb = boto3.resource("dynamodb")
            self._table = dynamodb.Table(table_name)

    def record_event(self, record: AuditRecord) -> None:
        """Persist an audit record to DynamoDB."""
        item = _convert_floats_to_decimal(record.to_dict())
        self._table.put_item(Item=item)

    def query_events(
        self,
        file_id: Optional[str] = None,
        event_type: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditRecord]:
        """Query audit log items."""
        filter_expr = None
        if file_id and Attr is not None:
            filter_expr = Attr("file_id").eq(file_id)
        if event_type and Attr is not None:
            fe = Attr("event_type").eq(event_type)
            filter_expr = fe if filter_expr is None else filter_expr & fe
        if outcome and Attr is not None:
            fe = Attr("outcome").eq(outcome)
            filter_expr = fe if filter_expr is None else filter_expr & fe

        scan_kwargs: Dict[str, Any] = {"Limit": limit}
        if filter_expr is not None:
            scan_kwargs["FilterExpression"] = filter_expr

        response = self._table.scan(**scan_kwargs)
        items = response.get("Items", [])
        records = [AuditRecord.from_dict(_convert_decimal_to_native(it)) for it in items]
        # Sort newest first by timestamp
        records.sort(key=lambda r: r.timestamp_utc, reverse=True)
        return records[:limit]
