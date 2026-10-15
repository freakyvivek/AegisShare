"""AWS Lambda Handler for Token Validation and Secure Download Redirection."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict

from backend.handlers.api_gateway_proxy import format_response, parse_event
from backend.services.audit_service import (
    AuditEventType,
    AuditOutcome,
    AuditRecord,
    AuditService,
)
from backend.services.dynamodb_service import (
    DynamoDBAuditStore,
    DynamoDBFilesStore,
    DynamoDBTokenStore,
)
from backend.services.storage_service import S3StorageService
from backend.services.token_service import (
    TokenExhaustedError,
    TokenExpiredError,
    TokenNotFoundError,
    TokenRevokedError,
    TokenService,
)


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for GET /api/download?token=..."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    if method == "OPTIONS":
        return format_response(204, "")

    if method != "GET":
        return format_response(405, {"error": "Method not allowed. Use GET."})

    bucket_name = os.environ.get("S3_BUCKET_NAME")
    tokens_table = os.environ.get("TOKENS_TABLE_NAME")
    files_table = os.environ.get("FILES_TABLE_NAME")
    audit_table = os.environ.get("AUDIT_TABLE_NAME")
    region_name = os.environ.get("AWS_REGION", "us-east-1")

    if not bucket_name or not tokens_table or not audit_table or not files_table:
        return format_response(500, {
            "error": "CONFIG_ERROR",
            "message": "AWS Lambda environment variables not set."
        })

    raw_token = query_params.get("token")
    if not raw_token:
        return format_response(400, {"error": "Missing 'token' query parameter."})

    tokens_store = DynamoDBTokenStore(table_name=tokens_table)
    audit_store = DynamoDBAuditStore(table_name=audit_table)
    files_store = DynamoDBFilesStore(table_name=files_table)
    storage = S3StorageService(bucket_name=bucket_name, region_name=region_name)

    token_hash = TokenService.hash_token(raw_token)
    token_prefix = AuditService._safe_token_prefix(token_hash)

    try:
        # Atomically validate and increment download count
        record = tokens_store.consume_download(token_hash)
        file_meta = files_store.get_file_metadata(record.file_id)

        # Generate short-lived presigned S3 GET URL
        download_desc = storage.generate_download_descriptor(
            file_id=record.file_id,
            expires_in_seconds=300,
        )

        # Record SUCCESS in audit log
        audit_rec = AuditRecord(
            event_id=f"evt_{TokenService.generate_raw_token(8)}",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            event_type=AuditEventType.DOWNLOAD_SUCCESS.value,
            file_id=record.file_id,
            outcome=AuditOutcome.SUCCESS.value,
            actor_ip=client_ip,
            user_agent=user_agent,
            token_hash_prefix=token_prefix,
            details={
                "download_count": record.download_count,
                "max_downloads": record.max_downloads,
                "filename": file_meta.original_filename if file_meta else record.file_id,
            },
        )
        audit_store.record_event(audit_rec)

        # If client requested JSON (e.g. API caller), return JSON; otherwise HTTP 302 Redirect
        wants_json = query_params.get("format") == "json"
        if wants_json:
            return format_response(200, {
                "download_url": download_desc.download_url,
                "expires_at_utc": download_desc.expires_at_utc,
                "filename": download_desc.original_filename,
            })

        return {
            "statusCode": 302,
            "headers": {
                "Location": download_desc.download_url,
                "Access-Control-Allow-Origin": "*",
            },
            "body": "",
        }

    except TokenExpiredError as err:
        audit_store.record_event(AuditRecord(
            event_id=f"evt_{TokenService.generate_raw_token(8)}",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            event_type=AuditEventType.ACCESS_REJECTED.value,
            file_id="unknown",
            outcome=AuditOutcome.DENIED.value,
            actor_ip=client_ip,
            user_agent=user_agent,
            token_hash_prefix=token_prefix,
            reason="Access token expired",
        ))
        return format_response(410, {"error": "ACCESS_EXPIRED", "message": str(err)})

    except TokenExhaustedError as err:
        audit_store.record_event(AuditRecord(
            event_id=f"evt_{TokenService.generate_raw_token(8)}",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            event_type=AuditEventType.ACCESS_REJECTED.value,
            file_id="unknown",
            outcome=AuditOutcome.DENIED.value,
            actor_ip=client_ip,
            user_agent=user_agent,
            token_hash_prefix=token_prefix,
            reason="Maximum download ceiling reached",
        ))
        return format_response(410, {"error": "DOWNLOAD_LIMIT_REACHED", "message": str(err)})

    except TokenRevokedError as err:
        audit_store.record_event(AuditRecord(
            event_id=f"evt_{TokenService.generate_raw_token(8)}",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            event_type=AuditEventType.ACCESS_REJECTED.value,
            file_id="unknown",
            outcome=AuditOutcome.DENIED.value,
            actor_ip=client_ip,
            user_agent=user_agent,
            token_hash_prefix=token_prefix,
            reason="Token was revoked by owner",
        ))
        return format_response(403, {"error": "TOKEN_REVOKED", "message": str(err)})

    except TokenNotFoundError as err:
        audit_store.record_event(AuditRecord(
            event_id=f"evt_{TokenService.generate_raw_token(8)}",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            event_type=AuditEventType.ACCESS_REJECTED.value,
            file_id="unknown",
            outcome=AuditOutcome.DENIED.value,
            actor_ip=client_ip,
            user_agent=user_agent,
            reason="Invalid or non-existent token",
        ))
        return format_response(404, {"error": "TOKEN_NOT_FOUND", "message": str(err)})

    except Exception as err:
        return format_response(500, {"error": "DOWNLOAD_FAILED", "message": str(err)})
