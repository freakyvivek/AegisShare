"""AWS Lambda Handler for Creating Expiring Share Tokens."""

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
from backend.services.token_service import TokenRecord, TokenService


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for POST /api/share."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    if method == "OPTIONS":
        return format_response(204, "")

    if method != "POST":
        return format_response(405, {"error": "Method not allowed. Use POST."})

    tokens_table = os.environ.get("TOKENS_TABLE_NAME")
    files_table = os.environ.get("FILES_TABLE_NAME")
    audit_table = os.environ.get("AUDIT_TABLE_NAME")
    api_base_url = os.environ.get("API_BASE_URL", "").rstrip("/")

    if not tokens_table or not files_table or not audit_table:
        return format_response(500, {
            "error": "CONFIG_ERROR",
            "message": "AWS Lambda environment variables (TOKENS_TABLE_NAME, FILES_TABLE_NAME, AUDIT_TABLE_NAME) not set."
        })

    if not isinstance(body, dict):
        return format_response(400, {"error": "Request body must be a JSON object."})

    file_id = body.get("file_id")
    expires_in_seconds = int(body.get("expires_in_seconds", 3600))
    max_downloads = body.get("max_downloads")
    if max_downloads is not None:
        max_downloads = int(max_downloads)

    if not file_id:
        return format_response(400, {"error": "Missing 'file_id' parameter."})

    if expires_in_seconds <= 0:
        return format_response(400, {"error": "expires_in_seconds must be greater than zero."})

    try:
        files_store = DynamoDBFilesStore(table_name=files_table)
        tokens_store = DynamoDBTokenStore(table_name=tokens_table)
        audit_store = DynamoDBAuditStore(table_name=audit_table)

        # 1. Verify file exists
        file_meta = files_store.get_file_metadata(file_id)
        if not file_meta:
            return format_response(404, {"error": f"File '{file_id}' not found in metadata registry."})

        # 2. Generate secure token & calculate expiration
        raw_token = TokenService.generate_raw_token()
        token_hash = TokenService.hash_token(raw_token)

        now_utc = datetime.now(timezone.utc)
        expires_at_dt = datetime.fromtimestamp(now_utc.timestamp() + expires_in_seconds, tz=timezone.utc)

        record = TokenRecord(
            token_hash=token_hash,
            file_id=file_id,
            created_at_utc=now_utc.isoformat(),
            expires_at_utc=expires_at_dt.isoformat(),
            max_downloads=max_downloads,
            download_count=0,
            is_revoked=False,
            revoked_at_utc=None,
        )

        tokens_store.save_token_record(record)

        # 3. Log audit event
        audit_rec = AuditRecord(
            event_id=f"evt_{TokenService.generate_raw_token(8)}",
            timestamp_utc=now_utc.isoformat(),
            event_type=AuditEventType.SHARE_LINK_CREATED.value,
            file_id=file_id,
            outcome=AuditOutcome.SUCCESS.value,
            actor_ip=client_ip,
            user_agent=user_agent,
            token_hash_prefix=AuditService._safe_token_prefix(token_hash),
            details={
                "expires_at_utc": record.expires_at_utc,
                "max_downloads": record.max_downloads,
                "expires_in_seconds": expires_in_seconds,
            },
        )
        audit_store.record_event(audit_rec)

        share_url = f"{api_base_url}/api/download?token={raw_token}" if api_base_url else f"/api/download?token={raw_token}"

        return format_response(201, {
            "message": "Share link created successfully.",
            "file_id": file_id,
            "raw_token": raw_token,
            "expires_at_utc": record.expires_at_utc,
            "max_downloads": record.max_downloads,
            "share_url": share_url,
        })

    except Exception as err:
        return format_response(500, {"error": "SHARE_CREATION_FAILED", "message": str(err)})
