"""AWS Lambda Handler for Non-Destructive Token Inspection."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict

from backend.handlers.api_gateway_proxy import format_response, parse_event
from backend.services.dynamodb_service import (
    DynamoDBFilesStore,
    DynamoDBTokenStore,
)
from backend.services.token_service import TokenService, TokenStatus


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for GET /api/tokens/inspect?token=..."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    if method == "OPTIONS":
        return format_response(204, "")

    if method != "GET":
        return format_response(405, {"error": "Method not allowed. Use GET."})

    tokens_table = os.environ.get("TOKENS_TABLE_NAME")
    files_table = os.environ.get("FILES_TABLE_NAME")

    if not tokens_table or not files_table:
        return format_response(500, {
            "error": "CONFIG_ERROR",
            "message": "AWS Lambda environment variables not set."
        })

    raw_token = query_params.get("token")
    if not raw_token:
        return format_response(400, {"error": "Missing 'token' query parameter."})

    tokens_store = DynamoDBTokenStore(table_name=tokens_table)
    files_store = DynamoDBFilesStore(table_name=files_table)

    token_hash = TokenService.hash_token(raw_token)
    record = tokens_store.get_token_record(token_hash)

    if not record:
        return format_response(404, {"status": "NOT_FOUND", "message": "Token does not exist or has expired."})

    # Evaluate current status
    now_dt = datetime.now(timezone.utc)
    expires_at_dt = datetime.fromisoformat(record.expires_at_utc)

    status = TokenStatus.VALID
    if record.is_revoked:
        status = TokenStatus.REVOKED
    elif now_dt >= expires_at_dt:
        status = TokenStatus.EXPIRED
    elif record.max_downloads is not None and record.download_count >= record.max_downloads:
        status = TokenStatus.EXHAUSTED

    file_meta = files_store.get_file_metadata(record.file_id)
    filename = file_meta.original_filename if file_meta else "Unknown"
    file_size = file_meta.file_size_bytes if file_meta else 0

    downloads_left = (
        record.max_downloads - record.download_count
        if record.max_downloads is not None
        else None
    )

    return format_response(200, {
        "status": status.value,
        "file_id": record.file_id,
        "filename": filename,
        "file_size_bytes": file_size,
        "expires_at_utc": record.expires_at_utc,
        "download_count": record.download_count,
        "max_downloads": record.max_downloads,
        "downloads_remaining": downloads_left,
        "is_revoked": record.is_revoked,
    })
