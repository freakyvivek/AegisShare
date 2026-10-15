"""AWS Lambda Handler for Listing Share Tokens."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict

from backend.handlers.api_gateway_proxy import format_response, parse_event
from backend.services.dynamodb_service import (
    DynamoDBFilesStore,
    DynamoDBTokenStore,
)
from backend.services.token_service import TokenStatus


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for GET /api/tokens."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    if method == "OPTIONS":
        return format_response(204, "")

    if method != "GET":
        return format_response(405, {"error": "Method not allowed. Use GET."})

    tokens_table = os.environ.get("TOKENS_TABLE_NAME")
    files_table = os.environ.get("FILES_TABLE_NAME")

    if not tokens_table:
        return format_response(500, {
            "error": "CONFIG_ERROR",
            "message": "TOKENS_TABLE_NAME environment variable not set."
        })

    file_id = query_params.get("file_id")

    try:
        tokens_store = DynamoDBTokenStore(table_name=tokens_table)
        files_store = DynamoDBFilesStore(table_name=files_table) if files_table else None

        records = tokens_store.list_tokens_for_file(file_id) if file_id else tokens_store.list_all_tokens()
        now_dt = datetime.now(timezone.utc)

        results = []
        for rec in records:
            status = TokenStatus.VALID
            if rec.is_revoked:
                status = TokenStatus.REVOKED
            elif now_dt >= datetime.fromisoformat(rec.expires_at_utc):
                status = TokenStatus.EXPIRED
            elif rec.max_downloads is not None and rec.download_count >= rec.max_downloads:
                status = TokenStatus.EXHAUSTED

            filename = rec.file_id
            if files_store:
                try:
                    f_meta = files_store.get_file_metadata(rec.file_id)
                    if f_meta:
                        filename = f_meta.original_filename
                except Exception:
                    pass

            results.append({
                "token_hash": rec.token_hash,
                "token_prefix": rec.token_hash[:12] + "...",
                "file_id": rec.file_id,
                "filename": filename,
                "status": status.value,
                "created_at_utc": rec.created_at_utc,
                "expires_at_utc": rec.expires_at_utc,
                "download_count": rec.download_count,
                "max_downloads": rec.max_downloads,
                "is_revoked": rec.is_revoked,
                "revoked_at_utc": rec.revoked_at_utc,
            })

        return format_response(200, {"tokens": results})
    except Exception as err:
        return format_response(500, {"error": "TOKENS_QUERY_FAILED", "message": str(err)})
