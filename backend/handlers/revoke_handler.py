"""AWS Lambda Handler for Revoking Expiring Share Tokens."""

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
    DynamoDBTokenStore,
)
from backend.services.token_service import TokenNotFoundError, TokenService


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for POST /api/revoke."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    if method == "OPTIONS":
        return format_response(204, "")

    if method != "POST":
        return format_response(405, {"error": "Method not allowed. Use POST."})

    tokens_table = os.environ.get("TOKENS_TABLE_NAME")
    audit_table = os.environ.get("AUDIT_TABLE_NAME")

    if not tokens_table or not audit_table:
        return format_response(500, {
            "error": "CONFIG_ERROR",
            "message": "AWS Lambda environment variables not set."
        })

    if not isinstance(body, dict):
        return format_response(400, {"error": "Body must be a JSON object."})

    raw_token = body.get("token")
    token_hash = body.get("token_hash")

    if not raw_token and not token_hash:
        return format_response(400, {"error": "Provide either 'token' or 'token_hash' to revoke."})

    if raw_token:
        token_hash = TokenService.hash_token(raw_token)

    tokens_store = DynamoDBTokenStore(table_name=tokens_table)
    audit_store = DynamoDBAuditStore(table_name=audit_table)

    try:
        record = tokens_store.revoke_token(token_hash)

        audit_rec = AuditRecord(
            event_id=f"evt_{TokenService.generate_raw_token(8)}",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            event_type=AuditEventType.TOKEN_REVOKED.value,
            file_id=record.file_id,
            outcome=AuditOutcome.SUCCESS.value,
            actor_ip=client_ip,
            user_agent=user_agent,
            token_hash_prefix=AuditService._safe_token_prefix(token_hash),
            reason="Explicit revocation by user",
        )
        audit_store.record_event(audit_rec)

        return format_response(200, {
            "message": "Token revoked successfully.",
            "file_id": record.file_id,
            "revoked_at_utc": record.revoked_at_utc,
        })
    except TokenNotFoundError as err:
        return format_response(404, {"error": str(err)})
    except Exception as err:
        return format_response(500, {"error": "REVOCATION_FAILED", "message": str(err)})
