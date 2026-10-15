"""AWS Lambda Handler for Querying Audit Telemetry."""

from __future__ import annotations

import os
from typing import Any, Dict

from backend.handlers.api_gateway_proxy import format_response, parse_event
from backend.services.dynamodb_service import DynamoDBAuditStore


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for GET /api/audit."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    if method == "OPTIONS":
        return format_response(204, "")

    if method != "GET":
        return format_response(405, {"error": "Method not allowed. Use GET."})

    audit_table = os.environ.get("AUDIT_TABLE_NAME")
    if not audit_table:
        return format_response(500, {
            "error": "CONFIG_ERROR",
            "message": "AUDIT_TABLE_NAME environment variable not set."
        })

    file_id = query_params.get("file_id")
    event_type = query_params.get("event_type")
    outcome = query_params.get("outcome")
    limit = int(query_params.get("limit", 100))

    try:
        audit_store = DynamoDBAuditStore(table_name=audit_table)
        records = audit_store.query_events(
            file_id=file_id,
            event_type=event_type,
            outcome=outcome,
            limit=limit,
        )
        return format_response(200, {
            "count": len(records),
            "events": [r.to_dict() for r in records],
        })
    except Exception as err:
        return format_response(500, {"error": "AUDIT_QUERY_FAILED", "message": str(err)})
