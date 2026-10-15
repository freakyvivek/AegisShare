"""AWS Lambda Handler for Listing Files in Vault."""

from __future__ import annotations

import os
from typing import Any, Dict

from backend.handlers.api_gateway_proxy import format_response, parse_event
from backend.services.dynamodb_service import DynamoDBFilesStore


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for GET /api/files."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    if method == "OPTIONS":
        return format_response(204, "")

    if method != "GET":
        return format_response(405, {"error": "Method not allowed. Use GET."})

    files_table = os.environ.get("FILES_TABLE_NAME")
    if not files_table:
        return format_response(500, {
            "error": "CONFIG_ERROR",
            "message": "FILES_TABLE_NAME environment variable not set."
        })

    try:
        files_store = DynamoDBFilesStore(table_name=files_table)
        files = files_store.list_files()
        return format_response(200, {
            "files": [f.to_dict() for f in files],
        })
    except Exception as err:
        return format_response(500, {"error": "FILES_QUERY_FAILED", "message": str(err)})
