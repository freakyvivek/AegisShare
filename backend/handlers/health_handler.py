"""AWS Lambda Handler for Health and Diagnostic Status."""

from __future__ import annotations

import os
from typing import Any, Dict

from backend.handlers.api_gateway_proxy import format_response, parse_event


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for GET /api/health."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    if method == "OPTIONS":
        return format_response(204, "")

    return format_response(200, {
        "status": "HEALTHY",
        "storage_backend": "aws_s3_dynamodb",
        "aws_region": os.environ.get("AWS_REGION", "us-east-1"),
        "s3_bucket": os.environ.get("S3_BUCKET_NAME", "unconfigured"),
        "files_table": os.environ.get("FILES_TABLE_NAME", "unconfigured"),
        "tokens_table": os.environ.get("TOKENS_TABLE_NAME", "unconfigured"),
        "audit_table": os.environ.get("AUDIT_TABLE_NAME", "unconfigured"),
    })
