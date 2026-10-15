"""API Gateway Proxy Response & Event Parsing Utilities for AWS Lambda."""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional, Tuple


def parse_event(event: Dict[str, Any]) -> Tuple[str, str, Dict[str, str], Any, str, str]:
    """Extract standard request components from an API Gateway HTTP/REST event.
    
    Returns:
        (http_method, path, query_params, parsed_body, client_ip, user_agent)
    """
    # 1. Method
    http_method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method")
        or "GET"
    ).upper()

    # 2. Path
    path = (
        event.get("path")
        or event.get("rawPath")
        or event.get("requestContext", {}).get("http", {}).get("path")
        or "/"
    ).rstrip("/")

    # 3. Query string parameters
    query_params = event.get("queryStringParameters") or {}

    # 4. Headers
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    # 5. Client IP & User Agent
    client_ip = (
        headers.get("x-forwarded-for", "").split(",")[0].strip()
        or event.get("requestContext", {}).get("identity", {}).get("sourceIp")
        or event.get("requestContext", {}).get("http", {}).get("sourceIp")
        or "unknown"
    )
    user_agent = headers.get("user-agent", "unknown")

    # 6. Body decoding
    raw_body = event.get("body")
    parsed_body = {}

    if raw_body:
        if event.get("isBase64Encoded", False):
            try:
                decoded_bytes = base64.b64decode(raw_body)
                try:
                    parsed_body = json.loads(decoded_bytes.decode("utf-8"))
                except Exception:
                    parsed_body = decoded_bytes  # binary payload
            except Exception:
                parsed_body = {}
        else:
            try:
                parsed_body = json.loads(raw_body)
            except Exception:
                parsed_body = raw_body

    return http_method, path, query_params, parsed_body, client_ip, user_agent


def format_response(
    status_code: int,
    body: Any,
    headers: Optional[Dict[str, str]] = None,
    is_base64: bool = False,
) -> Dict[str, Any]:
    """Format standard API Gateway Lambda Proxy response with CORS headers."""
    response_headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE, PUT",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, X-File-Name",
    }
    if headers:
        response_headers.update(headers)

    formatted_body = body
    if not isinstance(body, (str, bytes)):
        formatted_body = json.dumps(body, indent=2)
    elif isinstance(body, bytes):
        formatted_body = base64.b64encode(body).decode("utf-8")
        is_base64 = True

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": formatted_body,
        "isBase64Encoded": is_base64,
    }
