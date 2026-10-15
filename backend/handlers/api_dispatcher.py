"""Unified AWS Lambda Dispatcher for API Gateway Proxy Events.

Allows deploying a single unified Lambda function or mapping to individual
handler modules.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from backend.handlers import (
    audit_handler,
    download_handler,
    files_handler,
    health_handler,
    inspect_handler,
    revoke_handler,
    share_handler,
    tokens_handler,
    upload_handler,
)
from backend.handlers.api_gateway_proxy import format_response, parse_event


def normalize_path(path: str, stage: Optional[str] = None) -> str:
    """Normalize request path by removing stage prefix when present.

    When stage is 'dev' (or any named stage other than '$default'), removes
    exactly one leading '/{stage}' prefix if the path is '/{stage}' or begins with
    '/{stage}/'.
    Does not strip arbitrary first path segments or modify unrelated routes.
    Preserves query parameters and existing path matching behavior.
    """
    normalized = path.rstrip("/") if path else ""
    if not stage or stage == "$default":
        return normalized

    stage_prefix = f"/{stage}"
    if normalized == stage_prefix:
        return "/"
    if normalized.startswith(f"{stage_prefix}/"):
        return normalized[len(stage_prefix):]

    return normalized


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Route API Gateway event to appropriate handler based on method and path."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    # Global CORS pre-flight handler
    if method == "OPTIONS":
        return format_response(204, "")

    # Extract stage from event.requestContext.stage if present
    stage = None
    if isinstance(event, dict):
        rc = event.get("requestContext")
        if isinstance(rc, dict):
            stage = rc.get("stage")

    normalized_path = normalize_path(path, stage)

    # Route Table
    if normalized_path in ("/api/health", "/api/status"):
        return health_handler.lambda_handler(event, context)

    if normalized_path == "/api/files":
        return files_handler.lambda_handler(event, context)

    if normalized_path == "/api/upload":
        return upload_handler.lambda_handler(event, context)

    if normalized_path == "/api/share":
        return share_handler.lambda_handler(event, context)

    if normalized_path == "/api/tokens/inspect":
        return inspect_handler.lambda_handler(event, context)

    if normalized_path == "/api/download":
        return download_handler.lambda_handler(event, context)

    if normalized_path == "/api/revoke":
        return revoke_handler.lambda_handler(event, context)

    if normalized_path == "/api/tokens":
        return tokens_handler.lambda_handler(event, context)

    if normalized_path == "/api/audit":
        return audit_handler.lambda_handler(event, context)

    return format_response(404, {"error": "ROUTE_NOT_FOUND", "path": path, "method": method})
