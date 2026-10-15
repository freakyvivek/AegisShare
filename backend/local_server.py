"""Local Demo HTTP Server for Secure File Sharing.

Provides a standard library HTTP server (zero external dependencies)
implementing the complete REST API contract for offline demonstration and
local integration testing.

Endpoints:
- GET  /api/health            : Health check and service status.
- GET  /api/files             : List stored demo files.
- POST /api/upload            : Upload file payload to local storage.
- POST /api/share             : Create an expiring access token.
- GET  /api/tokens/inspect    : Inspect token status without consuming download.
- GET  /api/download          : Validate token, consume download, and stream file.
- POST /api/revoke            : Revoke an active access token.
- GET  /api/audit             : Query immutable audit logs.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import secrets
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

# Ensure project root is available in sys.path when invoked directly
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.services.audit_service import (
    AuditEventType,
    AuditOutcome,
    AuditService,
)
from backend.services.storage_service import (
    FileNotFoundStorageError,
    LocalStorageService,
)
from backend.services.token_service import (
    TokenError,
    TokenExhaustedError,
    TokenExpiredError,
    TokenNotFoundError,
    TokenRevokedError,
    TokenService,
    TokenStatus,
)

BASE_DIR = Path(__file__).resolve().parent.parent
LOCAL_DATA_DIR = BASE_DIR / "local_storage"


class SecureFileSharingHandler(BaseHTTPRequestHandler):
    """HTTP request handler for secure file sharing operations."""

    storage: LocalStorageService
    tokens: TokenService
    audit: AuditService

    def log_message(self, format: str, *args: Any) -> None:
        """Clean HTTP access logger."""
        print(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}")

    def _send_cors_headers(self) -> None:
        """Enable CORS for web clients."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, X-Requested-With",
        )

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def _send_json_response(self, status: int, data: Dict[str, Any]) -> None:
        """Send formatted JSON HTTP response."""
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _parse_json_body(self) -> Dict[str, Any]:
        """Read and decode JSON request payload."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        body_bytes = self.rfile.read(content_length)
        return json.loads(body_bytes.decode("utf-8"))

    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        query = parse_qs(parsed_url.query)

        # 1. Health & Status
        if path in ("/api/health", "/api/status"):
            self._send_json_response(
                HTTPStatus.OK,
                {
                    "status": "HEALTHY",
                    "storage_backend": self.storage.BACKEND_NAME,
                    "local_data_dir": str(self.storage.base_dir),
                    "total_audit_events": self.audit.count_events(),
                },
            )
            return

        # 2. List Files (Demo Helper)
        if path == "/api/files":
            files = []
            for f in self.storage.files_dir.glob("*"):
                if f.is_file():
                    try:
                        meta = self.storage.get_file_metadata(f.name)
                        files.append(meta.to_dict())
                    except Exception:
                        pass
            self._send_json_response(HTTPStatus.OK, {"files": files})
            return

        # 2b. List Tokens (Active Share Links)
        if path == "/api/tokens":
            file_id = query.get("file_id", [None])[0]
            if file_id:
                token_records = self.tokens.list_tokens_for_file(file_id)
            else:
                token_records = self.tokens.list_all_tokens()

            now_dt = datetime.now(timezone.utc)
            results = []
            for rec in token_records:
                status = TokenStatus.VALID
                if rec.is_revoked:
                    status = TokenStatus.REVOKED
                elif now_dt >= datetime.fromisoformat(rec.expires_at_utc):
                    status = TokenStatus.EXPIRED
                elif rec.max_downloads is not None and rec.download_count >= rec.max_downloads:
                    status = TokenStatus.EXHAUSTED

                try:
                    file_meta = self.storage.get_file_metadata(rec.file_id)
                    filename = file_meta.original_filename
                except Exception:
                    filename = rec.file_id

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

            self._send_json_response(HTTPStatus.OK, {"tokens": results})
            return

        # 2c. Static File Serving (Frontend SPA)
        if not path.startswith("/api"):
            frontend_dir = BASE_DIR / "frontend"
            rel_path = path.lstrip("/")
            if rel_path == "" or rel_path == "index.html":
                target_file = frontend_dir / "index.html"
            else:
                target_file = (frontend_dir / rel_path).resolve()

            try:
                target_file.relative_to(frontend_dir.resolve())
            except ValueError:
                self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Access denied."})
                return

            if target_file.exists() and target_file.is_file():
                mime, _ = mimetypes.guess_type(str(target_file))
                mime = mime or "application/octet-stream"
                file_bytes = target_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self._send_cors_headers()
                self.send_header(
                    "Content-Type",
                    f"{mime}; charset=utf-8" if "text" in mime or "javascript" in mime else mime,
                )
                self.send_header("Content-Length", str(len(file_bytes)))
                self.end_headers()
                self.wfile.write(file_bytes)
                return

        # 3. Inspect Token Status (Non-destructive)
        if path == "/api/tokens/inspect":
            raw_token = query.get("token", [""])[0]
            if not raw_token:
                self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing 'token' query parameter."})
                return

            status, record = self.tokens.inspect_token_status(raw_token)
            if status == TokenStatus.NOT_FOUND or record is None:
                self._send_json_response(
                    HTTPStatus.NOT_FOUND,
                    {"status": "NOT_FOUND", "message": "Token does not exist or has expired."},
                )
                return

            try:
                file_meta = self.storage.get_file_metadata(record.file_id)
                filename = file_meta.original_filename
                size = file_meta.file_size_bytes
            except Exception:
                filename = "Unknown"
                size = 0

            downloads_left = (
                record.max_downloads - record.download_count
                if record.max_downloads is not None
                else None
            )

            self._send_json_response(
                HTTPStatus.OK,
                {
                    "status": status.value,
                    "file_id": record.file_id,
                    "filename": filename,
                    "file_size_bytes": size,
                    "expires_at_utc": record.expires_at_utc,
                    "download_count": record.download_count,
                    "max_downloads": record.max_downloads,
                    "downloads_remaining": downloads_left,
                    "is_revoked": record.is_revoked,
                },
            )
            return

        # 4. Download File with Token Enforcement
        if path == "/api/download":
            raw_token = query.get("token", [""])[0]
            client_ip = self.client_address[0] if self.client_address else "unknown"
            user_agent = self.headers.get("User-Agent", "unknown")

            if not raw_token:
                self.audit.record_event(
                    event_type=AuditEventType.ACCESS_REJECTED,
                    file_id="unknown",
                    outcome=AuditOutcome.DENIED,
                    actor_ip=client_ip,
                    user_agent=user_agent,
                    reason="Missing token parameter",
                )
                self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing 'token' query parameter."})
                return

            try:
                # Validates token, enforces expiration and download count limits
                record = self.tokens.consume_download(raw_token)
                file_bytes, meta = self.storage.get_file_bytes(record.file_id)

                # Record success in audit log
                self.audit.record_event(
                    event_type=AuditEventType.DOWNLOAD_SUCCESS,
                    file_id=record.file_id,
                    outcome=AuditOutcome.SUCCESS,
                    actor_ip=client_ip,
                    user_agent=user_agent,
                    token_hash=record.token_hash,
                    details={
                        "filename": meta.original_filename,
                        "file_size_bytes": len(file_bytes),
                        "download_count": record.download_count,
                        "max_downloads": record.max_downloads,
                    },
                )

                # Stream file payload
                self.send_response(HTTPStatus.OK)
                self._send_cors_headers()
                self.send_header("Content-Type", meta.content_type)
                self.send_header("Content-Length", str(len(file_bytes)))
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{meta.original_filename}"',
                )
                self.end_headers()
                self.wfile.write(file_bytes)
                return

            except TokenExpiredError as err:
                status, rec = self.tokens.inspect_token_status(raw_token)
                file_id = rec.file_id if rec else "unknown"
                token_hash = rec.token_hash if rec else None
                self.audit.record_event(
                    event_type=AuditEventType.ACCESS_REJECTED,
                    file_id=file_id,
                    outcome=AuditOutcome.DENIED,
                    actor_ip=client_ip,
                    user_agent=user_agent,
                    token_hash=token_hash,
                    reason="Access token expired",
                )
                self._send_json_response(HTTPStatus.GONE, {"error": "ACCESS_EXPIRED", "message": str(err)})
                return

            except TokenExhaustedError as err:
                status, rec = self.tokens.inspect_token_status(raw_token)
                file_id = rec.file_id if rec else "unknown"
                token_hash = rec.token_hash if rec else None
                self.audit.record_event(
                    event_type=AuditEventType.ACCESS_REJECTED,
                    file_id=file_id,
                    outcome=AuditOutcome.DENIED,
                    actor_ip=client_ip,
                    user_agent=user_agent,
                    token_hash=token_hash,
                    reason="Download limit reached",
                )
                self._send_json_response(HTTPStatus.GONE, {"error": "DOWNLOAD_LIMIT_REACHED", "message": str(err)})
                return

            except TokenRevokedError as err:
                status, rec = self.tokens.inspect_token_status(raw_token)
                file_id = rec.file_id if rec else "unknown"
                token_hash = rec.token_hash if rec else None
                self.audit.record_event(
                    event_type=AuditEventType.ACCESS_REJECTED,
                    file_id=file_id,
                    outcome=AuditOutcome.DENIED,
                    actor_ip=client_ip,
                    user_agent=user_agent,
                    token_hash=token_hash,
                    reason="Token was revoked by owner",
                )
                self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "TOKEN_REVOKED", "message": str(err)})
                return

            except TokenNotFoundError as err:
                self.audit.record_event(
                    event_type=AuditEventType.ACCESS_REJECTED,
                    file_id="unknown",
                    outcome=AuditOutcome.DENIED,
                    actor_ip=client_ip,
                    user_agent=user_agent,
                    reason="Invalid token",
                )
                self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "TOKEN_INVALID", "message": str(err)})
                return

            except FileNotFoundStorageError as err:
                self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "FILE_NOT_FOUND", "message": str(err)})
                return

        # 5. Query Audit Logs
        if path == "/api/audit":
            file_id = query.get("file_id", [None])[0]
            event_type = query.get("event_type", [None])[0]
            limit = int(query.get("limit", [50])[0])

            events = self.audit.query_events(file_id=file_id, event_type=event_type, limit=limit)
            self._send_json_response(
                HTTPStatus.OK,
                {
                    "count": len(events),
                    "events": [e.to_dict() for e in events],
                },
            )
            return

        self._send_json_response(HTTPStatus.NOT_FOUND, {"error": f"Path '{path}' not found."})

    def do_POST(self) -> None:
        """Handle POST requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        client_ip = self.client_address[0] if self.client_address else "unknown"
        user_agent = self.headers.get("User-Agent", "unknown")

        # 1. File Upload (Multipart Form or Direct Binary Body)
        if path == "/api/upload":
            content_type = self.headers.get("Content-Type", "")
            file_id = f"file_{secrets.token_hex(6)}"

            if "multipart/form-data" in content_type:
                # Handle standard multipart file upload
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length)

                # Boundary extraction
                boundary_match = re.search(r"boundary=(.*)", content_type)
                if not boundary_match:
                    self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Malformed multipart boundary."})
                    return

                boundary = boundary_match.group(1).encode("utf-8").strip(b'"')
                parts = body.split(b"--" + boundary)

                filename = "uploaded_file.bin"
                file_bytes = b""
                part_content_type = "application/octet-stream"

                for part in parts:
                    if b'Content-Disposition: form-data; name="file"' in part:
                        # Extract filename if available
                        fn_match = re.search(rb'filename="([^"]+)"', part)
                        if fn_match:
                            filename = fn_match.group(1).decode("utf-8", errors="replace")
                        # Extract content type
                        ct_match = re.search(rb"Content-Type:\s*([^\r\n]+)", part)
                        if ct_match:
                            part_content_type = ct_match.group(1).decode("utf-8", errors="replace")
                        # File content begins after double CRLF
                        header_end = part.find(b"\r\n\r\n")
                        if header_end != -1:
                            file_bytes = part[header_end + 4 :].rstrip(b"\r\n")
                            break

                if not file_bytes:
                    self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "No file content detected."})
                    return

            else:
                # Direct binary or application/json upload
                filename = self.headers.get("X-File-Name", f"file_{secrets.token_hex(4)}.dat")
                part_content_type = content_type or "application/octet-stream"
                content_length = int(self.headers.get("Content-Length", 0))
                file_bytes = self.rfile.read(content_length)

            # Save in local demo storage
            meta = self.storage.save_file(
                file_id=file_id,
                filename=filename,
                data=file_bytes,
                content_type=part_content_type,
            )

            # Record in Audit Log
            self.audit.record_event(
                event_type=AuditEventType.FILE_UPLOAD,
                file_id=file_id,
                outcome=AuditOutcome.SUCCESS,
                actor_ip=client_ip,
                user_agent=user_agent,
                details={
                    "filename": meta.original_filename,
                    "file_size_bytes": meta.file_size_bytes,
                    "content_type": meta.content_type,
                    "storage_backend": meta.storage_backend,
                },
            )

            self._send_json_response(
                HTTPStatus.CREATED,
                {
                    "message": "File uploaded successfully.",
                    "file_id": meta.file_id,
                    "filename": meta.original_filename,
                    "file_size_bytes": meta.file_size_bytes,
                    "content_type": meta.content_type,
                    "storage_backend": meta.storage_backend,
                },
            )
            return

        # 2. Create Expiring Share Token
        if path == "/api/share":
            data = self._parse_json_body()
            file_id = data.get("file_id")
            expires_in_seconds = int(data.get("expires_in_seconds", 3600))
            max_downloads = data.get("max_downloads")
            if max_downloads is not None:
                max_downloads = int(max_downloads)

            if not file_id:
                self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing 'file_id' field."})
                return

            if not self.storage.file_exists(file_id):
                self._send_json_response(
                    HTTPStatus.NOT_FOUND,
                    {"error": f"File '{file_id}' does not exist in storage."},
                )
                return

            raw_token, record = self.tokens.create_token(
                file_id=file_id,
                expires_in_seconds=expires_in_seconds,
                max_downloads=max_downloads,
            )

            # Record link creation in audit log
            self.audit.record_event(
                event_type=AuditEventType.SHARE_LINK_CREATED,
                file_id=file_id,
                outcome=AuditOutcome.SUCCESS,
                actor_ip=client_ip,
                user_agent=user_agent,
                token_hash=record.token_hash,
                details={
                    "expires_at_utc": record.expires_at_utc,
                    "max_downloads": record.max_downloads,
                    "expires_in_seconds": expires_in_seconds,
                },
            )

            share_url = f"{self.storage.base_url}/api/download?token={raw_token}"

            self._send_json_response(
                HTTPStatus.CREATED,
                {
                    "message": "Share link created successfully.",
                    "file_id": file_id,
                    "raw_token": raw_token,
                    "expires_at_utc": record.expires_at_utc,
                    "max_downloads": record.max_downloads,
                    "share_url": share_url,
                },
            )
            return

        # 3. Revoke Token
        if path == "/api/revoke":
            data = self._parse_json_body()
            raw_token = data.get("token")
            token_hash = data.get("token_hash")

            if not raw_token and not token_hash:
                self._send_json_response(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "Provide either 'token' or 'token_hash' to revoke."},
                )
                return

            try:
                if raw_token:
                    record = self.tokens.revoke_token(raw_token)
                else:
                    record = self.tokens.revoke_token_by_hash(token_hash)

                self.audit.record_event(
                    event_type=AuditEventType.TOKEN_REVOKED,
                    file_id=record.file_id,
                    outcome=AuditOutcome.SUCCESS,
                    actor_ip=client_ip,
                    user_agent=user_agent,
                    token_hash=record.token_hash,
                    reason="Explicit revocation by user",
                )

                self._send_json_response(
                    HTTPStatus.OK,
                    {
                        "message": "Token revoked successfully.",
                        "file_id": record.file_id,
                        "revoked_at_utc": record.revoked_at_utc,
                    },
                )
                return
            except TokenNotFoundError as err:
                self._send_json_response(HTTPStatus.NOT_FOUND, {"error": str(err)})
                return

        self._send_json_response(HTTPStatus.NOT_FOUND, {"error": f"Path '{path}' not found."})


def create_app(data_dir: Optional[Path | str] = None, base_url: str = "http://localhost:8000"):
    """Instantiate services for the HTTP server."""
    storage_path = Path(data_dir) if data_dir else LOCAL_DATA_DIR
    storage = LocalStorageService(base_directory=storage_path, base_url=base_url)
    tokens = TokenService()
    audit = AuditService(log_file_path=storage_path / "audit_log.jsonl")

    SecureFileSharingHandler.storage = storage
    SecureFileSharingHandler.tokens = tokens
    SecureFileSharingHandler.audit = audit

    return storage, tokens, audit


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run local development server."""
    base_url = f"http://{host}:{port}"
    create_app(data_dir=LOCAL_DATA_DIR, base_url=base_url)

    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, SecureFileSharingHandler)
    print("=" * 65)
    print(f" Secure File Sharing - Local Demonstration Server")
    print("=" * 65)
    print(f" Host:            http://{host}:{port}")
    print(f" Local Storage:   {LOCAL_DATA_DIR / 'files'}")
    print(f" Audit Logs:      {LOCAL_DATA_DIR / 'audit_log.jsonl'}")
    print(f" Storage Backend: local_demo_storage (Explicitly identified)")
    print("=" * 65)
    print(" Press Ctrl+C to terminate.")
    print("=" * 65)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server gracefully...")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure File Sharing Local Demo Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)
