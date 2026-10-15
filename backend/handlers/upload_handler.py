"""AWS Lambda Handler for File Uploads and Presigned Upload Generation."""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.handlers.api_gateway_proxy import format_response, parse_event
from backend.services.audit_service import (
    AuditEventType,
    AuditOutcome,
    AuditRecord,
)
from backend.services.dynamodb_service import (
    DynamoDBAuditStore,
    DynamoDBFilesStore,
)
from backend.services.storage_service import (
    FileMetadata,
    S3StorageService,
)


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """Lambda entry point for POST /api/upload."""
    method, path, query_params, body, client_ip, user_agent = parse_event(event)

    if method == "OPTIONS":
        return format_response(204, "")

    if method != "POST":
        return format_response(405, {"error": "Method not allowed. Use POST."})

    bucket_name = os.environ.get("S3_BUCKET_NAME")
    files_table = os.environ.get("FILES_TABLE_NAME")
    audit_table = os.environ.get("AUDIT_TABLE_NAME")
    region_name = os.environ.get("AWS_REGION", "us-east-1")
    kms_key_id = os.environ.get("KMS_KEY_ID")

    if not bucket_name or not files_table or not audit_table:
        return format_response(500, {
            "error": "CONFIG_ERROR",
            "message": "AWS Lambda environment variables (S3_BUCKET_NAME, FILES_TABLE_NAME, AUDIT_TABLE_NAME) not set."
        })

    try:
        storage = S3StorageService(bucket_name=bucket_name, region_name=region_name, kms_key_id=kms_key_id)
        files_store = DynamoDBFilesStore(table_name=files_table)
        audit_store = DynamoDBAuditStore(table_name=audit_table)

        file_id = f"file_{secrets.token_hex(6)}"

        # Case A: Request Presigned Upload URL
        if isinstance(body, dict) and (body.get("action") == "presigned_url" or body.get("generate_presigned")):
            filename = body.get("filename", "upload.bin")
            content_type = body.get("content_type", "application/octet-stream")
            expires_in = int(body.get("expires_in_seconds", 300))

            descriptor = storage.generate_upload_descriptor(
                file_id=file_id,
                filename=filename,
                expires_in_seconds=expires_in,
                content_type=content_type,
            )

            meta = FileMetadata(
                file_id=file_id,
                original_filename=filename,
                file_size_bytes=0,  # Will be finalized upon S3 object created event
                content_type=content_type,
                uploaded_at_utc=datetime.now(timezone.utc).isoformat(),
                storage_backend=storage.BACKEND_NAME,
                storage_key_or_path=f"uploads/{file_id}",
            )
            files_store.save_file_metadata(meta)

            audit_rec = AuditRecord(
                event_id=f"evt_{secrets.token_hex(8)}",
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                event_type=AuditEventType.FILE_UPLOAD.value,
                file_id=file_id,
                outcome=AuditOutcome.SUCCESS.value,
                actor_ip=client_ip,
                user_agent=user_agent,
                details={"filename": filename, "type": "PRESIGNED_PUT_ISSUED"},
            )
            audit_store.record_event(audit_rec)

            return format_response(201, {
                "message": "Presigned upload descriptor generated.",
                "file_id": file_id,
                "upload_descriptor": descriptor.to_dict(),
            })

        # Case B: Direct Binary Upload via Lambda
        if isinstance(body, (bytes, str)):
            file_bytes = body if isinstance(body, bytes) else body.encode("utf-8")
            raw_headers = event.get("headers") or {}
            filename = raw_headers.get("x-file-name") or raw_headers.get("X-File-Name") or "uploaded_file.bin"
            content_type = raw_headers.get("content-type") or "application/octet-stream"

            meta = storage.save_file(
                file_id=file_id,
                filename=filename,
                data=file_bytes,
                content_type=content_type,
            )
            files_store.save_file_metadata(meta)

            audit_rec = AuditRecord(
                event_id=f"evt_{secrets.token_hex(8)}",
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                event_type=AuditEventType.FILE_UPLOAD.value,
                file_id=file_id,
                outcome=AuditOutcome.SUCCESS.value,
                actor_ip=client_ip,
                user_agent=user_agent,
                details={
                    "filename": meta.original_filename,
                    "file_size_bytes": meta.file_size_bytes,
                    "content_type": meta.content_type,
                    "storage_backend": meta.storage_backend,
                },
            )
            audit_store.record_event(audit_rec)

            return format_response(201, {
                "message": "File uploaded directly to encrypted S3 storage.",
                "file_id": meta.file_id,
                "filename": meta.original_filename,
                "file_size_bytes": meta.file_size_bytes,
                "content_type": meta.content_type,
                "storage_backend": meta.storage_backend,
            })

        return format_response(400, {"error": "Invalid upload payload."})

    except Exception as err:
        return format_response(500, {"error": "UPLOAD_FAILED", "message": str(err)})
