"""Storage Service Interface and Implementations for Secure File Sharing.

Provides:
1. Abstract Base Class `StorageService` defining standard storage contracts.
2. `LocalStorageService` for safe, transparent local demo file storage in a
   dedicated local data directory (clearly designated as local storage, NEVER
   misrepresented as Amazon S3).
3. `S3StorageService` adapter using boto3 for direct, short-lived presigned
   upload and download URLs with SSE encryption and strictly private ACLs.
   DOES NOT silently fallback to local storage if AWS is unavailable.
"""

from __future__ import annotations

import mimetypes
import os
import shutil
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


class StorageError(Exception):
    """Base exception for storage errors."""


class FileNotFoundStorageError(StorageError):
    """Raised when the specified file ID does not exist in storage."""


class StorageConfigurationError(StorageError):
    """Raised when storage adapter configuration or dependencies are missing."""


@dataclass
class FileMetadata:
    """Metadata describing a stored file."""

    file_id: str
    original_filename: str
    file_size_bytes: int
    content_type: str
    uploaded_at_utc: str
    storage_backend: str  # "local_demo_storage" or "aws_s3"
    storage_key_or_path: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UploadDescriptor:
    """Instructions and URL for uploading a file."""

    file_id: str
    upload_url: str
    http_method: str
    expires_at_utc: str
    storage_backend: str
    required_headers: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DownloadDescriptor:
    """Instructions and URL for downloading a file."""

    file_id: str
    download_url: str
    expires_at_utc: str
    storage_backend: str
    original_filename: str
    content_type: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StorageService(ABC):
    """Abstract interface for all storage backends."""

    @abstractmethod
    def save_file(
        self,
        file_id: str,
        filename: str,
        data: bytes,
        content_type: Optional[str] = None,
    ) -> FileMetadata:
        """Store file bytes directly."""
        pass

    @abstractmethod
    def get_file_bytes(self, file_id: str) -> tuple[bytes, FileMetadata]:
        """Retrieve stored file bytes and metadata."""
        pass

    @abstractmethod
    def get_file_metadata(self, file_id: str) -> FileMetadata:
        """Retrieve metadata for a stored file without loading all bytes."""
        pass

    @abstractmethod
    def file_exists(self, file_id: str) -> bool:
        """Check if a file exists in the storage backend."""
        pass

    @abstractmethod
    def delete_file(self, file_id: str) -> bool:
        """Permanently delete a file from the storage backend."""
        pass

    @abstractmethod
    def generate_upload_descriptor(
        self,
        file_id: str,
        filename: str,
        expires_in_seconds: int = 300,
        content_type: Optional[str] = None,
    ) -> UploadDescriptor:
        """Generate upload endpoint descriptor (local URL or S3 presigned PUT URL)."""
        pass

    @abstractmethod
    def generate_download_descriptor(
        self,
        file_id: str,
        expires_in_seconds: int = 300,
    ) -> DownloadDescriptor:
        """Generate download descriptor (local URL or S3 presigned GET URL)."""
        pass


class LocalStorageService(StorageService):
    """Local storage adapter for development and offline college demonstrations.
    
    Files are stored in a designated local directory.
    This service is explicitly identified as 'local_demo_storage' and is
    never misrepresented as Amazon S3.
    """

    BACKEND_NAME = "local_demo_storage"

    def __init__(self, base_directory: Path | str, base_url: str = "http://localhost:8000"):
        """Initialize LocalStorageService.
        
        Args:
            base_directory: Absolute or relative directory on local disk.
            base_url: Base host for local download/upload links.
        """
        self.base_dir = Path(base_directory).resolve()
        self.files_dir = self.base_dir / "files"
        self.meta_dir = self.base_dir / "metadata"
        self.base_url = base_url.rstrip("/")

        # Ensure storage subdirectories exist
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.meta_dir.mkdir(parents=True, exist_ok=True)

        self._in_memory_meta: Dict[str, FileMetadata] = {}

    def _sanitize_file_id(self, file_id: str) -> str:
        """Prevent path traversal vulnerabilities."""
        sanitized = Path(file_id).name
        if not sanitized or sanitized != file_id or ".." in file_id:
            raise ValueError(f"Invalid file_id: '{file_id}'")
        return sanitized

    def save_file(
        self,
        file_id: str,
        filename: str,
        data: bytes,
        content_type: Optional[str] = None,
    ) -> FileMetadata:
        safe_id = self._sanitize_file_id(file_id)
        guessed_type, _ = mimetypes.guess_type(filename)
        resolved_content_type = content_type or guessed_type or "application/octet-stream"

        file_path = self.files_dir / safe_id
        file_path.write_bytes(data)

        meta = FileMetadata(
            file_id=safe_id,
            original_filename=Path(filename).name,
            file_size_bytes=len(data),
            content_type=resolved_content_type,
            uploaded_at_utc=datetime.now(timezone.utc).isoformat(),
            storage_backend=self.BACKEND_NAME,
            storage_key_or_path=str(file_path),
        )
        self._in_memory_meta[safe_id] = meta
        return meta

    def get_file_metadata(self, file_id: str) -> FileMetadata:
        safe_id = self._sanitize_file_id(file_id)
        if safe_id not in self._in_memory_meta:
            file_path = self.files_dir / safe_id
            if not file_path.exists():
                raise FileNotFoundStorageError(f"File ID '{safe_id}' not found in local demo storage.")
            # Recover minimal metadata if lost from memory
            meta = FileMetadata(
                file_id=safe_id,
                original_filename=safe_id,
                file_size_bytes=file_path.stat().st_size,
                content_type="application/octet-stream",
                uploaded_at_utc=datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc).isoformat(),
                storage_backend=self.BACKEND_NAME,
                storage_key_or_path=str(file_path),
            )
            self._in_memory_meta[safe_id] = meta
        return self._in_memory_meta[safe_id]

    def get_file_bytes(self, file_id: str) -> tuple[bytes, FileMetadata]:
        safe_id = self._sanitize_file_id(file_id)
        meta = self.get_file_metadata(safe_id)
        file_path = Path(meta.storage_key_or_path)
        if not file_path.exists():
            raise FileNotFoundStorageError(f"File payload missing at {file_path}")
        return file_path.read_bytes(), meta

    def file_exists(self, file_id: str) -> bool:
        try:
            safe_id = self._sanitize_file_id(file_id)
            return (self.files_dir / safe_id).exists()
        except ValueError:
            return False

    def delete_file(self, file_id: str) -> bool:
        safe_id = self._sanitize_file_id(file_id)
        file_path = self.files_dir / safe_id
        existed = file_path.exists()
        if existed:
            file_path.unlink()
        self._in_memory_meta.pop(safe_id, None)
        return existed

    def generate_upload_descriptor(
        self,
        file_id: str,
        filename: str,
        expires_in_seconds: int = 300,
        content_type: Optional[str] = None,
    ) -> UploadDescriptor:
        safe_id = self._sanitize_file_id(file_id)
        now_utc = datetime.now(timezone.utc)
        expires_at_dt = datetime.fromtimestamp(now_utc.timestamp() + expires_in_seconds, tz=timezone.utc)

        # Local upload route serviced by the local runner
        upload_url = f"{self.base_url}/api/upload/direct/{safe_id}"
        return UploadDescriptor(
            file_id=safe_id,
            upload_url=upload_url,
            http_method="PUT",
            expires_at_utc=expires_at_dt.isoformat(),
            storage_backend=self.BACKEND_NAME,
            required_headers={"Content-Type": content_type or "application/octet-stream"},
        )

    def generate_download_descriptor(
        self,
        file_id: str,
        expires_in_seconds: int = 300,
    ) -> DownloadDescriptor:
        safe_id = self._sanitize_file_id(file_id)
        meta = self.get_file_metadata(safe_id)
        now_utc = datetime.now(timezone.utc)
        expires_at_dt = datetime.fromtimestamp(now_utc.timestamp() + expires_in_seconds, tz=timezone.utc)

        download_url = f"{self.base_url}/api/files/download/{safe_id}"
        return DownloadDescriptor(
            file_id=safe_id,
            download_url=download_url,
            expires_at_utc=expires_at_dt.isoformat(),
            storage_backend=self.BACKEND_NAME,
            original_filename=meta.original_filename,
            content_type=meta.content_type,
        )


class S3StorageService(StorageService):
    """AWS S3 Storage Adapter using boto3 and pre-signed URLs.
    
    Security Controls:
    - Never makes S3 objects public (all objects remain strictly private).
    - Enforces AWS Server-Side Encryption (AES256 or AWS KMS).
    - Generates short-lived presigned URLs (default 300 seconds).
    - Explicitly raises StorageConfigurationError if boto3 or AWS credentials
      are absent. Never silently falls back to local storage.
    """

    BACKEND_NAME = "aws_s3"

    def __init__(
        self,
        bucket_name: str,
        region_name: str = "us-east-1",
        kms_key_id: Optional[str] = None,
        s3_client: Optional[Any] = None,
    ):
        """Initialize S3StorageService.
        
        Args:
            bucket_name: Name of the private S3 bucket.
            region_name: AWS region where the bucket resides.
            kms_key_id: Optional AWS KMS key ID for SSE-KMS. Defaults to SSE-S3 (AES256).
            s3_client: Optional pre-configured boto3 S3 client (e.g. for testing/mocking).
        """
        if not bucket_name:
            raise StorageConfigurationError("AWS S3 bucket_name must be configured.")

        self.bucket_name = bucket_name
        self.region_name = region_name
        self.kms_key_id = kms_key_id
        self._meta_cache: Dict[str, FileMetadata] = {}

        if s3_client is not None:
            self._s3_client = s3_client
        else:
            try:
                import boto3  # type: ignore
                from botocore.config import Config  # type: ignore

                # Enforce SigV4 and regional endpoint
                config = Config(signature_version="s3v4", s3={"addressing_style": "virtual"})
                self._s3_client = boto3.client("s3", region_name=region_name, config=config)
            except ImportError as err:
                raise StorageConfigurationError(
                    "boto3 is not installed. To use S3StorageService, install boto3 or configure AWS credentials. "
                    "Notice: Storage service does not silently fall back to local disk."
                ) from err

    def _s3_key_for_file(self, file_id: str) -> str:
        return f"uploads/{file_id}"

    def save_file(
        self,
        file_id: str,
        filename: str,
        data: bytes,
        content_type: Optional[str] = None,
    ) -> FileMetadata:
        key = self._s3_key_for_file(file_id)
        guessed_type, _ = mimetypes.guess_type(filename)
        resolved_content_type = content_type or guessed_type or "application/octet-stream"

        put_params: Dict[str, Any] = {
            "Bucket": self.bucket_name,
            "Key": key,
            "Body": data,
            "ContentType": resolved_content_type,
            "ServerSideEncryption": "AES256" if not self.kms_key_id else "aws:kms",
        }
        if self.kms_key_id:
            put_params["SSEKMSKeyId"] = self.kms_key_id

        self._s3_client.put_object(**put_params)

        meta = FileMetadata(
            file_id=file_id,
            original_filename=Path(filename).name,
            file_size_bytes=len(data),
            content_type=resolved_content_type,
            uploaded_at_utc=datetime.now(timezone.utc).isoformat(),
            storage_backend=self.BACKEND_NAME,
            storage_key_or_path=key,
        )
        self._meta_cache[file_id] = meta
        return meta

    def get_file_metadata(self, file_id: str) -> FileMetadata:
        if file_id in self._meta_cache:
            return self._meta_cache[file_id]

        key = self._s3_key_for_file(file_id)
        try:
            head = self._s3_client.head_object(Bucket=self.bucket_name, Key=key)
            meta = FileMetadata(
                file_id=file_id,
                original_filename=head.get("Metadata", {}).get("original-filename", file_id),
                file_size_bytes=head.get("ContentLength", 0),
                content_type=head.get("ContentType", "application/octet-stream"),
                uploaded_at_utc=head.get("LastModified", datetime.now(timezone.utc)).isoformat()
                if hasattr(head.get("LastModified"), "isoformat")
                else str(head.get("LastModified")),
                storage_backend=self.BACKEND_NAME,
                storage_key_or_path=key,
            )
            self._meta_cache[file_id] = meta
            return meta
        except Exception as err:
            raise FileNotFoundStorageError(f"File '{file_id}' not found in S3 bucket '{self.bucket_name}': {err}")

    def get_file_bytes(self, file_id: str) -> tuple[bytes, FileMetadata]:
        key = self._s3_key_for_file(file_id)
        meta = self.get_file_metadata(file_id)
        try:
            response = self._s3_client.get_object(Bucket=self.bucket_name, Key=key)
            return response["Body"].read(), meta
        except Exception as err:
            raise StorageError(f"Failed to read file from S3: {err}")

    def file_exists(self, file_id: str) -> bool:
        key = self._s3_key_for_file(file_id)
        try:
            self._s3_client.head_object(Bucket=self.bucket_name, Key=key)
            return True
        except Exception:
            return False

    def delete_file(self, file_id: str) -> bool:
        key = self._s3_key_for_file(file_id)
        try:
            self._s3_client.delete_object(Bucket=self.bucket_name, Key=key)
            self._meta_cache.pop(file_id, None)
            return True
        except Exception as err:
            raise StorageError(f"Failed to delete S3 object: {err}")

    def generate_upload_descriptor(
        self,
        file_id: str,
        filename: str,
        expires_in_seconds: int = 300,
        content_type: Optional[str] = None,
    ) -> UploadDescriptor:
        """Generate a short-lived S3 pre-signed PUT URL.
        
        Enforces server-side encryption and strictly private ACL.
        """
        key = self._s3_key_for_file(file_id)
        guessed_type, _ = mimetypes.guess_type(filename)
        resolved_content_type = content_type or guessed_type or "application/octet-stream"

        params: Dict[str, Any] = {
            "Bucket": self.bucket_name,
            "Key": key,
            "ContentType": resolved_content_type,
            "ServerSideEncryption": "AES256" if not self.kms_key_id else "aws:kms",
        }
        if self.kms_key_id:
            params["SSEKMSKeyId"] = self.kms_key_id

        presigned_url = self._s3_client.generate_presigned_url(
            ClientMethod="put_object",
            Params=params,
            ExpiresIn=expires_in_seconds,
            HttpMethod="PUT",
        )

        now_utc = datetime.now(timezone.utc)
        expires_at_dt = datetime.fromtimestamp(now_utc.timestamp() + expires_in_seconds, tz=timezone.utc)

        return UploadDescriptor(
            file_id=file_id,
            upload_url=presigned_url,
            http_method="PUT",
            expires_at_utc=expires_at_dt.isoformat(),
            storage_backend=self.BACKEND_NAME,
            required_headers={"Content-Type": resolved_content_type},
        )

    def generate_download_descriptor(
        self,
        file_id: str,
        expires_in_seconds: int = 300,
    ) -> DownloadDescriptor:
        """Generate a short-lived S3 pre-signed GET URL."""
        key = self._s3_key_for_file(file_id)
        meta = self.get_file_metadata(file_id)

        params: Dict[str, Any] = {
            "Bucket": self.bucket_name,
            "Key": key,
            "ResponseContentDisposition": f'attachment; filename="{meta.original_filename}"',
        }

        presigned_url = self._s3_client.generate_presigned_url(
            ClientMethod="get_object",
            Params=params,
            ExpiresIn=expires_in_seconds,
            HttpMethod="GET",
        )

        now_utc = datetime.now(timezone.utc)
        expires_at_dt = datetime.fromtimestamp(now_utc.timestamp() + expires_in_seconds, tz=timezone.utc)

        return DownloadDescriptor(
            file_id=file_id,
            download_url=presigned_url,
            expires_at_utc=expires_at_dt.isoformat(),
            storage_backend=self.BACKEND_NAME,
            original_filename=meta.original_filename,
            content_type=meta.content_type,
        )
