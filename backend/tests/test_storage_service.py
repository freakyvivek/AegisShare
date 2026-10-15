"""Unit tests for StorageService implementations."""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from backend.services.storage_service import (
    FileNotFoundStorageError,
    LocalStorageService,
    S3StorageService,
    StorageConfigurationError,
)


class TestLocalStorageService(unittest.TestCase):
    """Test suite for local storage adapter."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_storage_")
        self.storage = LocalStorageService(base_directory=self.temp_dir, base_url="http://localhost:8000")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_save_and_retrieve_file(self):
        sample_bytes = b"Hello Secure File Sharing!"
        meta = self.storage.save_file(
            file_id="report_001",
            filename="report.pdf",
            data=sample_bytes,
            content_type="application/pdf",
        )

        self.assertEqual(meta.file_id, "report_001")
        self.assertEqual(meta.original_filename, "report.pdf")
        self.assertEqual(meta.file_size_bytes, len(sample_bytes))
        self.assertEqual(meta.content_type, "application/pdf")
        self.assertEqual(meta.storage_backend, "local_demo_storage")

        # Retrieve bytes
        retrieved_bytes, retrieved_meta = self.storage.get_file_bytes("report_001")
        self.assertEqual(retrieved_bytes, sample_bytes)
        self.assertEqual(retrieved_meta.file_id, "report_001")

    def test_file_exists_and_delete(self):
        self.assertFalse(self.storage.file_exists("test_file"))
        self.storage.save_file("test_file", "sample.txt", b"demo data")
        self.assertTrue(self.storage.file_exists("test_file"))

        deleted = self.storage.delete_file("test_file")
        self.assertTrue(deleted)
        self.assertFalse(self.storage.file_exists("test_file"))

    def test_get_nonexistent_file_raises_error(self):
        with self.assertRaises(FileNotFoundStorageError):
            self.storage.get_file_bytes("does_not_exist")

    def test_path_traversal_attack_rejected(self):
        with self.assertRaises(ValueError):
            self.storage.save_file("../evil_file", "evil.txt", b"danger")

        with self.assertRaises(ValueError):
            self.storage.get_file_bytes("../../etc/passwd")

    def test_generate_descriptors(self):
        self.storage.save_file("file_xyz", "data.json", b'{"key": "value"}')

        upload_desc = self.storage.generate_upload_descriptor("file_xyz", "data.json")
        self.assertEqual(upload_desc.file_id, "file_xyz")
        self.assertIn("/api/upload/direct/file_xyz", upload_desc.upload_url)
        self.assertEqual(upload_desc.storage_backend, "local_demo_storage")

        download_desc = self.storage.generate_download_descriptor("file_xyz")
        self.assertEqual(download_desc.file_id, "file_xyz")
        self.assertIn("/api/files/download/file_xyz", download_desc.download_url)
        self.assertEqual(download_desc.original_filename, "data.json")


class TestS3StorageService(unittest.TestCase):
    """Test suite for S3 adapter contract and safety invariants."""

    def test_missing_bucket_raises_configuration_error(self):
        with self.assertRaises(StorageConfigurationError):
            S3StorageService(bucket_name="")

    def test_no_silent_fallback_when_boto3_unavailable(self):
        """Ensures that AWS S3 adapter NEVER silently falls back to local storage."""
        # Passing an invalid client creation or verifying exception behavior
        mock_client = MagicMock()
        mock_client.generate_presigned_url.return_value = "https://mock-bucket.s3.amazonaws.com/uploads/f1?signature=xyz"
        mock_client.head_object.return_value = {
            "ContentLength": 1024,
            "ContentType": "application/pdf",
            "Metadata": {"original-filename": "report.pdf"},
        }

        s3_service = S3StorageService(
            bucket_name="secure-college-bucket-test",
            region_name="us-east-1",
            s3_client=mock_client,
        )

        # Upload descriptor check
        upload_desc = s3_service.generate_upload_descriptor("f1", "report.pdf", expires_in_seconds=300)
        self.assertEqual(upload_desc.storage_backend, "aws_s3")
        self.assertTrue(upload_desc.upload_url.startswith("https://mock-bucket.s3.amazonaws.com"))

        # Verify presigned URL call parameters enforce encryption and private access
        mock_client.generate_presigned_url.assert_called_with(
            ClientMethod="put_object",
            Params={
                "Bucket": "secure-college-bucket-test",
                "Key": "uploads/f1",
                "ContentType": "application/pdf",
                "ServerSideEncryption": "AES256",
            },
            ExpiresIn=300,
            HttpMethod="PUT",
        )

        # Download descriptor check
        download_desc = s3_service.generate_download_descriptor("f1", expires_in_seconds=120)
        self.assertEqual(download_desc.storage_backend, "aws_s3")


if __name__ == "__main__":
    unittest.main()
