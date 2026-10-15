"""Integration tests for backend/local_server.py."""

import json
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

from backend.local_server import SecureFileSharingHandler, create_app


class TestLocalServerHTTP(unittest.TestCase):
    """Test suite running live HTTP calls against the local demo server."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="test_server_")
        cls.port = 8991
        cls.base_url = f"http://127.0.0.1:{cls.port}"

        create_app(data_dir=cls.temp_dir, base_url=cls.base_url)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", cls.port), SecureFileSharingHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_health_check(self):
        req = urllib.request.Request(f"{self.base_url}/api/health")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "HEALTHY")
            self.assertEqual(data["storage_backend"], "local_demo_storage")

    def test_upload_share_inspect_download_and_audit_flow(self):
        # 1. Upload File
        sample_content = b"Content for college project demonstration"
        req = urllib.request.Request(
            f"{self.base_url}/api/upload",
            data=sample_content,
            headers={"Content-Type": "text/plain", "X-File-Name": "demo_report.txt"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 201)
            upload_res = json.loads(resp.read().decode())
            file_id = upload_res["file_id"]
            self.assertEqual(upload_res["filename"], "demo_report.txt")

        # 2. Create Share Link (1 download max, 60s expiry)
        share_payload = json.dumps({
            "file_id": file_id,
            "expires_in_seconds": 60,
            "max_downloads": 1,
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/share",
            data=share_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 201)
            share_res = json.loads(resp.read().decode())
            raw_token = share_res["raw_token"]
            self.assertIn("share_url", share_res)

        # 3. Inspect Token (Non-destructive)
        inspect_url = f"{self.base_url}/api/tokens/inspect?token={urllib.parse.quote(raw_token)}"
        with urllib.request.urlopen(inspect_url) as resp:
            self.assertEqual(resp.status, 200)
            inspect_res = json.loads(resp.read().decode())
            self.assertEqual(inspect_res["status"], "VALID")
            self.assertEqual(inspect_res["filename"], "demo_report.txt")
            self.assertEqual(inspect_res["downloads_remaining"], 1)

        # 4. First Download (Success)
        download_url = f"{self.base_url}/api/download?token={urllib.parse.quote(raw_token)}"
        with urllib.request.urlopen(download_url) as resp:
            self.assertEqual(resp.status, 200)
            downloaded_bytes = resp.read()
            self.assertEqual(downloaded_bytes, sample_content)

        # 5. Second Download (Exhausted -> HTTP 410 Gone)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(download_url)
        self.assertEqual(ctx.exception.code, 410)

        # 6. Verify Audit Trail Contains All Events
        audit_url = f"{self.base_url}/api/audit?file_id={file_id}"
        with urllib.request.urlopen(audit_url) as resp:
            self.assertEqual(resp.status, 200)
            audit_res = json.loads(resp.read().decode())
            self.assertGreaterEqual(audit_res["count"], 4)
            event_types = [e["event_type"] for e in audit_res["events"]]
            self.assertIn("ACCESS_REJECTED", event_types)
            self.assertIn("DOWNLOAD_SUCCESS", event_types)
            self.assertIn("SHARE_LINK_CREATED", event_types)
            self.assertIn("FILE_UPLOAD", event_types)


if __name__ == "__main__":
    unittest.main()
