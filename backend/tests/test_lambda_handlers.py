"""Unit tests for AWS Lambda API Gateway handlers."""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from backend.handlers import (
    api_dispatcher,
    api_gateway_proxy,
    health_handler,
)


class TestLambdaHandlers(unittest.TestCase):
    """Test suite for Lambda event routing, proxy responses, and handlers."""

    def test_api_gateway_proxy_response_formatting(self):
        resp = api_gateway_proxy.format_response(
            status_code=200,
            body={"status": "OK", "count": 5},
        )
        self.assertEqual(resp["statusCode"], 200)
        self.assertIn("Access-Control-Allow-Origin", resp["headers"])
        self.assertEqual(resp["headers"]["Access-Control-Allow-Origin"], "*")
        body_dict = json.loads(resp["body"])
        self.assertEqual(body_dict["status"], "OK")

    def test_api_gateway_proxy_event_parsing(self):
        event = {
            "httpMethod": "POST",
            "path": "/api/share",
            "queryStringParameters": {"format": "json"},
            "headers": {
                "User-Agent": "TestClient/1.0",
                "X-Forwarded-For": "203.0.113.195",
            },
            "body": json.dumps({"file_id": "file_123"}),
            "isBase64Encoded": False,
        }
        method, path, query, body, ip, ua = api_gateway_proxy.parse_event(event)

        self.assertEqual(method, "POST")
        self.assertEqual(path, "/api/share")
        self.assertEqual(query.get("format"), "json")
        self.assertEqual(body.get("file_id"), "file_123")
        self.assertEqual(ip, "203.0.113.195")
        self.assertEqual(ua, "TestClient/1.0")

    def test_health_handler(self):
        event = {"httpMethod": "GET", "path": "/api/health"}
        resp = health_handler.lambda_handler(event)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["status"], "HEALTHY")
        self.assertEqual(body["storage_backend"], "aws_s3_dynamodb")

    def test_api_dispatcher_options_cors(self):
        event = {"httpMethod": "OPTIONS", "path": "/api/upload"}
        resp = api_dispatcher.lambda_handler(event)

        self.assertEqual(resp["statusCode"], 204)
        self.assertEqual(resp["headers"]["Access-Control-Allow-Origin"], "*")

    def test_api_dispatcher_unknown_route(self):
        event = {"httpMethod": "GET", "path": "/api/nonexistent"}
        resp = api_dispatcher.lambda_handler(event)

        self.assertEqual(resp["statusCode"], 404)
        body = json.loads(resp["body"])
        self.assertEqual(body["error"], "ROUTE_NOT_FOUND")

    def test_normalize_path_unit(self):
        """Verify unit behavior of normalize_path under all stage and path variations."""
        # 1. /dev/api/health with stage dev resolves to /api/health
        self.assertEqual(api_dispatcher.normalize_path("/dev/api/health", "dev"), "/api/health")
        self.assertEqual(api_dispatcher.normalize_path("/dev/api/health/", "dev"), "/api/health")

        # 2. Already using /api/health is NOT altered
        self.assertEqual(api_dispatcher.normalize_path("/api/health", "dev"), "/api/health")

        # 3. Exactly one leading /dev prefix removed
        self.assertEqual(api_dispatcher.normalize_path("/dev/dev/api/health", "dev"), "/dev/api/health")

        # 4. Stage path equals /dev or /dev/ resolves to /
        self.assertEqual(api_dispatcher.normalize_path("/dev", "dev"), "/")
        self.assertEqual(api_dispatcher.normalize_path("/dev/", "dev"), "/")

        # 5. Non-matching prefix not stripped
        self.assertEqual(api_dispatcher.normalize_path("/dev_preview/api/health", "dev"), "/dev_preview/api/health")

        # 6. $default stage does NOT strip prefix
        self.assertEqual(api_dispatcher.normalize_path("/dev/api/health", "$default"), "/dev/api/health")

        # 7. None/empty stage does NOT strip prefix (local demo/test events)
        self.assertEqual(api_dispatcher.normalize_path("/api/health", None), "/api/health")
        self.assertEqual(api_dispatcher.normalize_path("/dev/api/health", None), "/dev/api/health")

    def test_api_dispatcher_stage_prefixed_health_check(self):
        """HTTP API Gateway v2 event for /dev/api/health with stage 'dev' resolves to /api/health."""
        # HTTP API Gateway v2 payload format 2.0 structure
        v2_event = {
            "version": "2.0",
            "routeKey": "ANY /{proxy+}",
            "rawPath": "/dev/api/health",
            "requestContext": {
                "stage": "dev",
                "http": {
                    "method": "GET",
                    "path": "/dev/api/health",
                },
            },
        }
        resp = api_dispatcher.lambda_handler(v2_event)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["status"], "HEALTHY")

        # REST / v1 format structure
        v1_event = {
            "httpMethod": "GET",
            "path": "/dev/api/health",
            "requestContext": {
                "stage": "dev",
            },
        }
        resp_v1 = api_dispatcher.lambda_handler(v1_event)
        self.assertEqual(resp_v1["statusCode"], 200)
        body_v1 = json.loads(resp_v1["body"])
        self.assertEqual(body_v1["status"], "HEALTHY")

    def test_api_dispatcher_unaltered_health_check(self):
        """Request already using /api/health with stage 'dev' is not altered."""
        event = {
            "httpMethod": "GET",
            "path": "/api/health",
            "requestContext": {
                "stage": "dev",
            },
        }
        resp = api_dispatcher.lambda_handler(event)
        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["status"], "HEALTHY")

    def test_api_dispatcher_default_stage_not_stripped(self):
        """For '$default' stage, /dev is not stripped, resulting in ROUTE_NOT_FOUND."""
        event = {
            "httpMethod": "GET",
            "path": "/dev/api/health",
            "requestContext": {
                "stage": "$default",
            },
        }
        resp = api_dispatcher.lambda_handler(event)
        self.assertEqual(resp["statusCode"], 404)
        body = json.loads(resp["body"])
        self.assertEqual(body["error"], "ROUTE_NOT_FOUND")

    def test_api_dispatcher_other_routes_with_stage(self):
        """Other routes with stage 'dev' resolve correctly to their respective handlers."""
        # OPTIONS preflight on /dev/api/upload
        options_event = {
            "httpMethod": "OPTIONS",
            "path": "/dev/api/upload",
            "requestContext": {"stage": "dev"},
        }
        resp_opt = api_dispatcher.lambda_handler(options_event)
        self.assertEqual(resp_opt["statusCode"], 204)

        # GET /dev/api/tokens/inspect resolves to inspect_handler
        mock_env = {
            "TOKENS_TABLE_NAME": "test-tokens",
            "FILES_TABLE_NAME": "test-files",
            "S3_BUCKET_NAME": "test-bucket",
            "AUDIT_TABLE_NAME": "test-audit",
        }
        with patch.dict(os.environ, mock_env):
            inspect_event = {
                "httpMethod": "GET",
                "path": "/dev/api/tokens/inspect",
                "queryStringParameters": {},
                "requestContext": {"stage": "dev"},
            }
            resp_inspect = api_dispatcher.lambda_handler(inspect_event)
            self.assertEqual(resp_inspect["statusCode"], 400)
            self.assertIn("Missing 'token'", json.loads(resp_inspect["body"])["error"])

            # GET /dev/api/download resolves to download_handler
            download_event = {
                "httpMethod": "GET",
                "path": "/dev/api/download",
                "queryStringParameters": {},
                "requestContext": {"stage": "dev"},
            }
            resp_dl = api_dispatcher.lambda_handler(download_event)
            self.assertEqual(resp_dl["statusCode"], 400)
            self.assertIn("Missing 'token'", json.loads(resp_dl["body"])["error"])

    def test_api_dispatcher_local_demo_requests(self):
        """Requests without requestContext (local demo/test format) continue to work unaltered."""
        health_event = {"httpMethod": "GET", "path": "/api/health"}
        resp = api_dispatcher.lambda_handler(health_event)
        self.assertEqual(resp["statusCode"], 200)

        options_event = {"httpMethod": "OPTIONS", "path": "/api/upload"}
        resp_opt = api_dispatcher.lambda_handler(options_event)
        self.assertEqual(resp_opt["statusCode"], 204)


if __name__ == "__main__":
    unittest.main()

