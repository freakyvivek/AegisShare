"""Unit tests validating AWS SAM Infrastructure as Code template integrity."""

import re
import unittest
from pathlib import Path


class TestSamTemplate(unittest.TestCase):
    """Test suite validating structure and security controls in infrastructure/template.yaml."""

    @classmethod
    def setUpClass(cls):
        template_path = Path(__file__).resolve().parent.parent.parent / "infrastructure" / "template.yaml"
        cls.template_content = template_path.read_text(encoding="utf-8")

    def test_template_header_and_transform(self):
        self.assertIn("AWSTemplateFormatVersion: '2010-09-09'", self.template_content)
        self.assertIn("Transform: AWS::Serverless-2016-10-31", self.template_content)

    def test_s3_encryption_and_public_access_block(self):
        # S3 Server-Side Encryption
        self.assertIn("SSEAlgorithm: AES256", self.template_content)
        # Block Public Access Flags
        self.assertIn("BlockPublicAcls: true", self.template_content)
        self.assertIn("BlockPublicPolicy: true", self.template_content)
        self.assertIn("IgnorePublicAcls: true", self.template_content)
        self.assertIn("RestrictPublicBuckets: true", self.template_content)
        # TLS enforcement
        self.assertIn("aws:SecureTransport", self.template_content)

    def test_dynamodb_tables_defined(self):
        self.assertIn("FilesMetadataTable:", self.template_content)
        self.assertIn("ShareTokensTable:", self.template_content)
        self.assertIn("AuditLogsTable:", self.template_content)
        # TTL enabled on tokens table
        self.assertIn("AttributeName: ttl", self.template_content)
        self.assertIn("Enabled: true", self.template_content)
        # Server-side encryption enabled
        self.assertIn("SSEEnabled: true", self.template_content)

    def test_lambda_and_iam_least_privilege(self):
        self.assertIn("AWS::Serverless::Function", self.template_content)
        self.assertIn("backend.handlers.api_dispatcher.lambda_handler", self.template_content)
        self.assertIn("s3:GetObject", self.template_content)
        self.assertIn("s3:PutObject", self.template_content)
        self.assertIn("dynamodb:GetItem", self.template_content)
        self.assertIn("dynamodb:PutItem", self.template_content)

    def test_api_gateway_cors(self):
        self.assertIn("AWS::ApiGatewayV2::Api", self.template_content)
        self.assertIn("AWS::ApiGatewayV2::Stage", self.template_content)
        self.assertIn("CorsConfiguration:", self.template_content)
        self.assertIn("AllowOrigins:", self.template_content)

    def test_outputs_defined(self):
        self.assertIn("Outputs:", self.template_content)
        self.assertIn("ApiEndpointUrl:", self.template_content)
        self.assertIn("EncryptedFilesBucketName:", self.template_content)

    def test_cost_optimizations(self):
        # DynamoDB PITR disabled for low-cost demonstration
        self.assertIn("PointInTimeRecoveryEnabled: false", self.template_content)
        self.assertNotIn("PointInTimeRecoveryEnabled: true", self.template_content)
        # CloudWatch retention set to 7 days
        self.assertIn("RetentionInDays: 7", self.template_content)

    def test_samconfig_changeset_review(self):
        samconfig_path = Path(__file__).resolve().parent.parent.parent / "samconfig.toml"
        self.assertTrue(samconfig_path.exists(), "samconfig.toml should exist")
        content = samconfig_path.read_text(encoding="utf-8")
        self.assertIn("confirm_changeset = true", content)
        self.assertIn("stack_name", content)

    def test_iam_policies_and_boundary_integrity(self):
        import json
        docs_dir = Path(__file__).resolve().parent.parent.parent / "docs"
        
        # S3 HeadObject invalid action check
        self.assertNotIn("s3:HeadObject", self.template_content)
        self.assertIn("PermissionsBoundaryArn", self.template_content)
        
        # Verify deployment policy
        dep_path = docs_dir / "deployment-policy.json"
        self.assertTrue(dep_path.exists())
        dep_policy = json.loads(dep_path.read_text(encoding="utf-8"))
        
        # Verify no vault object access for deployer
        for stmt in dep_policy.get("Statement", []):
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            for r in resources:
                self.assertNotIn("aegisshare-secure-vault-*-137327915859/*", r)
        
        # Verify iam:UpdateAssumeRolePolicy is NOT present
        dep_str = json.dumps(dep_policy)
        self.assertNotIn("iam:UpdateAssumeRolePolicy", dep_str)
        self.assertIn("AWSLambdaBasicExecutionRole", dep_str)
        
        # Verify lambda execution policy and boundary
        exec_path = docs_dir / "lambda-execution-policy.json"
        boundary_path = docs_dir / "lambda-permissions-boundary.json"
        self.assertTrue(exec_path.exists())
        self.assertTrue(boundary_path.exists())
        json.loads(exec_path.read_text(encoding="utf-8"))
        json.loads(boundary_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
