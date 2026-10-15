# AegisShare Pre-Deployment Security Review & Permission Hardening

**Target Account:** `137327915859`  
**Deployer Principal:** `arn:aws:iam::137327915859:user/AegisShareDeployUser`  
**Deployment Region:** `ap-south-1`  
**Stack Name:** `aegisshare-app`  
**Review Status:** Security Correction Pass Completed — **Zero cloud permissions modified, zero policies attached, zero cloud resources created or deployed.**  
**Live AWS Status:** *PENDING — Live AWS functionality has NOT been verified in the cloud.*

---

## 1. Executive Summary of Corrections

Following a comprehensive security audit of `docs/deployment-policy.json`, `docs/lambda-execution-policy.json`, and `infrastructure/template.yaml`, the following critical corrections were implemented:

1. **Vault Object Access Revoked from Deployer:** Removed `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` on the application vault bucket (`arn:aws:s3:::aegisshare-secure-vault-*-137327915859/*`). The deployment user now holds exclusively bucket control-plane permissions for CloudFormation stack management, with zero access to user file contents.
2. **Privilege-Escalation Vectors Neutralized:**
   - Enforced that `iam:CreateRole` requires an explicit Permissions Boundary (`arn:aws:iam::137327915859:policy/AegisShareLambdaExecutionBoundary`).
   - Removed `iam:UpdateAssumeRolePolicy` to prevent modifying trust relationships to assume the role directly.
   - Constrained `iam:AttachRolePolicy` and `iam:DetachRolePolicy` exclusively to the managed policy `arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole`.
   - Constrained `iam:PassRole` strictly to `lambda.amazonaws.com`.
3. **Invalid S3 Action Scrubbed:** Removed `s3:HeadObject` from `infrastructure/template.yaml` (S3 authorizes `HeadObject` calls via `s3:GetObject`).
4. **Permissions Boundary Support:** Created `docs/lambda-permissions-boundary.json` and updated `infrastructure/template.yaml` with the `PermissionsBoundaryArn` parameter.

---

## 2. Hardened IAM Policy Specifications

### A. Deployment Policy (`docs/deployment-policy.json`)
Applied to: `arn:aws:iam::137327915859:user/AegisShareDeployUser`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudFormationStackManagement",
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateChangeSet",
        "cloudformation:DescribeChangeSet",
        "cloudformation:ExecuteChangeSet",
        "cloudformation:DeleteChangeSet",
        "cloudformation:ListChangeSets",
        "cloudformation:CreateStack",
        "cloudformation:UpdateStack",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResources",
        "cloudformation:GetTemplate",
        "cloudformation:GetTemplateSummary"
      ],
      "Resource": [
        "arn:aws:cloudformation:ap-south-1:137327915859:stack/aegisshare-*/*",
        "arn:aws:cloudformation:ap-south-1:137327915859:changeSet/*/*"
      ]
    },
    {
      "Sid": "CloudFormationGlobalValidation",
      "Effect": "Allow",
      "Action": [
        "cloudformation:ValidateTemplate"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3SAMArtifactBucketManagement",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::aws-sam-cli-managed-*",
        "arn:aws:s3:::aws-sam-cli-managed-*/*"
      ]
    },
    {
      "Sid": "S3VaultBucketControlPlaneManagementOnly",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:GetEncryptionConfiguration",
        "s3:PutEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:PutBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:PutBucketVersioning",
        "s3:GetLifecycleConfiguration",
        "s3:PutLifecycleConfiguration"
      ],
      "Resource": [
        "arn:aws:s3:::aegisshare-secure-vault-*-137327915859"
      ]
    },
    {
      "Sid": "DynamoDBTableControlPlaneManagementOnly",
      "Effect": "Allow",
      "Action": [
        "dynamodb:CreateTable",
        "dynamodb:DeleteTable",
        "dynamodb:DescribeTable",
        "dynamodb:UpdateTable",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:UpdateTimeToLive",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:UpdateContinuousBackups",
        "dynamodb:ListTagsOfResource",
        "dynamodb:TagResource",
        "dynamodb:UntagResource"
      ],
      "Resource": [
        "arn:aws:dynamodb:ap-south-1:137327915859:table/aegisshare-*"
      ]
    },
    {
      "Sid": "LambdaFunctionManagement",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:DeleteFunction",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:ListTags",
        "lambda:TagResource",
        "lambda:UntagResource",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "lambda:GetPolicy"
      ],
      "Resource": [
        "arn:aws:lambda:ap-south-1:137327915859:function:aegisshare-*"
      ]
    },
    {
      "Sid": "ApiGatewayV2Management",
      "Effect": "Allow",
      "Action": [
        "apigateway:GET",
        "apigateway:POST",
        "apigateway:PUT",
        "apigateway:PATCH",
        "apigateway:DELETE"
      ],
      "Resource": [
        "arn:aws:apigateway:ap-south-1::/apis",
        "arn:aws:apigateway:ap-south-1::/apis/*"
      ]
    },
    {
      "Sid": "CloudWatchLogsGroupManagement",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:DescribeLogGroups",
        "logs:PutRetentionPolicy",
        "logs:DeleteRetentionPolicy",
        "logs:ListTagsForResource",
        "logs:ListTagsLogGroup",
        "logs:TagResource",
        "logs:UntagResource"
      ],
      "Resource": [
        "arn:aws:logs:ap-south-1:137327915859:log-group:/aws/lambda/aegisshare-*:*"
      ]
    },
    {
      "Sid": "IAMLambdaExecutionRoleManagementWithBoundaryEnforcement",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:UpdateRole",
        "iam:GetRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:TagRole",
        "iam:UntagRole"
      ],
      "Resource": [
        "arn:aws:iam::137327915859:role/aegisshare-*"
      ],
      "Condition": {
        "StringEquals": {
          "iam:PermissionsBoundary": "arn:aws:iam::137327915859:policy/AegisShareLambdaExecutionBoundary"
        }
      }
    },
    {
      "Sid": "IAMAttachApprovedBasicExecutionRolePolicyOnly",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy"
      ],
      "Resource": [
        "arn:aws:iam::137327915859:role/aegisshare-*"
      ],
      "Condition": {
        "ArnEquals": {
          "iam:PolicyArn": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        }
      }
    },
    {
      "Sid": "IAMPassRoleToLambdaServiceOnly",
      "Effect": "Allow",
      "Action": [
        "iam:PassRole"
      ],
      "Resource": [
        "arn:aws:iam::137327915859:role/aegisshare-*"
      ],
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    }
  ]
}
```

---

### B. Lambda Runtime Execution Policy (`docs/lambda-execution-policy.json`)
Applied to: `AegisShareApiFunctionRole` (assumed by `lambda.amazonaws.com`)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogsLogging",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:ap-south-1:137327915859:log-group:/aws/lambda/aegisshare-*:*"
      ]
    },
    {
      "Sid": "S3EncryptedVaultObjectAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::aegisshare-secure-vault-dev-137327915859/*"
      ]
    },
    {
      "Sid": "DynamoDBTablesAndIndexesAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Scan",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:ap-south-1:137327915859:table/aegisshare-files-dev",
        "arn:aws:dynamodb:ap-south-1:137327915859:table/aegisshare-tokens-dev",
        "arn:aws:dynamodb:ap-south-1:137327915859:table/aegisshare-tokens-dev/index/*",
        "arn:aws:dynamodb:ap-south-1:137327915859:table/aegisshare-audit-logs-dev",
        "arn:aws:dynamodb:ap-south-1:137327915859:table/aegisshare-audit-logs-dev/index/*"
      ]
    }
  ]
}
```

---

### C. Permissions Boundary (`docs/lambda-permissions-boundary.json`)
Applied to: `arn:aws:iam::137327915859:policy/AegisShareLambdaExecutionBoundary`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LambdaExecutionBoundaryCloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:ap-south-1:137327915859:log-group:/aws/lambda/aegisshare-*:*"
      ]
    },
    {
      "Sid": "LambdaExecutionBoundaryS3VaultObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::aegisshare-secure-vault-*-137327915859/*"
      ]
    },
    {
      "Sid": "LambdaExecutionBoundaryDynamoDBAccess",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Scan",
        "dynamodb:Query"
      ],
      "Resource": [
        "arn:aws:dynamodb:ap-south-1:137327915859:table/aegisshare-*"
      ]
    }
  ]
}
```

---

## 3. Comparison of IAM Role Models

| Dimension | Model 1: Template-Generated Role with Boundary (Active) | Model 2: Predefined Runtime Execution Role |
| :--- | :--- | :--- |
| **How Role is Provisioned** | Synthesized dynamically by AWS SAM from `template.yaml` `Policies:`. | Pre-created in advance by an AWS Account Administrator. |
| **Permissions Boundary** | **Required.** `iam:CreateRole` requires `iam:PermissionsBoundary` condition matching `AegisShareLambdaExecutionBoundary`. | Built directly into the pre-created role; deployer requires no boundary check. |
| **Deployer IAM Scope** | Requires scoped `iam:CreateRole`, `PutRolePolicy`, `AttachRolePolicy` (strictly filtered). | **Zero IAM creation permissions.** Deployer only needs `iam:PassRole` on the fixed role ARN. |
| **Privilege Escalation Risk** | **Eliminated.** Effective permissions are capped by the boundary; `iam:DeleteRolePermissionsBoundary` is omitted. | **Zero.** The deployer cannot alter, attach, or replace policies on the role. |
| **Template Config** | Uses `PermissionsBoundary: !If [HasPermissionsBoundary, ...]` (built into template). | Set `Role: arn:aws:iam::137327915859:role/AegisShareLambdaExecutionRole` in `template.yaml`. |

---

## 4. Destructive Permissions Audit & CloudFormation Rollback Clarification

| Action | Resources | Role in Deployment & Rollback | Role in Teardown & Cleanup |
| :--- | :--- | :--- | :--- |
| **`cloudformation:DeleteStack`** | `aegisshare-*/*` | **NOT required for automatic rollback.** When stack creation fails, CloudFormation triggers an internal rollback to delete provisioned resources; it does **not** call `DeleteStack`. | **Required for deliberate stack deletion** (e.g., `sam delete` or removing the stack after demonstration). |
| **`s3:DeleteBucket`** | `aegisshare-secure-vault-*` | **Required during rollback** if bucket creation succeeded before a later resource failed. | **Required for deliberate cleanup** when deleting the stack. |
| **`dynamodb:DeleteTable`** | `aegisshare-*` | **Required during rollback** if table creation succeeded before subsequent failures. Also needed during updates that require resource replacement. | **Required for deliberate stack deletion**. |
| **`lambda:DeleteFunction`** | `aegisshare-*` | **Required during rollback** if function creation succeeded before a later failure. | **Required for deliberate stack deletion**. |
| **`iam:DeleteRole`** | `aegisshare-*` | **Required during rollback** if role creation succeeded before stack failure. | **Required for deliberate stack deletion** to avoid orphaned roles. |
| **`s3:DeleteObject`** | SAM Artifact Bucket | Not used in rollback. | Used to purge old packaged zip artifacts during continuous builds. |

---

## 5. Verification Against Actual Infrastructure Template

- **Account:** `137327915859`
- **Region:** `ap-south-1`
- **S3 Bucket:** `aegisshare-secure-vault-dev-137327915859` (Server-Side Encryption `AES256`, 4x PublicAccessBlock `true`, TLS-only transport policy).
- **DynamoDB Tables:** `aegisshare-files-dev`, `aegisshare-tokens-dev`, `aegisshare-audit-logs-dev` (`PAY_PER_REQUEST` billing, SSE enabled, PITR disabled for cost control, TTL enabled on `ttl`).
- **HTTP API Gateway:** `HttpApiGateway` (V2 HTTP API with CORS).
- **Lambda Function:** `AegisShareApiFunction` (Python 3.12, 256MB, 15s timeout).
- **CloudWatch Logs:** `/aws/lambda/aegisshare-app-AegisShareApiFunction-*` (7-day retention).

---

## 6. Validation Tools Status

1. **Local JSON Syntax Validation:** **PASSED** (Validated [docs/deployment-policy.json](file:///d:/AWS%20SECURE%20FILE%20SHARING/docs/deployment-policy.json), [docs/lambda-execution-policy.json](file:///d:/AWS%20SECURE%20FILE%20SHARING/docs/lambda-execution-policy.json), and [docs/lambda-permissions-boundary.json](file:///d:/AWS%20SECURE%20FILE%20SHARING/docs/lambda-permissions-boundary.json)).
2. **SAM Lint:** `sam validate --lint` **PASSED** (0 errors).
3. **SAM Build:** `sam build` **PASSED** (Build succeeded, 293 KB package size).
4. **Regression Tests:** `python -m unittest discover -s backend/tests -v` **PASSED** (41 tests passing in 0.826s).
5. **AWS Access Analyzer Validation (`aws accessanalyzer validate-policy`):**
   - **Status:** **Could not execute.**
   - **Reason:** The local workstation does not have AWS credentials configured in `~/.aws/credentials` or environment variables (`aws: [ERROR]: An error occurred (NoCredentials): Unable to locate credentials`).
   - **Next Step:** Run `aws accessanalyzer validate-policy` once active credentials for `AegisShareDeployUser` are configured via `aws configure`.

---

## 7. Safe Deployment Checklist

- [x] All object-level permissions on vault bucket removed from deployer policy.
- [x] `iam:UpdateAssumeRolePolicy` removed from deployer policy.
- [x] `iam:AttachRolePolicy` restricted to `AWSLambdaBasicExecutionRole`.
- [x] Permissions boundary enforcement configured for `iam:CreateRole`.
- [x] `iam:PassRole` restricted to `lambda.amazonaws.com`.
- [x] `confirm_changeset = true` verified in `samconfig.toml`.
- [x] Automated test suite passing (41/41 tests OK).
- [ ] Account Administrator creates the managed boundary policy:
  ```powershell
  aws iam create-policy --policy-name AegisShareLambdaExecutionBoundary --policy-document file://docs/lambda-permissions-boundary.json
  ```
- [ ] Account Administrator attaches `docs/deployment-policy.json` to `arn:aws:iam::137327915859:user/AegisShareDeployUser`.
- [ ] Configure workstation credentials:
  ```powershell
  aws configure
  ```
- [ ] Validate policies with Access Analyzer:
  ```powershell
  aws accessanalyzer validate-policy --policy-document file://docs/deployment-policy.json --policy-type IDENTITY_POLICY --region ap-south-1
  ```
- [ ] Execute SAM deployment with change-set review:
  ```powershell
  sam deploy --parameter-overrides Environment="dev" PermissionsBoundaryArn="arn:aws:iam::137327915859:policy/AegisShareLambdaExecutionBoundary"
  ```
