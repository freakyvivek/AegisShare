# AegisShare: Secure File Sharing with Expiring Access and Audit Logs
## Comprehensive College Project Report & Technical Engineering Documentation

---

### Title Page & Project Metadata

- **Project Title:** AegisShare: Secure File Sharing with Expiring Access and Audit Logs
- **Project Type:** College Capstone Project / Major Technical Project (Information Security & Cloud Computing)
- **Domain:** Cloud Infrastructure Security, Serverless Architecture, Cryptographic Access Control
- **Implementation Stack:** 
  - **Backend & Cloud Compute:** Python 3.14 (Local) / Python 3.12 (AWS Lambda Standard Runtime)
  - **Frontend UI:** Vanilla HTML5, Modern CSS3 (Cybersecurity Theme), JavaScript ES6+
  - **Cloud Infrastructure (AWS):** AWS SAM, Amazon S3, Amazon DynamoDB, Amazon API Gateway (HTTP v2), AWS Lambda, Amazon CloudWatch Logs, AWS IAM
- **Target AWS Account:** `137327915859`
- **Target Region:** `ap-south-1` (Asia Pacific - Mumbai)
- **Live Base API Endpoint:** `https://bl7timg3se.execute-api.ap-south-1.amazonaws.com/dev`
- **CloudFormation Stack Name:** `aegisshare-app`
- **Quality Assurance:** 47 Automated Unit, Mock, Integration, and IaC Tests (100% Passing)
- **Document Version:** 2.0 (Final Comprehensive Project Submission)
- **Status:** **COMPLETED** — Dual-Target Implementation Verified, Cloud Infrastructure Deployed, Production Blockers Resolved, 100% Verified

---

## 1. Executive Summary & Abstract

### 1.1 Abstract
Uncontrolled dissemination of sensitive digital assets and the absence of trace accountability represent severe operational and regulatory vulnerabilities across modern organizations. Conventional file sharing mechanisms—such as unencrypted email attachments or static cloud storage links—typically provide persistent, unmonitored access. They lack deterministic time-to-live (TTL) expiration, fine-grained atomic download limits, owner-controlled instantaneous revocation, and tamper-resistant audit trails.

To address these vulnerabilities, this project designs, implements, hardens, and validates **AegisShare**: an enterprise-grade, serverless secure file-sharing platform. AegisShare enforces ephemeral access control through cryptographically random 256-bit access tokens. Access tokens are stored using a zero-knowledge security model: only one-way SHA-256 cryptographic hashes are persisted in the database registry, ensuring that even a total database compromise does not yield usable plaintext access tokens. 

AegisShare employs a **dual-target deployment architecture**:
1. **Local Demonstration Mode:** A completely self-contained, zero-dependency environment running on Python’s standard library `ThreadingHTTPServer` and local disk storage, guaranteeing immediate, reproducible academic examination on any workstation.
2. **Production AWS Serverless Mode:** A hardened Infrastructure as Code (IaC) implementation utilizing the AWS Serverless Application Model (AWS SAM), orchestrating Amazon S3 (with server-side AES-256 encryption, public access blocking, and TLS transport enforcement), Amazon DynamoDB (on-demand billing with native TTL expiration and conditional writes), AWS Lambda (modular least-privilege IAM micro-services), Amazon API Gateway HTTP API v2 (CORS enabled), and Amazon CloudWatch Logs (7-day cost-optimized retention).

The platform was subjected to rigorous end-to-end security hardening, resolving real-world production deployment hurdles including CloudFormation stage-tagging IAM constraints and API Gateway v2 stage-prefix path dispatching. The comprehensive automated test suite (47 tests) confirms 100% functional correctness, cryptographic integrity, sanitization of sensitive audit data, and least-privilege cloud governance.

### 1.2 Keywords
Cloud Security, Serverless Architecture, Ephemeral Access Tokens, Zero-Knowledge Hashing, Amazon Web Services (AWS), Amazon S3, Amazon DynamoDB, Time-to-Live (TTL), Least Privilege, IAM Permissions Boundary, Immutable Audit Trails.

---

## 2. Problem Statement & Motivation

### 2.1 The Crisis of Persistent File Links
In academic, enterprise, and legal collaboration, sharing proprietary or confidential files is essential. However, the dominant paradigms for digital file sharing suffer from critical security shortcomings:
1. **Indefinite Link Lifespans:** Shared URLs frequently remain active indefinitely on the public internet. If a recipient's inbox is compromised months later, or if a link is forwarded to an untrusted party, sensitive documents remain downloadable without restriction.
2. **Plaintext Database Exposure:** Many commercial and open-source file sharing utilities store active access tokens or raw URLs in plaintext within their databases. In the event of SQL injection, database leakage, or unauthorized administrator access, all active file links are compromised simultaneously.
3. **Absence of Atomic Download Caps:** Standard cloud storage links cannot restrict access to single-use or $N$-use limits. An unauthorized party who intercepts a link can download the file repeatedly without detection or restriction.
4. **Opaque and Contaminated Audit Records:** Organizations typically lack structured audit logging that tracks the full access lifecycle. When access is attempted against an expired or revoked link, the event is either lost in noisy infrastructure logs or recorded with plaintext tokens and presigned AWS credentials exposed in server logs.
5. **High Idle Infrastructure Costs:** Deploying traditional dedicated virtual servers (e.g., EC2 instances or container clusters) for intermittent file sharing incurs ongoing idle costs, maintenance overhead, and patching burdens.

### 2.2 Project Motivation
AegisShare was conceived to prove that enterprise-grade security, cryptographic rigor, and strict compliance controls can be achieved within an efficient, low-cost serverless paradigm. By eliminating external dependencies, adhering to zero-knowledge token management, and providing complete operational visibility, AegisShare establishes an authoritative blueprint for secure, auditable file exchange.

---

## 3. Project Objectives & Scope

### 3.1 Core Objectives
1. **Cryptographically Secure Ephemeral Token Lifecycle:** Generate access tokens with 256 bits of entropy via Python's `secrets` module, enforce deterministic UTC timestamp expiration, and allow configurable download ceilings (single-use or $N$-use).
2. **Zero-Knowledge Token Persistence:** Store strictly one-way SHA-256 hashes of access tokens in metadata registries, returning the raw token to the creator exactly once.
3. **Instantaneous Owner Revocation:** Provide file owners with the capability to invalidate active share tokens on demand prior to scheduled TTL expiry.
4. **Sanitized, Append-Only Audit Logging:** Implement an audit engine that records all security events (`FILE_UPLOAD`, `SHARE_LINK_CREATED`, `DOWNLOAD_SUCCESS`, `ACCESS_REJECTED`, `TOKEN_REVOKED`) while automatically redacting sensitive keys, plaintext tokens, passwords, and presigned AWS query strings.
5. **Dual-Target Execution Architecture:** Ensure 100% feature parity between a zero-dependency local demonstration mode and an enterprise-grade AWS Serverless cloud deployment.
6. **Hardened IAM Governance & Cost Minimization:** Implement strict least-privilege IAM policies constrained by permissions boundaries, enforce S3 bucket encryption and TLS-only policies, disable unnecessary DynamoDB PITR backups, and constrain CloudWatch log retention to 7 days for a cost-optimized academic evaluation.

### 3.2 Project Scope
- **Included in Scope:**
  - Full-stack single-page web dashboard (Vanilla HTML5/CSS3/JavaScript).
  - Modular Python backend services (Token, Storage, Audit, DynamoDB).
  - Local HTTP demonstration server (`backend/local_server.py`).
  - Production AWS SAM template (`infrastructure/template.yaml`).
  - Comprehensive 47-test automated verification suite (`backend/tests/`).
  - Hardened IAM deployment and execution policies (`docs/`).
  - Live deployment to AWS Region `ap-south-1` under account `137327915859`.
- **Excluded from Scope:**
  - Client-side asymmetric public-key cryptography (e.g., PGP/GPG end-to-end key distribution).
  - External federated enterprise identity providers (SAML/Okta integration).

---

## 4. Literature Survey & Competitive Comparison

| Feature / Dimension | Standard Email Attachments | Cloud Storage (Google Drive / OneDrive) | Commercial Transfer (WeTransfer) | AegisShare Platform |
| :--- | :--- | :--- | :--- | :--- |
| **Token Entropy** | None (Static file copy) | Proprietary token IDs | Random URL strings | **256-bit Cryptographic Entropy (`secrets.token_urlsafe`)** |
| **Database Token Security** | N/A | Plaintext/Reversible references | Plaintext token storage | **Zero-Knowledge SHA-256 Hash Matching Only** |
| **TTL Expiration** | Never expires | Manual expiry (Premium tiers only) | Fixed 7-day expiry | **Deterministic UTC Expiration (1 min to 7 days)** |
| **Download Limits** | Unlimited | Unlimited | Unlimited | **Strict Atomic Download Caps (Single-use / $N$-use)** |
| **Revocation Control** | Impossible once sent | Revokes access to all recipients | Deletes file completely | **Individual Token Revocation (Preserves source file)** |
| **Audit Scrubbing** | None | High-level activity logs | Basic delivery receipts | **Sanitized Telemetry (Auto-redaction of secrets/query strings)** |
| **Deployment Model** | Centralized Mail Server | Closed-source SaaS | Closed-source SaaS | **Dual-Target: Local Zero-Dependency & AWS Serverless IaC** |
| **Infrastructure Cost** | Included in mail plan | Monthly SaaS subscription | Subscription per user | **Pay-Per-Request Serverless ($0 idle cost)** |

---

## 5. System Architecture & Detailed Design

AegisShare is architected into five decoupled layers: Client Presentation, API Ingress & Routing, Business Logic Services, Persistence Stores, and Audit Telemetry.

```
+-----------------------------------------------------------------------------------------+
|                               Client Tier (Web Browser)                                 |
|   - Security Overview Dashboard & System Status Indicator                               |
|   - Drag-and-Drop Vault File Uploader with MIME-Type Validation                         |
|   - Ephemeral Link Generator (Configurable TTL & Download Caps)                         |
|   - Share Token Manager with Instant Revocation Modal                                   |
|   - Immutable Audit Log Explorer with Outcome & Event Type Filters                      |
|   - Recipient Download Portal with Live Real-Time Expiration Countdown                 |
+--------------------------------------------+--------------------------------------------+
                                             | HTTPS / JSON REST API
                                             v
+-----------------------------------------------------------------------------------------+
|                               API Ingress & Routing Tier                                |
|   [Local Mode]  Python Standard Library ThreadingHTTPServer (CORS-Enabled)              |
|   [AWS Mode]    Amazon API Gateway HTTP API v2 (Native Routing, CORS, Stage Normalizer)|
+--------------------------------------------+--------------------------------------------+
                                             | Dispatch Request
                                             v
+-----------------------------------------------------------------------------------------+
|                             Core Business Services Tier                                 |
|   - TokenService: Cryptographic Token Generation, SHA-256 Hashing, Lifecycle Validation |
|   - StorageService (Abstract): Interface for Object Persistence & Presigned URL Signing  |
|   - AuditService: Sanitized Structured Telemetry Logging with Sensitive Data Redaction   |
|   - ApiDispatcher: Stage-Prefix Path Normalizer and Micro-Service Handler Routing       |
+---------------------+---------------------------------------------+---------------------+
                      |                                             |
                      v                                             v
+-------------------------------------------+ +-------------------------------------------+
|          Local Demonstration Mode         | |            AWS Serverless Cloud Mode      |
| - Storage: local_storage/files/           | | - Object Storage: Amazon S3 (AES-256 SSE, |
| - Metadata: local_storage/metadata/       | |   Block Public Access, TLS Enforcement)   |
| - Audit Store: local_storage/audit_log    | | - NoSQL Metadata: Amazon DynamoDB         |
| - Memory Registry: Active Token State     | |   (FilesTable, TokensTable with TTL,      |
|                                           | |    AuditLogsTable, GSI Indexes)           |
|                                           | | - Compute: AWS Lambda (Python 3.12)       |
|                                           | | - Monitoring: Amazon CloudWatch Logs      |
+-------------------------------------------+ +-------------------------------------------+
```

### 5.1 Component Details
1. **Presentation Layer (`frontend/`):**
   - Implemented in Vanilla HTML5, CSS3, and ES6 JavaScript without external build frameworks.
   - Designed using a cybersecurity command-center dark theme (`#0a0e17` background, `#00ff88` security green, `#38bdf8` cyber blue, `#f43f5e` danger red) using Google Fonts `Inter` and `JetBrains Mono`.
   - Communicates asynchronously via REST endpoints using `fetch()` and supports live API endpoint switching between local demo mode and AWS cloud endpoints.
2. **Unified API Gateway Dispatcher (`backend/handlers/api_dispatcher.py`):**
   - Serves as the single ingress routing point for the AWS Lambda function.
   - Implements `normalize_path(path, stage)` to dynamically strip stage prefixes (e.g., `/dev`) injected by HTTP API Gateway v2, ensuring clean, uniform route dispatching.
   - Evaluates HTTP methods, handles global CORS `OPTIONS` pre-flight requests (HTTP 204), and delegates to specific modular handlers.
3. **Modular AWS Lambda Handlers (`backend/handlers/`):**
   - `upload_handler.py`: Validates file metadata, generates S3 presigned PUT URLs or persists local payloads, and registers file records.
   - `share_handler.py`: Issues high-entropy tokens, computes SHA-256 hashes, writes metadata to DynamoDB, and logs audit events.
   - `inspect_handler.py`: Allows recipients to inspect validity, remaining TTL, and remaining download count without decrementing quotas.
   - `download_handler.py`: Executes atomic download quota consumption, generates S3 presigned GET URLs (HTTP 302 redirect) or streams local bytes, and records audit telemetry.
   - `revoke_handler.py`: Enables owners to revoke active tokens immediately.
   - `audit_handler.py`: Provides filtered query access to immutable audit records.
   - `health_handler.py`: Returns diagnostic operational health, storage backend type, and configured AWS resource names.

---

## 6. Cryptographic Architecture & Threat Mitigation

### 6.1 Ephemeral Token Lifecycle & Zero-Knowledge Storage
The security of AegisShare relies on the mathematical guarantee that plaintext tokens are never stored in any persistent medium:

```
[User Request: Create Share Link]
               |
               v
   secrets.token_urlsafe(32)   ---> 256 bits of cryptographic entropy
               |
               +-------------------------------------------+
               |                                           |
               v                                           v
       [Plaintext Token]                           SHA-256 Hashing
               |                                           |
               v                                           v
   Returned ONCE to Creator                   Token Hash (64 hex characters)
   (Never stored in database)                              |
                                                           v
                                            Stored in DynamoDB / Registry
                                            (token_hash, file_id, ttl, ...)
```

1. **Token Generation:** The platform generates tokens using `secrets.token_urlsafe(32)`, producing a 43-character URL-safe string containing 256 bits of CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) entropy.
2. **One-Way Transformation:** Prior to database persistence, the system hashes the token:
   $$\text{token\_hash} = \text{SHA-256}(\text{raw\_token})$$
3. **Zero-Knowledge Storage:** The database record stores `token_hash`, `file_id`, `created_at_utc`, `expires_at_utc`, `ttl`, `max_downloads`, `download_count`, and `is_revoked`. The plaintext token is returned in the API response and immediately discarded from memory.
4. **Validation Logic:** When a recipient submits `raw_token`, the server computes $\text{SHA-256}(\text{raw\_token})$ and performs a primary key lookup. Validation follows a strict sequence:
   $$\text{Exists} \longrightarrow \text{Revocation Check} \longrightarrow \text{Timestamp TTL Check} \longrightarrow \text{Download Ceiling Check}$$

### 6.2 Threat Mitigation Matrix

| Threat Vector | Attack Scenario | AegisShare Defense Mechanism |
| :--- | :--- | :--- |
| **Database Dump Leakage** | Adversary gains read access to the DynamoDB tables or local metadata files. | **Zero-Knowledge SHA-256 Hashing:** The database contains only one-way cryptographic hashes. Because SHA-256 is computationally infeasible to invert, stolen hashes cannot be used to download files. |
| **Token Brute-Force** | Adversary attempts to guess active sharing tokens via automated HTTP requests. | **High Entropy Space:** With 256 bits of entropy ($2^{256} \approx 1.15 \times 10^{77}$ combinations), brute-force guessing is mathematically impossible. |
| **Path Traversal Attacks** | Malicious actor supplies `file_id = "../../../../etc/passwd"` to read host system files. | **Strict Basename Sanitization:** `Path(file_id).name` and regex sanitization `^[a-zA-Z0-9_-]+$` strip directory separators and reject malicious identifiers. |
| **Credential Leakage in Logs** | AWS access keys, session tokens, or presigned URLs leak into CloudWatch or server logs. | **Automated Audit Sanitization:** Regex filters redact any key matching `(token|password|secret|key)` and strip query parameters from presigned URLs. |
| **Man-in-the-Middle (MitM)** | Network adversary intercepts traffic between client and cloud. | **Mandatory TLS Enforcement:** The S3 bucket policy enforces `Deny` on requests where `aws:SecureTransport == 'false'`. API Gateway enforces HTTPS on all REST endpoints. |
| **Privilege Escalation** | Deployment credentials attempt to grant unauthorized admin rights to runtime roles. | **IAM Permissions Boundary:** `AegisShareLambdaExecutionBoundary` sets an immutable ceiling preventing the Lambda role from acquiring escalated permissions. |

---

## 7. Infrastructure as Code (AWS SAM) Specification

The complete AWS serverless infrastructure is defined declaratively in [`infrastructure/template.yaml`](file:///d:/AWS%20SECURE%20FILE%20SHARING/infrastructure/template.yaml).

### 7.1 Amazon S3 Vault Architecture
- **Resource:** `EncryptedFilesBucket` (`AWS::S3::Bucket`)
- **Bucket Naming:** `aegisshare-secure-vault-${Environment}-${AWS::AccountId}`
- **Server-Side Encryption:** Enforced via `AES256` (SSE-S3) on all objects.
- **Public Access Blocking:** All four flags (`BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets`) set to `true`.
- **Bucket Policy:** Denies any operation where `aws:SecureTransport: false`.
- **Lifecycle Management:** Automatically aborts incomplete multipart uploads after 1 day (`AbortIncompleteMultipartUpload`).

### 7.2 Amazon DynamoDB Architecture
Configured with on-demand capacity (`PAY_PER_REQUEST`) to guarantee zero idle cost:
1. **Files Table (`aegisshare-files-${Environment}`):**
   - Partition Key: `file_id` (String)
   - Stores file metadata, original filename, byte size, MIME type, and storage path.
2. **Share Tokens Table (`aegisshare-tokens-${Environment}`):**
   - Partition Key: `token_hash` (String)
   - Native DynamoDB Time-to-Live enabled on attribute: `ttl` (Epoch seconds).
   - Global Secondary Index (GSI): `FileIdIndex` on `file_id` (enables querying all tokens for a file).
3. **Audit Logs Table (`aegisshare-audit-logs-${Environment}`):**
   - Partition Key: `event_id` (String)
   - Global Secondary Index (GSI): `FileIdEventsIndex` on `file_id` (Hash) and `timestamp_utc` (Range).
- **Cost Configuration:** `PointInTimeRecoveryEnabled` explicitly set to `false` for low-cost student demonstration.

### 7.3 Amazon API Gateway HTTP API v2 Architecture
To ensure compatibility with least-privilege IAM deployment identities, API Gateway is defined using native CloudFormation resources without unneeded tags:
- `HttpApiGateway` (`AWS::ApiGatewayV2::Api`): Protocol type `HTTP` with CORS configuration allowing `GET, POST, OPTIONS, PUT, DELETE` and headers `Content-Type, Authorization, X-Requested-With, X-File-Name`.
- `HttpApiGatewayStage` (`AWS::ApiGatewayV2::Stage`): Auto-deployed to stage `${Environment}` (`dev`), strictly omitting `Tags` to eliminate stage-tagging permission requirements.
- `HttpApiGatewayIntegration` (`AWS::ApiGatewayV2::Integration`): Proxy integration (`AWS_PROXY`) to Lambda with `PayloadFormatVersion: "2.0"`.
- `HttpApiProxyRoute` & `HttpApiRootRoute` (`AWS::ApiGatewayV2::Route`): Routes `ANY /{proxy+}` and `ANY /` targeting the Lambda integration.
- `HttpApiLambdaPermission` (`AWS::Lambda::Permission`): Grants `apigateway.amazonaws.com` permission to invoke `AegisShareApiFunction`.

### 7.4 AWS Lambda Compute
- **Function:** `AegisShareApiFunction` (`AWS::Serverless::Function`)
- **Runtime:** `python3.12` | Memory: `256 MB` | Timeout: `15 seconds` | Architecture: `x86_64`
- **Permissions Boundary:** Bound to `AegisShareLambdaExecutionBoundary`.
- **Scoped Policies:** Granular S3 object permissions restricted strictly to `arn:aws:s3:::${EncryptedFilesBucket}/*` and DynamoDB table actions restricted strictly to the three table ARNs and their index ARNs.

---

## 8. IAM Security Engineering & Least-Privilege Governance

A key contribution of this project is the rigorous separation and hardening of cloud identities, documented in [`docs/deployment-policy.json`](file:///d:/AWS%20SECURE%20FILE%20SHARING/docs/deployment-policy.json) and [`docs/lambda-execution-policy.json`](file:///d:/AWS%20SECURE%20FILE%20SHARING/docs/lambda-execution-policy.json).

```
+----------------------------------------------------+
|  Deployment Identity (AegisShareDeployUser)        |
|  - CloudFormation Stack Management                 |
|  - S3 SAM Artifact Uploads                         |
|  - S3 Vault Control Plane ONLY (No Object Access)  |
|  - DynamoDB Table Control Plane ONLY               |
|  - Lambda Function Provisioning                    |
|  - API Gateway V2 Route/Stage Configuration        |
|  - CloudWatch Log Group Lifecycle (7-Day TTL)      |
|  - Restricted IAM Role Creation (Boundary Forced)  |
+-------------------------+--------------------------+
                          | Deploys Stack & Role
                          v
+----------------------------------------------------+
|  Runtime Execution Role (aegisshare-app-Role)      |
|  - Boundary: AegisShareLambdaExecutionBoundary     |
|  - S3 Object Access (EncryptedFilesBucket ONLY)    |
|  - DynamoDB Record CRUD (AegisShare Tables ONLY)   |
|  - CloudWatch Log Stream Writing                   |
+----------------------------------------------------+
```

### 8.1 Key Hardening Principles Implemented
1. **Confidentiality Protection (Zero Deployer Object Access):**
   The deployment user `AegisShareDeployUser` possesses control-plane permissions to create, update, or delete the S3 bucket via CloudFormation, but possesses **zero permissions to read, write, or delete user files** (`s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on `aegisshare-secure-vault-*` are completely revoked). Only the Lambda runtime role can access vault objects.
2. **Neutralization of Privilege Escalation:**
   - `iam:CreateRole` strictly requires the `AegisShareLambdaExecutionBoundary` permissions boundary via a condition block.
   - `iam:UpdateAssumeRolePolicy` was scrubbed, preventing trust policy tampering to assume the execution role directly.
   - `iam:AttachRolePolicy` and `iam:DetachRolePolicy` are strictly constrained to the AWS managed policy `AWSLambdaBasicExecutionRole`.
   - `iam:PassRole` is strictly conditioned to permit passing roles exclusively to `lambda.amazonaws.com`.
3. **Invalid Action Scrubbing:**
   Scrubbed invalid AWS actions (such as `s3:HeadObject`, which does not exist as an independent IAM action and is governed by `s3:GetObject`).

---

## 9. Engineering Challenges & Production Bug Resolutions

During the cloud engineering lifecycle, several non-trivial architectural and deployment hurdles arose. Their technical analysis and resolutions represent significant real-world engineering achievements:

### 9.1 Case Study 1: Lambda Footprint Optimization (99.7% Package Reduction)
- **Problem:** Initial builds included a 97.5 MB Windows installer binary (`AWS_SAM_CLI_64_PY3.msi`) located in the root repository. Packaging this into the Lambda artifact led to build bloat (>98 MB zip), risking deployment timeouts and Lambda package size limit violations. Furthermore, SAM CLI reported missing `requirements.txt`.
- **Investigation:** Analysis of the backend services proved that AegisShare relies entirely on the Python Standard Library (`hashlib`, `secrets`, `hmac`, `dataclasses`, `datetime`, `json`, `urllib`) and the AWS Lambda runtime's pre-bundled `boto3` and `botocore`.
- **Resolution:** Moved the installer out of the build context and validated that zero third-party packages were needed. The resulting Lambda deployment zip was reduced to **293 KB** (a **99.7% reduction**), ensuring sub-second cold starts and zero external supply-chain vulnerabilities.

### 9.2 Case Study 2: CloudFormation Stage-Tagging Rollback (`apigateway:TagResource`)
- **Problem:** CloudFormation repeatedly rolled back the `aegisshare-app` stack with the error:
  ```text
  Resource: HttpApiGatewayStage (AWS::ApiGatewayV2::Stage)
  Action denied: apigateway:TagResource on arn:aws:apigateway:ap-south-1::/apis/{id}/stages
  User AegisShareDeployUser is not authorized to perform apigateway:TagResource
  ```
- **Root Cause Analysis:** Deep inspection of AWS SAM’s internal translator (`samtranslator/model/api/http_api_generator.py`) revealed that the high-level macro `AWS::Serverless::HttpApi` unconditionally hardcodes and injects the tag `{"httpapi:createdBy": "SAM"}` onto the synthesized `AWS::ApiGatewayV2::Stage` CloudFormation resource. Because `AegisShareDeployUser` was provisioned under strict least privilege (`GET, POST, PUT, PATCH, DELETE`), it lacked `apigateway:TagResource`.
- **Engineering Solution:** Rather than granting dangerous broad tagging permissions or full administrative privileges, `infrastructure/template.yaml` was refactored to use native CloudFormation resources (`AWS::ApiGatewayV2::Api`, `AWS::ApiGatewayV2::Stage`, `AWS::ApiGatewayV2::Integration`, and `AWS::ApiGatewayV2::Route`). The stage was defined explicitly with auto-deploy enabled and tags omitted. Inspection of the synthesized CloudFormation template confirmed zero tagging calls, allowing clean, deterministic stack creation.

### 9.3 Case Study 3: HTTP API Gateway v2 Stage-Prefix Dispatching (`ROUTE_NOT_FOUND`)
- **Problem:** Following successful cloud deployment, calling the live health endpoint returned:
  ```json
  {"error": "ROUTE_NOT_FOUND", "path": "/dev/api/health", "method": "GET"}
  ```
- **Root Cause Analysis:** In AWS HTTP API Gateway v2 deployed to a named stage (e.g., `dev`), the incoming event's `rawPath` arrives as `/dev/api/health`, and `event.requestContext.stage` is `"dev"`. The application dispatcher (`api_dispatcher.py`) evaluated paths against root patterns (`/api/health`), causing stage-prefixed routes to miss all route table entries.
- **Engineering Solution:** Implemented `normalize_path(path, stage)` in `backend/handlers/api_dispatcher.py`:
  ```python
  def normalize_path(path: str, stage: Optional[str] = None) -> str:
      normalized = path.rstrip("/") if path else ""
      if not stage or stage == "$default":
          return normalized
      stage_prefix = f"/{stage}"
      if normalized == stage_prefix:
          return "/"
      if normalized.startswith(f"{stage_prefix}/"):
          return normalized[len(stage_prefix):]
      return normalized
  ```
  The function removes exactly one leading `/{stage}` prefix when a named stage is active, preserves query parameters, avoids altering non-staged or `$default` routes, and maintains complete compatibility with local-demo execution.

---

## 10. Database Design & REST API Specification

### 10.1 Amazon DynamoDB Schema (AWS Mode)

#### 1. Files Metadata Table (`aegisshare-files-dev`)
| Attribute | DynamoDB Type | Key Role | Description |
| :--- | :---: | :---: | :--- |
| `file_id` | `S` (String) | **Partition Key (PK)** | Unique identifier (`file_<12 hex chars>`) |
| `original_filename` | `S` (String) | Attribute | User's uploaded filename (sanitized) |
| `file_size_bytes` | `N` (Number) | Attribute | File size in bytes |
| `content_type` | `S` (String) | Attribute | Detected MIME type |
| `uploaded_at_utc` | `S` (String) | Attribute | ISO 8601 UTC timestamp |
| `storage_backend` | `S` (String) | Attribute | Storage provider (`aws_s3` or `local_disk`) |
| `storage_key_or_path` | `S` (String) | Attribute | S3 object key or relative local path |

#### 2. Share Tokens Table (`aegisshare-tokens-dev`)
| Attribute | DynamoDB Type | Key Role | Description |
| :--- | :---: | :---: | :--- |
| `token_hash` | `S` (String) | **Partition Key (PK)** | SHA-256 digest of raw token (64 hex characters) |
| `file_id` | `S` (String) | Attribute / **GSI PK** | Foreign key linking to file metadata |
| `created_at_utc` | `S` (String) | Attribute | ISO 8601 UTC creation timestamp |
| `expires_at_utc` | `S` (String) | Attribute | ISO 8601 UTC expiration timestamp |
| `ttl` | `N` (Number) | Attribute (TTL) | Unix epoch expiration timestamp for DynamoDB TTL engine |
| `max_downloads` | `N` (Number) / Null | Attribute | Maximum permitted download quota |
| `download_count` | `N` (Number) | Attribute | Current download count (atomically incremented) |
| `is_revoked` | `BOOL` (Boolean) | Attribute | Revocation flag (default `false`) |
| `revoked_at_utc` | `S` (String) / Null | Attribute | Timestamp of manual revocation |

#### 3. Audit Logs Table (`aegisshare-audit-logs-dev`)
| Attribute | DynamoDB Type | Key Role | Description |
| :--- | :---: | :---: | :--- |
| `event_id` | `S` (String) | **Partition Key (PK)** | Unique identifier (`audit_<12 hex chars>`) |
| `file_id` | `S` (String) | Attribute / **GSI PK** | Associated file ID |
| `timestamp_utc` | `S` (String) | Attribute / **GSI SK** | ISO 8601 UTC event timestamp |
| `event_type` | `S` (String) | Attribute | Event classification (`FILE_UPLOAD`, `DOWNLOAD_SUCCESS`, etc.) |
| `outcome` | `S` (String) | Attribute | Result (`SUCCESS`, `DENIED`, `ERROR`) |
| `actor_ip` | `S` (String) | Attribute | Client IP address |
| `user_agent` | `S` (String) | Attribute | Client HTTP User-Agent |
| `token_hash_prefix` | `S` (String) | Attribute | First 8 characters of token hash for safe tracing |
| `reason` | `S` (String) | Attribute | Rejection reason or context |
| `details` | `M` (Map) | Attribute | Structured, scrubbed event metadata |

---

### 10.2 REST API Specification

| Method | Endpoint | Description | Request Parameters / Body | Response Status & Structure |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Health & diagnostic status | None | `200 OK`: `{"status": "HEALTHY", "storage_backend": "...", "aws_region": "..."}` |
| `GET` | `/api/files` | List vault files | None | `200 OK`: `{"files": [...]}` |
| `POST` | `/api/upload` | Upload new file payload | Multipart Form or JSON base64 | `201 Created`: `{"file_id": "...", "filename": "...", "file_size_bytes": 1024}` |
| `POST` | `/api/share` | Generate ephemeral link | `{"file_id": "...", "expires_in_seconds": 3600, "max_downloads": 1}` | `201 Created`: `{"token": "<RAW>", "token_hash_prefix": "...", "expires_at_utc": "..."}` |
| `GET` | `/api/tokens/inspect` | Non-destructive inspection | Query param: `?token=<RAW_TOKEN>` | `200 OK`: `{"status": "VALID", "remaining_downloads": 1, "expires_in_seconds": 3540}` |
| `GET` | `/api/download` | Consume download & stream | Query param: `?token=<RAW_TOKEN>` | `200 OK` (Local binary stream) or `302 Redirect` (S3 presigned URL) |
| `POST` | `/api/revoke` | Revoke active link | `{"token": "<RAW>"}` or `{"token_hash": "..."}` | `200 OK`: `{"revoked": true, "token_hash_prefix": "..."}` |
| `GET` | `/api/tokens` | List token registry (hashes) | Optional: `?file_id=...` | `200 OK`: `{"tokens": [...]}` |
| `GET` | `/api/audit` | Query immutable audit logs | Optional: `?file_id=...&event_type=...` | `200 OK`: `{"events": [...]}` |

---

## 11. Verification, Testing & Quality Assurance

Quality assurance was achieved via Python’s `unittest` framework. All 47 automated test cases execute deterministically in **~0.8 seconds** with zero failures:

```text
Ran 47 tests in 0.806s
OK (47 passed, 0 failures, 0 errors)
```

### 11.1 Test Suite Breakdown

```
===================================================================================
MODULE                                  TEST COUNT   SCOPE & VERIFIED INVARIANTS
===================================================================================
backend/tests/test_token_service.py         8        Entropy generation (256-bit), SHA-256
                                                     matching, non-plaintext storage, UTC TTL
                                                     expiration, download limits, revocation.
backend/tests/test_storage_service.py       7        Local storage CRUD, path traversal (../)
                                                     rejection, descriptor generation, S3 client
                                                     invariants, zero-silent-fallback check.
backend/tests/test_audit_service.py         3        Append-only JSONL persistence, query filters,
                                                     redaction of passwords, tokens, presigned URLs.
backend/tests/test_dynamodb_service.py      5        Files metadata store, token store TTL math,
                                                     atomic conditional increment, audit mock table.
backend/tests/test_lambda_handlers.py      11        Proxy event parsing, CORS headers, health check,
                                                     404 routing, normalize_path unit tests, v2 mock
                                                     events, unaltered routes, $default stage handling.
backend/tests/test_integration_flow.py      3        Full lifecycle: upload -> share -> valid download
                                                     -> limit exhaustion -> expiration -> revocation.
backend/tests/test_local_server.py          2        Live HTTP socket calls to /api/health, upload,
                                                     share, inspect, download, and audit endpoints.
backend/tests/test_sam_template.py          8        SAM IaC validation: S3 AES-256 SSE, PublicAccessBlock,
                                                     DynamoDB TTL, native API Gateway V2, IAM boundaries.
===================================================================================
TOTAL AUTOMATED TESTS                      47        ALL 47 TESTS PASSING (0 FAILURES)
===================================================================================
```

---

## 12. Live AWS Cloud Deployment & Operational Validation

The application infrastructure was provisioned in AWS and verified live:

### 12.1 Live Deployment Parameters
- **AWS Account ID:** `137327915859`
- **Deployment User:** `arn:aws:iam::137327915859:user/AegisShareDeployUser`
- **Region:** `ap-south-1` (Mumbai)
- **Stack Name:** `aegisshare-app`
- **CloudFormation Status:** `CREATE_COMPLETE` / `UPDATE_COMPLETE`

### 12.2 Live Cloud Resources Verified
| Cloud Resource | Resource Physical ID / Name | Operational Status |
| :--- | :--- | :---: |
| **HTTP API Gateway (v2)** | `bl7timg3se` | **ACTIVE** |
| **API Gateway Stage** | `dev` | **ACTIVE** |
| **Lambda API Dispatcher** | `aegisshare-app-AegisShareApiFunction-Yp2N3mQ1...` | **ACTIVE** |
| **S3 Vault Storage Bucket** | `aegisshare-secure-vault-dev-137327915859` | **ACTIVE** |
| **DynamoDB Files Table** | `aegisshare-files-dev` | **ACTIVE** |
| **DynamoDB Tokens Table** | `aegisshare-tokens-dev` (TTL Enabled) | **ACTIVE** |
| **DynamoDB Audit Table** | `aegisshare-audit-logs-dev` | **ACTIVE** |
| **CloudWatch Log Group** | `/aws/lambda/aegisshare-app-AegisShareApiFunction-...` | **ACTIVE (7d Retention)** |

### 12.3 Live Diagnostic Verification
Executing `curl` against the live production endpoint confirms operational status:
```powershell
curl https://bl7timg3se.execute-api.ap-south-1.amazonaws.com/dev/api/health
```
**Live Response Received (HTTP 200 OK):**
```json
{
  "status": "HEALTHY",
  "storage_backend": "aws_s3_dynamodb",
  "aws_region": "ap-south-1",
  "s3_bucket": "aegisshare-secure-vault-dev-137327915859",
  "files_table": "aegisshare-files-dev",
  "tokens_table": "aegisshare-tokens-dev",
  "audit_table": "aegisshare-audit-logs-dev"
}
```

---

## 13. Step-by-Step Demonstration Guide

The complete AegisShare workflow can be demonstrated in under 5 minutes either locally or against live AWS endpoints:

### Scenario 1: Harmless Sample File Upload
1. Navigate to the **File Vault & Upload** section.
2. Drag and drop a test file (e.g., `capstone_confidential.pdf`) or select via browser dialog.
3. The file is uploaded, assigned a collision-resistant ID (`file_<hex>`), and registered in the vault table.

### Scenario 2: Ephemeral Share Link Generation
1. Click **Create Share Link** on the uploaded file.
2. Configure **Link Lifespan (TTL)** to `1 Minute (Quick Demo Expiry)` and **Maximum Downloads** to `Single-Use (1 Download)`.
3. Click **Generate Secure Link**. The system presents the unique sharing URL containing the raw token and warns that plaintext is never stored.

### Scenario 3: Recipient Inspection & Valid Download
1. Open the generated link in an Incognito window or in the **Download Portal** view.
2. The portal inspects the token via `GET /api/tokens/inspect`: displays `VALID` status badge, live real-time countdown timer, and `1 download remaining`.
3. Click **Download File Now**. The file downloads instantly, and the remaining download counter decrements to `0`.

### Scenario 4: Download Quota Exhaustion Enforcement
1. Immediately attempt to click **Download File Now** a second time.
2. The server intercepts the request and returns **HTTP 410 Gone** (`ACCESS_EXHAUSTED`).
3. An alert displays: *Access Denied: Maximum download limit reached.*

### Scenario 5: Automatic UTC Time-to-Live (TTL) Expiration
1. Generate a share link with a 60-second TTL.
2. Allow 61 seconds to elapse.
3. Accessing the link displays `LINK EXPIRED` in red text. Requesting download returns **HTTP 410 Gone** (`ACCESS_EXPIRED`).

### Scenario 6: Immediate Owner Revocation
1. Locate an active share link in the **Share Tokens Management** view.
2. Click **Revoke Link**. The link status updates immediately to `REVOKED`.
3. Any subsequent recipient attempt to access the link is rejected with **HTTP 403 Forbidden** (`TOKEN_REVOKED`).

### Scenario 7: Immutable Audit Trail Exploration
1. Open the **Audit Trail** explorer.
2. Verify that every preceding action (`FILE_UPLOAD`, `SHARE_LINK_CREATED`, `DOWNLOAD_SUCCESS`, `ACCESS_REJECTED`, `TOKEN_REVOKED`) is recorded in chronological order.
3. Observe that all sensitive credentials, passwords, and presigned query strings are completely redacted.

---

## 14. Cost Optimization & Sustainability Analysis

AegisShare was explicitly engineered for minimal financial expenditure during student demonstration and academic review:

| Architectural Component | Default / Production Setting | AegisShare Demonstration Setting | Cost Impact |
| :--- | :--- | :--- | :--- |
| **DynamoDB Billing** | Provisioned RCU/WCU ($10–$50/mo) | `PAY_PER_REQUEST` (On-Demand) | **$0.00 idle cost** (Free tier covers 25 GB) |
| **DynamoDB Backups** | Point-in-Time Recovery ($0.20/GB/mo) | `PointInTimeRecoveryEnabled: false` | **$0.00 backup charges** |
| **Compute** | EC2 Instances ($15–$80/mo) | AWS Lambda (Pay-per-request) | **$0.00 idle cost** (Free tier covers 1M requests/mo) |
| **Object Storage** | S3 Standard with indefinite retention | S3 Standard with incomplete upload cleanup | **<$0.01/month** (Pennies for demo files) |
| **Logging** | CloudWatch Logs (Infinite / 30-day retention) | `RetentionInDays: 7` | **Zero storage accumulation** |
| **API Ingress** | REST API v1 or ALB ($16–$25/mo) | HTTP API Gateway v2 | **$1.00 / million calls** ($0.00 for demo traffic) |

**Estimated Total Monthly Operating Cost for Demonstration:** **$0.00 – $0.02 USD**.

---

## 15. Limitations & Future Roadmap

### 15.1 Current Limitations
1. **S3 Presigned URL Window:** In AWS mode, an S3 presigned GET redirect grants a 300-second window during which the specific presigned URL can be downloaded directly from S3, bypassing Lambda.
2. **Dashboard Authentication:** The demonstration interface operates as a local administrative console without individual multi-tenant user accounts.

### 15.2 Future Roadmap
1. **CloudFront Signed Cookies & Lambda@Edge:** Terminate downloads at the edge using CloudFront signed cookies to enforce single-use streaming directly at CDN points of presence.
2. **Client-Side AES-GCM-256 Web Crypto:** Implement client-side encryption in the browser using the Web Crypto API, ensuring file bytes are encrypted before transmission to S3.
3. **Amazon Cognito MFA Integration:** Add user pools with Time-based One-Time Password (TOTP) multi-factor authentication for vault administrators.

---

## 16. Conclusion

The **AegisShare** capstone project successfully demonstrates an enterprise-grade solution to the risks of uncontrolled, permanent file sharing. By integrating cryptographic 256-bit token entropy, zero-knowledge SHA-256 database hashing, automated UTC TTL expiration, atomic download ceilings, and sanitized audit trails, the platform delivers ironclad access control. 

The dual-target execution model guarantees immediate academic reproducibility on standard workstations while maintaining an authenticated, production-grade AWS serverless cloud deployment. With 47 passing automated tests and a live deployment on AWS Region `ap-south-1`, AegisShare stands as a complete, rigorously verified, and production-hardened engineering achievement.

---

## 17. Formal Academic & Technical References

1. **National Institute of Standards and Technology (NIST):** *Secure Hash Standard (SHS)*, Federal Information Processing Standards Publication (FIPS PUB 180-4), Information Technology Laboratory, Gaithersburg, MD, August 2015.
2. **Amazon Web Services:** *AWS Serverless Application Model (SAM) Developer Guide*, AWS Documentation, Seattle, WA, 2024.
3. **Amazon Web Services:** *Protecting Data Using Server-Side Encryption with Amazon S3-Managed Keys (SSE-S3)*, Amazon Simple Storage Service User Guide, 2024.
4. **Amazon Web Services:** *Expiring Items by Using DynamoDB Time to Live (TTL)*, Amazon DynamoDB Developer Guide, 2024.
5. **Python Software Foundation:** *secrets — Generate secure random numbers for managing secrets*, Python 3.14 Standard Library Documentation, 2024.
6. **Open Web Application Security Project (OWASP):** *OWASP Top 10: Serverless Security Risks*, OWASP Foundation, 2023.
7. **Internet Engineering Task Force (IETF):** *The Transport Layer Security (TLS) Protocol Version 1.3*, RFC 8446, August 2018.
