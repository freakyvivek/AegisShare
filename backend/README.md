# Backend Services: Secure File Sharing with Expiring Access and Audit Logs

This directory contains the core services, security controls, automated test suites, and local demonstration server for the college capstone project.

---

## 1. Module Overview

| Module | Purpose | Key Classes / Functions |
| :--- | :--- | :--- |
| [`services/token_service.py`](file:///d:/AWS%20SECURE%20FILE%20SHARING/backend/services/token_service.py) | Ephemeral token lifecycle, cryptographic generation, and access limit enforcement. | `TokenService`, `TokenRecord`, `TokenStatus`, `TokenExpiredError`, `TokenExhaustedError`, `TokenRevokedError` |
| [`services/storage_service.py`](file:///d:/AWS%20SECURE%20FILE%20SHARING/backend/services/storage_service.py) | Abstract storage contracts with dedicated local demo and AWS S3 adapters. | `StorageService` (ABC), `LocalStorageService`, `S3StorageService`, `FileMetadata`, `UploadDescriptor`, `DownloadDescriptor` |
| [`services/audit_service.py`](file:///d:/AWS%20SECURE%20FILE%20SHARING/backend/services/audit_service.py) | Immutable structured audit logger with sensitive credential and signature scrubbing. | `AuditService`, `AuditRecord`, `AuditEventType`, `AuditOutcome` |
| [`local_server.py`](file:///d:/AWS%20SECURE%20FILE%20SHARING/backend/local_server.py) | Standalone local HTTP server (using Python standard library) exposing demo REST APIs. | `SecureFileSharingHandler`, `create_app()`, `run_server()` |
| [`tests/`](file:///d:/AWS%20SECURE%20FILE%20SHARING/backend/tests/) | Automated unit and end-to-end integration test suite using Python `unittest`. | `test_token_service.py`, `test_storage_service.py`, `test_audit_service.py`, `test_integration_flow.py`, `test_local_server.py` |

---

## 2. Core Security Controls & Assumptions

1. **Token Security & One-Way Hashing:**
   - Tokens are generated using `secrets.token_urlsafe(32)` (cryptographically secure randomness).
   - Plaintext tokens are returned to the creator once and **NEVER stored in the metadata store**. Only the SHA-256 hash (`hashlib.sha256`) is stored.
   - Even if the metadata store or database is compromised, attackers cannot reconstruct the active share tokens.

2. **Strict UTC Expiration Enforcement:**
   - Expiration dates are tracked and verified using UTC timestamps (`datetime.now(timezone.utc)`).
   - Any access attempt past `expires_at_utc` triggers immediate rejection (`TokenExpiredError`) and generates an `ACCESS_REJECTED` audit event.

3. **Download Limit Counters:**
   - Tokens can enforce a single-use or multi-use ceiling (`max_downloads`).
   - Once `download_count >= max_downloads`, subsequent attempts fail with `TokenExhaustedError`.

4. **Explicit Revocation:**
   - Tokens can be revoked prior to expiration by the file owner, terminating further downloads.

5. **Storage Isolation & No Silent Fallbacks:**
   - `LocalStorageService` stores files in an isolated local directory (`local_storage/files/`) with strict basename sanitization to prevent path traversal attacks. It is explicitly labeled `local_demo_storage` and never misrepresented as Amazon S3.
   - `S3StorageService` generates short-lived presigned URLs (default 300 seconds) with Server-Side Encryption (`AES256` or AWS KMS) and private ACLs. If `boto3` or AWS configuration is missing, it raises `StorageConfigurationError` and **never silently falls back to local storage**.

6. **Audit Trail Sanitization:**
   - The audit logger records security events (`FILE_UPLOAD`, `SHARE_LINK_CREATED`, `DOWNLOAD_SUCCESS`, `ACCESS_REJECTED`, `TOKEN_REVOKED`).
   - Plaintext tokens, passwords, and sensitive credentials are redacted (`[REDACTED_SENSITIVE_DATA]`).
   - Pre-signed URLs have their query parameters (including AWS signatures and access keys) stripped (`[QUERY_STRIPPED_FOR_AUDIT]`).

---

## 3. Local Data Storage Locations

When running in local demo mode, files and logs are persisted under:
```
D:/AWS SECURE FILE SHARING/local_storage/
├── files/             # Actual uploaded binary files (named by safe file_id)
├── metadata/          # Local metadata records
└── audit_log.jsonl    # Append-only structured JSON Lines audit trail
```

---

## 4. How to Run Automated Tests

The test suite requires no external pip packages and runs via Python's built-in `unittest` runner:

```powershell
python -m unittest discover -s backend/tests -v
```

All 22 unit, integration, and HTTP tests should pass with status `OK`.

---

## 5. How to Run the Local Demo Server

Start the local HTTP demonstration server:

```powershell
python backend/local_server.py --port 8000
```

Available REST API Endpoints:
- `GET  /api/health` — Status and storage backend identification.
- `GET  /api/files` — List stored files.
- `POST /api/upload` — Upload file (supports multipart form-data or raw binary).
- `POST /api/share` — Create expiring token (body: `{"file_id": "...", "expires_in_seconds": 3600, "max_downloads": 1}`).
- `GET  /api/tokens/inspect?token=...` — Non-destructive token inspection.
- `GET  /api/download?token=...` — Download file and consume access count.
- `POST /api/revoke` — Revoke token (body: `{"token": "..."}`).
- `GET  /api/audit?file_id=...` — Query filtered audit events.
