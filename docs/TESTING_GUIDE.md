# AegisShare: Comprehensive Testing & Demonstration Guide

This guide details exact commands, demonstration procedures, expected outputs, and validation criteria for **AegisShare: Secure File Sharing with Expiring Access and Audit Logs**.

---

## 1. Quick Start Commands (Windows)

All commands should be executed from the project root directory: `D:\AWS SECURE FILE SHARING`.

### A. Run Automated Unit & Integration Tests (38 Tests)
```powershell
python -m unittest discover -s backend/tests -v
```
**Expected Outcome:**
```text
Ran 38 tests in ~0.8s
OK
```

### B. Launch Local Demonstration Server
```powershell
python backend/local_server.py --port 8000
```
**Expected Outcome:**
The server starts on `http://127.0.0.1:8000`, serving the single-page application and REST API endpoints.

### C. Access the Web Application
Open any modern web browser (Edge, Chrome, Firefox) and navigate to:
```text
http://127.0.0.1:8000
```

---

## 2. Step-by-Step Demonstration Scenarios

### Scenario 1: Harmless Sample File Upload
1. Navigate to the **File Vault & Upload** section from the sidebar.
2. Drag and drop any test file (e.g., a text file or PDF) into the upload dropzone, or click **browse**.
3. **Observations:**
   - The upload progress bar animates to 100%.
   - A success banner appears: `File "<filename>" uploaded successfully (ID: file_<hex>).`
   - The file appears in the **Files in Vault** table with its original filename, calculated file size, MIME type, and upload timestamp in UTC.

---

### Scenario 2: Generate Ephemeral Share Link with Single-Use Cap
1. Click **Create Share Link** next to your uploaded file (or open the **Share Links** tab).
2. Configure parameters:
   - **Target File:** Select your file.
   - **Link Lifespan (TTL):** Select `1 Minute (Quick Demo Expiry)` or `5 Minutes`.
   - **Maximum Downloads:** Select `Single-Use (1 Download)`.
3. Click **Generate Secure Link**.
4. **Observations:**
   - A green success card appears displaying the generated URL (e.g., `http://127.0.0.1:8000/?token=<RAW_TOKEN>`).
   - A security notice explains: *Plaintext token is displayed once; only its SHA-256 hash is preserved by the server.*
   - Click **Copy** to copy the URL to your clipboard.

---

### Scenario 3: Recipient Download (Valid Access)
1. Open an Incognito window or click **Test in Portal →** on the dashboard.
2. The browser navigates to the **Download Portal** view with the token auto-populated in the access field.
3. The portal executes `GET /api/tokens/inspect?token=...`:
   - Status badge shows `VALID` (green).
   - Live countdown timer displays time remaining (e.g., `Expires in: 0h 4m 45s`).
   - Displays filename, size, and `1 downloads left`.
4. Click **Download File Now**.
5. **Observations:**
   - The browser downloads the original file payload.
   - The download counter decrements.
   - Status refreshes to show `0 downloads left` (Limit reached).

---

### Scenario 4: Download Rejection on Exhausted Access Count
1. Click **Download File Now** a second time using the same link.
2. **Observations:**
   - The server rejects the request with **HTTP 410 Gone**.
   - An alert appears in the portal: `Access Denied: Access token reached maximum download limit (1).`
   - The download button becomes disabled.

---

### Scenario 5: Access Rejection on Expired TTL
1. Create a share link with a 1-minute TTL (`60 seconds`).
2. Wait 61 seconds for the UTC timestamp to elapse.
3. Attempt to inspect or download the file via the recipient portal.
4. **Observations:**
   - The live countdown timer displays `LINK EXPIRED` in red text.
   - Calling `/api/download` returns **HTTP 410 Gone** (`ACCESS_EXPIRED`).
   - The download is blocked.

---

### Scenario 6: Explicit Link Revocation by Owner
1. Generate an active share link with a 1-hour expiration.
2. In the dashboard, navigate to the **Share Tokens Management** table.
3. Locate the link (identifiable by its `token_prefix`, e.g., `a1b2c3d4...`).
4. Click the red **Revoke Link** button and confirm the modal dialog.
5. **Observations:**
   - The link status changes from `VALID` to `REVOKED` (red badge).
   - Any subsequent recipient attempt to access this link is immediately blocked with **HTTP 403 Forbidden** (`TOKEN_REVOKED`).

---

### Scenario 7: Audit Log Verification
1. Navigate to the **Audit Trail** view from the sidebar.
2. Inspect the immutable chronological telemetry.
3. **Observations:**
   - Every previous action is recorded with UTC timestamp, action type, outcome, client IP, and scrubbed details.
   - You will see the complete event sequence:
     1. `FILE_UPLOAD` -> `SUCCESS`
     2. `SHARE_LINK_CREATED` -> `SUCCESS`
     3. `DOWNLOAD_SUCCESS` -> `SUCCESS`
     4. `ACCESS_REJECTED` -> `DENIED` (*Reason: Download limit reached*)
     5. `TOKEN_REVOKED` -> `SUCCESS`
     6. `ACCESS_REJECTED` -> `DENIED` (*Reason: Token was revoked by owner*)
   - Sensitive data verification: Plaintext tokens and secret signatures are completely absent from the log. Only non-identifying hash prefixes (`token_hash_prefix`) are present.
   - Test the event filters: Filter by `Outcome: DENIED` or `Event Type: ACCESS_REJECTED`.

---

## 3. Automated Test Breakdown & Coverage

The project includes 38 automated test cases in `backend/tests/`:

| Test Module | Test Count | Scope & Assertions |
| :--- | :---: | :--- |
| `test_token_service.py` | 8 | Cryptographic randomness, SHA-256 hash matching, non-plaintext storage, UTC TTL expiration, download counter increment, single/multi-use exhaustion, owner revocation. |
| `test_storage_service.py` | 7 | Local demo file persistence, byte retrieval, file deletion, path traversal (`../`) rejection, descriptor generation, S3 client configuration error handling, and strict no-silent-fallback enforcement. |
| `test_audit_service.py` | 3 | Event creation, multi-criteria filtering, append-only file persistence, and automatic redacting of sensitive keys (`token`, `password`, presigned query strings). |
| `test_integration_flow.py` | 3 | Complete end-to-end service cycle: upload -> share -> valid download -> exhaustion rejection -> expiration rejection -> revocation rejection. |
| `test_local_server.py` | 2 | Live HTTP server socket execution: `/api/health`, `/api/upload`, `/api/share`, `/api/tokens/inspect`, `/api/download`, `/api/audit`. |
| `test_dynamodb_service.py` | 5 | DynamoDB files store, token store TTL calculation, atomic conditional updates with expression values, revocation, and audit store querying via table mock. |
| `test_lambda_handlers.py` | 5 | API Gateway proxy event parser, CORS headers, unified dispatcher routing, health check handler, and 404 route handling. |
| `test_sam_template.py` | 5 | Structural and security validation of `infrastructure/template.yaml`: S3 SSE-AES256, PublicAccessBlock flags, TLS-only bucket policy, DynamoDB tables with TTL, IAM least-privilege scoping, and outputs. |

---

## 4. AWS Cloud Deployment Checklist (Post-Submission)

When AWS credentials and tools are configured in the environment:

- [ ] **1. Toolchain Verification:**
  - `aws --version` (Must return AWS CLI v2)
  - `sam --version` (Must return SAM CLI)
  - `aws sts get-caller-identity` (Must return active AWS account and IAM user/role)
- [ ] **2. SAM Build:**
  ```powershell
  sam build -t infrastructure/template.yaml
  ```
- [ ] **3. Guided Deployment:**
  ```powershell
  sam deploy --guided --stack-name aegisshare-dev --region us-east-1
  ```
- [ ] **4. Record CloudFormation Outputs:**
  - Copy `ApiEndpointUrl` (e.g., `https://xxxx.execute-api.us-east-1.amazonaws.com/dev`).
  - Copy `EncryptedFilesBucketName` (e.g., `aegisshare-secure-vault-dev-123456789012`).
- [ ] **5. Connect Frontend:**
  - Open `http://127.0.0.1:8000`.
  - Click the gear icon in the lower-left corner.
  - Paste the `ApiEndpointUrl` into the input field and click **Save & Reconnect**.
- [ ] **6. Validate Cloud Infrastructure:**
  - Verify file objects in S3 console under `uploads/`.
  - Verify items in DynamoDB tables (`aegisshare-files-dev`, `aegisshare-tokens-dev`, `aegisshare-audit-logs-dev`).
  - Verify execution logs in CloudWatch Log Group `/aws/lambda/AegisShareApiFunction`.
