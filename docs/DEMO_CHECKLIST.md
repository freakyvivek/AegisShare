# AegisShare: College Project Demonstration & Evidence Checklist

This document provides a systematic guide for collecting demonstration evidence, capturing submission screenshots, performing live examiner walkthroughs, and clarifying the boundary between verified local functionality and pending live AWS integration.

---

## 1. Required Screenshots for College Project Submission

Capture the following screenshots from the running application (`http://127.0.0.1:8000`) for your submission report or slide deck:

| # | Screenshot Title | Location in App | What to Highlight / Caption |
| :-: | :--- | :--- | :--- |
| **1** | **System Security Overview** | Navigation: *Overview* | Overview telemetry cards showing stored files, active links, audit count, and `local_demo_storage` backend indicator. |
| **2** | **File Vault & Upload Interface** | Navigation: *File Vault & Upload* | Drag-and-drop dropzone, animated upload progress, and the Vault table showing original filenames, MIME types, and UTC timestamps. |
| **3** | **Link Generation & Security Notice** | Navigation: *Share Links* | Configuration of TTL (e.g., 5 min) and maximum downloads (e.g., 1 download), the generated link, and the zero-knowledge security notice banner. |
| **4** | **Recipient Download Portal (Valid Access)** | Navigation: *Download Portal* | Live countdown timer (e.g., `Expires in: 0h 4m 52s`), green `VALID` badge, file metadata, remaining downloads count, and the **Download File Now** button. |
| **5** | **Access Rejection: Expired Link** | Navigation: *Download Portal* | Red `LINK EXPIRED` timer and the `Access Denied: ACCESS_EXPIRED` alert box after TTL elapses. |
| **6** | **Access Rejection: Download Cap Reached** | Navigation: *Download Portal* | Alert banner displaying `Access Denied: Access token reached maximum download limit (1)` on an attempted second download. |
| **7** | **Active Tokens Management & Revocation** | Navigation: *Share Links* | Share Tokens table showing SHA-256 token prefixes, download counts, and the **Revoke Link** action button transitioning a token to `REVOKED`. |
| **8** | **Immutable Audit Trail Explorer** | Navigation: *Audit Trail* | Filtered table showing the full audit log: `FILE_UPLOAD`, `SHARE_LINK_CREATED`, `DOWNLOAD_SUCCESS`, `ACCESS_REJECTED`, `TOKEN_REVOKED` with client IP and scrubbed details. |
| **9** | **Automated Test Suite Output** | PowerShell Terminal | Terminal window displaying the execution of `python -m unittest discover -s backend/tests -v` showing all 38 tests passing with status `OK`. |

---

## 2. Live Examiner Demonstration Walkthrough

Follow this scripted 5-minute demonstration during your project evaluation:

### Step 1: Prove System Architecture (30 seconds)
1. Show the terminal running `python backend/local_server.py --port 8000`.
2. Explain that the system is built with a dual-target architecture: a standalone zero-dependency Python server with Vanilla HTML5/CSS/JS frontend for local evaluation, and an AWS SAM Infrastructure-as-Code template ready for cloud deployment.
3. Show the test runner output: `38 tests passed in 0.8 seconds`.

### Step 2: Upload and Vault Inspection (1 minute)
1. Open `http://127.0.0.1:8000`.
2. Navigate to **File Vault & Upload**.
3. Upload a sample document (e.g., `capstone_project_draft.pdf`).
4. Point out the auto-assigned unique file identifier (`file_<hex>`) and strict path sanitization that prevents directory traversal.

### Step 3: Zero-Knowledge Ephemeral Link Creation (1 minute)
1. Select the uploaded file and configure a **1-minute TTL** and **Single-Use (1 download)** limit.
2. Click **Generate Secure Link**.
3. Point out the core security mechanism:
   - The plaintext token is generated using `secrets.token_urlsafe(32)`.
   - The server hashes it immediately using SHA-256.
   - The plaintext token is shown only once to the sender and is never saved in the database or server logs.

### Step 4: Recipient Portal & Download Verification (1 minute)
1. Click **Test in Portal →** to open the recipient view.
2. Show the real-time JavaScript countdown timer syncing against the server's UTC expiration timestamp.
3. Click **Download File Now** and verify that the file opens cleanly.
4. Refresh or click download again to trigger the download limit exhaustion:
   - Demonstrate the server returning **HTTP 410 Gone**.
   - Show the message: `Access token reached maximum download limit (1)`.

### Step 5: On-Demand Link Revocation (1 minute)
1. Generate another link with 1-hour expiration.
2. Go to **Share Tokens Management** and click **Revoke Link**.
3. Try accessing the link in the portal: show that access is immediately terminated with **HTTP 403 Forbidden**.

### Step 6: Audit Trail & Compliance Inspection (30 seconds)
1. Open the **Audit Trail** table.
2. Demonstrate how every action (upload, link creation, download success, download rejection, revocation) is permanently logged.
3. Show that sensitive credentials, raw tokens, and pre-signed query strings are scrubbed (`[REDACTED_SENSITIVE_DATA]` / `[QUERY_STRIPPED_FOR_AUDIT]`).

---

## 3. Boundary of Tested Local Code vs. Pending Live AWS Integration

For academic transparency, explicitly state the boundary of verified functionality to your examiners:

### Verified Local Evidence:
- [x] Full web application dashboard, dropzone, and recipient portal functioning at `http://127.0.0.1:8000`.
- [x] Cryptographic token generation, SHA-256 one-way hashing, and non-plaintext metadata storage.
- [x] Strict UTC TTL expiration and download ceiling enforcement.
- [x] On-demand token revocation.
- [x] Append-only audit logging with sensitive credential redaction.
- [x] 38 automated test cases passing in 0.81s (including mocks of DynamoDB tables, S3 adapters, Lambda proxy events, and SAM template validation).

### Evidence Still Pending for Live AWS Deployment:
- [ ] Live AWS CLI and SAM CLI installations in the host environment.
- [ ] Active AWS account credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
- [ ] CloudFormation stack provisioning confirmation (`sam deploy`).
- [ ] Live AWS S3 console object listings and DynamoDB item view screenshots.
- [ ] Live CloudWatch Log streams from actual Lambda invocations.
