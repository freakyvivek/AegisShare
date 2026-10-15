"""Audit Service for Secure File Sharing.

Records immutable structured audit trails for all security events:
file uploads, share link creation, successful downloads, rejected accesses,
expirations, and revocations.

SECURITY ASSURANCES:
- Plaintext share tokens are NEVER recorded.
- Pre-signed URLs and query strings are NEVER recorded.
- Credentials and secrets are scrubbed before persistence.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditEventType(str, Enum):
    """Categorized security event types."""

    FILE_UPLOAD = "FILE_UPLOAD"
    SHARE_LINK_CREATED = "SHARE_LINK_CREATED"
    DOWNLOAD_SUCCESS = "DOWNLOAD_SUCCESS"
    ACCESS_REJECTED = "ACCESS_REJECTED"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    FILE_DELETED = "FILE_DELETED"


class AuditOutcome(str, Enum):
    """Security event outcome."""

    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    ERROR = "ERROR"


@dataclass
class AuditRecord:
    """Represents a single immutable audit log entry."""

    event_id: str
    timestamp_utc: str
    event_type: str
    file_id: str
    outcome: str
    actor_ip: str = "unknown"
    user_agent: str = "unknown"
    token_hash_prefix: Optional[str] = None
    reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditRecord:
        return cls(**data)


class AuditService:
    """Manages recording, sanitizing, and querying security audit logs."""

    FORBIDDEN_DETAIL_KEYS = {
        "token",
        "raw_token",
        "secret",
        "credentials",
        "password",
        "x-amz-signature",
        "signature",
    }

    def __init__(self, log_file_path: Optional[Path | str] = None):
        """Initialize AuditService.
        
        Args:
            log_file_path: Optional path to an append-only JSON Lines file.
        """
        self._in_memory_logs: List[AuditRecord] = []
        self._log_file: Optional[Path] = Path(log_file_path).resolve() if log_file_path else None

        if self._log_file:
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            if self._log_file.exists():
                self._load_existing_logs()

    def _load_existing_logs(self) -> None:
        """Load records from existing audit file into memory."""
        try:
            with open(self._log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._in_memory_logs.append(AuditRecord.from_dict(json.loads(line)))
        except Exception:
            # If log cannot be read or is corrupted, start fresh in memory
            pass

    def _sanitize_details(self, details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Strip or mask any sensitive keys before logging."""
        if not details:
            return {}

        sanitized: Dict[str, Any] = {}
        for key, value in details.items():
            lower_k = key.lower()
            if any(forbidden in lower_k for forbidden in self.FORBIDDEN_DETAIL_KEYS):
                sanitized[key] = "[REDACTED_SENSITIVE_DATA]"
            elif isinstance(value, str) and ("http://" in value or "https://" in value) and "?" in value:
                # Strip query strings from URLs to remove any auth params/signatures
                base_url = value.split("?")[0]
                sanitized[key] = f"{base_url}?[QUERY_STRIPPED_FOR_AUDIT]"
            else:
                sanitized[key] = value

        return sanitized

    @staticmethod
    def _safe_token_prefix(token_hash: Optional[str]) -> Optional[str]:
        """Extract only a non-identifying prefix of the token hash."""
        if not token_hash:
            return None
        # Return only first 12 characters of the SHA-256 hash for correlation
        return token_hash[:12] + "..."

    def record_event(
        self,
        event_type: AuditEventType | str,
        file_id: str,
        outcome: AuditOutcome | str,
        actor_ip: str = "unknown",
        user_agent: str = "unknown",
        token_hash: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Append an audit record.
        
        Args:
            event_type: AuditEventType enum or string.
            file_id: Target file identifier.
            outcome: AuditOutcome enum or string.
            actor_ip: Client IP address (optional).
            user_agent: Client User-Agent string (optional).
            token_hash: SHA-256 hash of the access token (NEVER plaintext token!).
            reason: Plaintext explanation (e.g. 'Token expired').
            details: Arbitrary metadata dictionary (will be scrubbed for sensitive items).
        """
        event_id = f"evt_{secrets.token_hex(8)}"
        now_utc = datetime.now(timezone.utc).isoformat()

        record = AuditRecord(
            event_id=event_id,
            timestamp_utc=now_utc,
            event_type=str(event_type.value if isinstance(event_type, AuditEventType) else event_type),
            file_id=str(file_id),
            outcome=str(outcome.value if isinstance(outcome, AuditOutcome) else outcome),
            actor_ip=actor_ip or "unknown",
            user_agent=user_agent or "unknown",
            token_hash_prefix=self._safe_token_prefix(token_hash),
            reason=reason,
            details=self._sanitize_details(details),
        )

        self._in_memory_logs.append(record)

        # Write append-only to log file if configured
        if self._log_file:
            try:
                with open(self._log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record.to_dict()) + "\n")
            except Exception:
                # Do not crash the application if filesystem write encounters issues
                pass

        return record

    def query_events(
        self,
        file_id: Optional[str] = None,
        event_type: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditRecord]:
        """Query audit log entries matching filters, newest first."""
        results = self._in_memory_logs[:]

        if file_id:
            results = [r for r in results if r.file_id == file_id]
        if event_type:
            results = [r for r in results if r.event_type == event_type]
        if outcome:
            results = [r for r in results if r.outcome == outcome]

        # Return newest first
        results.reverse()
        return results[:limit]

    def get_recent_events(self, limit: int = 50) -> List[AuditRecord]:
        """Return the most recent audit events."""
        return self.query_events(limit=limit)

    def count_events(self, file_id: Optional[str] = None) -> int:
        """Count recorded events."""
        if file_id:
            return sum(1 for r in self._in_memory_logs if r.file_id == file_id)
        return len(self._in_memory_logs)
