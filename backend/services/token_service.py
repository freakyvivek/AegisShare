"""Token Service for Secure File Sharing.

Provides cryptographically secure token generation, SHA-256 hashing,
UTC expiration enforcement, download count limits, and token revocation.
Plaintext tokens are NEVER persisted in metadata; only secure SHA-256
hashes are stored.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class TokenStatus(str, Enum):
    """Enumeration of possible token validation outcomes."""

    VALID = "VALID"
    NOT_FOUND = "NOT_FOUND"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    EXHAUSTED = "EXHAUSTED"  # Exceeded max download count


class TokenError(Exception):
    """Base exception for token operations."""


class TokenNotFoundError(TokenError):
    """Raised when token hash is not found."""


class TokenExpiredError(TokenError):
    """Raised when token has exceeded its UTC expiration time."""


class TokenRevokedError(TokenError):
    """Raised when token has been explicitly revoked."""


class TokenExhaustedError(TokenError):
    """Raised when token has reached its maximum download limit."""


@dataclass
class TokenRecord:
    """Represents stored metadata for a sharing token.
    
    The plaintext token is NOT stored here - only its SHA-256 hash.
    """

    token_hash: str
    file_id: str
    created_at_utc: str
    expires_at_utc: str
    max_downloads: Optional[int] = None
    download_count: int = 0
    is_revoked: bool = False
    revoked_at_utc: Optional[str] = None
    custom_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary for persistence."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TokenRecord:
        """Construct record from dictionary."""
        return cls(**data)


class TokenService:
    """Manages token generation, validation, revocation, and lifecycle."""

    def __init__(self, token_store: Optional[Dict[str, TokenRecord]] = None):
        """Initialize TokenService with an optional custom token store.
        
        Args:
            token_store: In-memory dictionary mapping token_hash -> TokenRecord.
        """
        self._store: Dict[str, TokenRecord] = token_store if token_store is not None else {}

    @staticmethod
    def generate_raw_token(byte_length: int = 32) -> str:
        """Generate a cryptographically secure, URL-safe random string.
        
        Uses Python secrets module (backed by os.urandom).
        """
        return secrets.token_urlsafe(byte_length)

    @staticmethod
    def hash_token(raw_token: str) -> str:
        """Calculate the SHA-256 hash of a raw token.
        
        Only hashes are stored in metadata stores, preventing token compromise
        in case of database leakage.
        """
        if not raw_token or not isinstance(raw_token, str):
            raise ValueError("Token must be a non-empty string.")
        return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

    def create_token(
        self,
        file_id: str,
        expires_in_seconds: int,
        max_downloads: Optional[int] = None,
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, TokenRecord]:
        """Create a new expiring share token for a file.
        
        Args:
            file_id: Unique identifier for the shared file.
            expires_in_seconds: Lifetime in seconds from now. Must be positive.
            max_downloads: Optional ceiling on allowed successful downloads.
            custom_metadata: Optional arbitrary non-sensitive metadata.

        Returns:
            Tuple of (raw_token, TokenRecord). The raw_token must be returned
            to the user immediately; it is NOT stored in the database.
        """
        if not file_id or not isinstance(file_id, str):
            raise ValueError("file_id must be a non-empty string.")
        if expires_in_seconds <= 0:
            raise ValueError("expires_in_seconds must be greater than zero.")
        if max_downloads is not None and max_downloads <= 0:
            raise ValueError("max_downloads must be greater than zero if specified.")

        now_utc = datetime.now(timezone.utc)
        expires_at_utc = now_utc.timestamp() + expires_in_seconds
        expires_at_dt = datetime.fromtimestamp(expires_at_utc, tz=timezone.utc)

        raw_token = self.generate_raw_token()
        token_hash = self.hash_token(raw_token)

        record = TokenRecord(
            token_hash=token_hash,
            file_id=file_id,
            created_at_utc=now_utc.isoformat(),
            expires_at_utc=expires_at_dt.isoformat(),
            max_downloads=max_downloads,
            download_count=0,
            is_revoked=False,
            revoked_at_utc=None,
            custom_metadata=custom_metadata or {},
        )

        self._store[token_hash] = record
        return raw_token, record

    def inspect_token_status(
        self,
        raw_token: str,
        current_time_utc: Optional[datetime] = None,
    ) -> tuple[TokenStatus, Optional[TokenRecord]]:
        """Non-destructive status check for a given raw token.
        
        Does not increment the download count.
        """
        if not raw_token:
            return TokenStatus.NOT_FOUND, None

        token_hash = self.hash_token(raw_token)
        record = self._store.get(token_hash)
        if not record:
            return TokenStatus.NOT_FOUND, None

        if record.is_revoked:
            return TokenStatus.REVOKED, record

        now_dt = current_time_utc or datetime.now(timezone.utc)
        expires_at_dt = datetime.fromisoformat(record.expires_at_utc)

        if now_dt >= expires_at_dt:
            return TokenStatus.EXPIRED, record

        if record.max_downloads is not None and record.download_count >= record.max_downloads:
            return TokenStatus.EXHAUSTED, record

        return TokenStatus.VALID, record

    def validate_token(
        self,
        raw_token: str,
        current_time_utc: Optional[datetime] = None,
    ) -> TokenRecord:
        """Validate that a token is currently eligible for file access.
        
        Raises appropriate TokenError subclass if invalid. Does not consume a download.
        """
        status, record = self.inspect_token_status(raw_token, current_time_utc)

        if status == TokenStatus.NOT_FOUND or record is None:
            raise TokenNotFoundError("Access token is invalid or does not exist.")
        if status == TokenStatus.REVOKED:
            raise TokenRevokedError(f"Access token for file '{record.file_id}' was revoked.")
        if status == TokenStatus.EXPIRED:
            raise TokenExpiredError(
                f"Access token for file '{record.file_id}' expired at {record.expires_at_utc}."
            )
        if status == TokenStatus.EXHAUSTED:
            raise TokenExhaustedError(
                f"Access token reached maximum download limit ({record.max_downloads})."
            )

        return record

    def consume_download(
        self,
        raw_token: str,
        current_time_utc: Optional[datetime] = None,
    ) -> TokenRecord:
        """Validate token and atomically increment its download count.
        
        Returns updated TokenRecord on success.
        Raises TokenError subclasses if access is disallowed.
        """
        record = self.validate_token(raw_token, current_time_utc)
        record.download_count += 1
        return record

    def revoke_token(self, raw_token: str) -> TokenRecord:
        """Revoke a token by its raw representation.
        
        Raises TokenNotFoundError if token does not exist.
        """
        token_hash = self.hash_token(raw_token)
        return self.revoke_token_by_hash(token_hash)

    def revoke_token_by_hash(self, token_hash: str) -> TokenRecord:
        """Revoke a token directly by its stored SHA-256 hash."""
        record = self._store.get(token_hash)
        if not record:
            raise TokenNotFoundError(f"Token hash {token_hash} not found.")

        record.is_revoked = True
        record.revoked_at_utc = datetime.now(timezone.utc).isoformat()
        return record

    def get_token_by_hash(self, token_hash: str) -> Optional[TokenRecord]:
        """Retrieve stored metadata by token hash (safe, no raw token returned)."""
        return self._store.get(token_hash)

    def list_tokens_for_file(self, file_id: str) -> list[TokenRecord]:
        """List all token records created for a specific file."""
        return [rec for rec in self._store.values() if rec.file_id == file_id]

    def list_all_tokens(self) -> list[TokenRecord]:
        """List all token records currently stored (safe metadata, no raw tokens)."""
        return list(self._store.values())
