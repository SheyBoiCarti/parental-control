"""Private persisted credentials and opaque browser sessions."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import secrets

import bcrypt
from sqlalchemy import delete, select, update

from db.models import AdminCredential, BrowserSession


class AuthenticationError(Exception):
    """The supplied credential or session cannot authenticate this request."""


class AuthUnavailable(Exception):
    """No usable persisted administrator credential is configured."""


@dataclass(frozen=True)
class AdminIdentity:
    username: str
    version: int


@dataclass(frozen=True)
class SessionIdentity:
    username: str
    session_id: str
    csrf_token: str = field(repr=False)
    expires_at: datetime


@dataclass(frozen=True)
class LoginSession:
    token: str = field(repr=False)
    identity: SessionIdentity


def validate_password(password: str) -> None:
    if len(password) < 8 or len(password.encode("utf-8")) > 72:
        raise ValueError("Password must be at least 8 characters and at most 72 UTF-8 bytes")


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def _verify(password: str, encoded: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), encoded.encode("ascii"))
    except (ValueError, UnicodeError):
        return False


class AuthService:
    def __init__(self, session_scope, *, clock=None):
        self.session_scope = session_scope
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._mutation_lock = asyncio.Lock()
        self._revocation_callbacks = []

    def on_revoke(self, callback) -> None:
        """Listen for a revoked session digest, or None for all sessions."""
        self._revocation_callbacks.append(callback)

    def _now(self) -> datetime:
        return self.clock().astimezone(timezone.utc).replace(tzinfo=None)

    @staticmethod
    def token_digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def ensure_configured(self) -> None:
        async with self.session_scope() as session:
            credential = await session.get(AdminCredential, 1)
            if credential is None:
                raise AuthUnavailable("No administrator password configured; run main.py --reset-password locally")
            try:
                await asyncio.to_thread(bcrypt.checkpw, b"validation", credential.password_hash.encode("ascii"))
            except (ValueError, UnicodeError) as error:
                raise AuthUnavailable("Stored administrator credential is invalid; run main.py --reset-password locally") from error

    async def authenticate(self, username: str, password: str) -> AdminIdentity:
        async with self.session_scope() as session:
            credential = await session.get(AdminCredential, 1)
            if credential is None:
                raise AuthUnavailable("Administrator credential is not configured")
            valid = await asyncio.to_thread(_verify, password, credential.password_hash)
            if not valid or not secrets.compare_digest(username.encode(), credential.username.encode()):
                raise AuthenticationError("Invalid credentials")
            return AdminIdentity(credential.username, credential.version)

    async def login(self, username: str, password: str) -> LoginSession:
        identity = await self.authenticate(username, password)
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = self._now()
        expires = now + timedelta(hours=8)
        digest = self.token_digest(token)
        async with self._mutation_lock:
            async with self.session_scope() as session:
                current = await session.get(AdminCredential, 1)
                if current is None or current.version != identity.version:
                    raise AuthenticationError("Credential changed; log in again")
                await session.execute(delete(BrowserSession).where(BrowserSession.expires_at <= now))
                session.add(BrowserSession(
                    token_digest=digest, credential_id=1, credential_version=identity.version,
                    csrf_token=csrf, created_at=now, expires_at=expires,
                ))
        return LoginSession(token, SessionIdentity(identity.username, digest, csrf, expires.replace(tzinfo=timezone.utc)))

    async def validate_session(self, token: str) -> SessionIdentity:
        if not token or len(token) > 128:
            raise AuthenticationError("Invalid session")
        digest = self.token_digest(token)
        async with self.session_scope() as session:
            result = (await session.execute(
                select(BrowserSession, AdminCredential)
                .join(AdminCredential, BrowserSession.credential_id == AdminCredential.id)
                .where(BrowserSession.token_digest == digest)
            )).first()
            if result is None:
                raise AuthenticationError("Invalid session")
            browser, credential = result
            if browser.expires_at <= self._now() or browser.credential_version != credential.version:
                raise AuthenticationError("Expired session")
            return SessionIdentity(credential.username, digest, browser.csrf_token,
                                   browser.expires_at.replace(tzinfo=timezone.utc))

    async def _notify_revoked(self, digest: str | None) -> None:
        for callback in self._revocation_callbacks:
            await callback(digest)

    async def logout(self, token: str) -> None:
        digest = self.token_digest(token)
        async with self._mutation_lock:
            async with self.session_scope() as session:
                await session.execute(delete(BrowserSession).where(BrowserSession.token_digest == digest))
        await self._notify_revoked(digest)

    async def change_password(self, current_password: str, new_password: str) -> None:
        validate_password(new_password)
        async with self._mutation_lock:
            async with self.session_scope() as session:
                credential = await session.get(AdminCredential, 1)
                if credential is None or not await asyncio.to_thread(_verify, current_password, credential.password_hash):
                    raise AuthenticationError("Current password is incorrect")
                encoded = await asyncio.to_thread(_hash, new_password)
                result = await session.execute(
                    update(AdminCredential).where(AdminCredential.id == 1, AdminCredential.version == credential.version)
                    .values(password_hash=encoded, version=credential.version + 1, updated_at=self._now())
                )
                if result.rowcount != 1:
                    raise AuthenticationError("Credential changed; try again")
                await session.execute(delete(BrowserSession))
        await self._notify_revoked(None)

    async def reset_password(self, username: str, password: str) -> None:
        """Local CLI recovery only; no unauthenticated HTTP route invokes this."""
        validate_password(password)
        encoded = await asyncio.to_thread(_hash, password)
        async with self._mutation_lock:
            async with self.session_scope() as session:
                credential = await session.get(AdminCredential, 1)
                if credential is None:
                    session.add(AdminCredential(id=1, username=username, password_hash=encoded,
                                                version=1, updated_at=self._now()))
                else:
                    credential.username = username
                    credential.password_hash = encoded
                    credential.version += 1
                    credential.updated_at = self._now()
                await session.execute(delete(BrowserSession))
        await self._notify_revoked(None)
