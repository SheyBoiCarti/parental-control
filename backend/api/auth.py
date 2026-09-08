"""Shared REST authentication and browser request protection."""

import secrets
from typing import Optional

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from core.auth_service import AuthenticationError, _hash, _verify

COOKIE_NAME = "pc_session"
security = HTTPBasic(auto_error=False)


def hash_password(password: str) -> str:
    return _hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return _verify(password, hashed)


def check_origin(request, *, required: bool = False) -> None:
    origin = request.headers.get("origin")
    if (required and not origin) or (origin is not None and origin not in request.app.state.config.allowed_origins):
        raise HTTPException(403, "Origin not allowed")


def get_auth_service(request: Request):
    service = request.app.state.auth_service
    if service is None:
        raise HTTPException(503, "Authentication service unavailable")
    return service


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Security(security),
) -> str:
    check_origin(request)
    token = request.cookies.get(COOKIE_NAME)
    if not token and credentials is None:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Basic"})
    service = get_auth_service(request)
    if token:
        identity = await service.validate_session(token)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            check_origin(request, required=True)
            csrf = request.headers.get("x-csrf-token", "")
            if not secrets.compare_digest(csrf.encode(), identity.csrf_token.encode()):
                raise HTTPException(403, "Invalid CSRF token")
        return identity.username
    address = request.client.host if request.client else "unknown"
    limiter = request.app.state.login_limiter
    reservation = limiter.reserve(address)
    try:
        identity = await service.authenticate(credentials.username, credentials.password)
    except AuthenticationError:
        # Keep the reservation: failed Basic attempts share the same limit as
        # browser logins and cannot become a bcrypt-work bypass.
        raise
    except BaseException:
        limiter.release(address, reservation)
        raise
    limiter.release(address, reservation)
    return identity.username
