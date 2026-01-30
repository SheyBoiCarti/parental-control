"""Authentication module using HTTP Basic Auth."""

import secrets
import bcrypt
from typing import Optional
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from config import AUTH_USERNAME, AUTH_PASSWORD_HASH

security = HTTPBasic()


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def get_current_user(credentials: HTTPBasicCredentials = Security(security)) -> str:
    """
    Verify HTTP Basic credentials and return username.

    Raises HTTPException if authentication fails.
    """
    # If no password hash is configured, authentication is disabled
    if not AUTH_PASSWORD_HASH:
        return credentials.username

    # Verify username
    username_correct = secrets.compare_digest(
        credentials.username.encode('utf-8'),
        AUTH_USERNAME.encode('utf-8')
    )

    # Verify password
    password_correct = verify_password(credentials.password, AUTH_PASSWORD_HASH)

    if not (username_correct and password_correct):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    return credentials.username


def optional_auth(credentials: Optional[HTTPBasicCredentials] = Security(security, auto_error=False)) -> Optional[str]:
    """
    Optional authentication - returns username if valid, None if no auth provided.

    Use this for endpoints that should work with or without auth.
    """
    if not AUTH_PASSWORD_HASH:
        return "anonymous"

    if credentials is None:
        return None

    try:
        return get_current_user(credentials)
    except HTTPException:
        return None
