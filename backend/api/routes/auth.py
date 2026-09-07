"""Browser session endpoints; credentials never enter URL or browser storage."""

from collections import OrderedDict, deque
import math
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from api.auth import COOKIE_NAME, check_origin, get_auth_service, get_current_user
from core.auth_service import AuthenticationError

router = APIRouter(prefix="/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(max_length=1024, repr=False)


class LoginLimiter:
    """Bounded reservations include in-flight checks to avoid parallel bypass."""
    def __init__(self, clock=time.monotonic, capacity=4096):
        self.clock = clock
        self.capacity = capacity
        self.attempts = OrderedDict()

    def reserve(self, address):
        now = self.clock()
        for key in list(self.attempts):
            records = self.attempts[key]
            while records and records[0] <= now - 60:
                records.popleft()
            if not records:
                del self.attempts[key]
        records = self.attempts.get(address)
        if records is None:
            if len(self.attempts) >= self.capacity:
                raise HTTPException(429, "Login capacity exceeded", headers={"Retry-After": "60"})
            records = self.attempts[address] = deque()
        if len(records) >= 5:
            raise HTTPException(429, "Too many failed logins", headers={"Retry-After": str(max(1, math.ceil(60 - now + records[0])))})
        records.append(now)
        return now

    def release(self, address, reservation):
        records = self.attempts.get(address)
        if records is not None and reservation in records:
            records.remove(reservation)
            if not records:
                del self.attempts[address]


def session_json(identity):
    return {"username": identity.username, "csrf_token": identity.csrf_token,
            "expires_at": identity.expires_at.isoformat()}


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response):
    check_origin(request)
    service = get_auth_service(request)
    # Uvicorn only accepts forwarded addresses from explicitly trusted proxies.
    address = request.client.host if request.client else "unknown"
    limiter = request.app.state.login_limiter
    reservation = limiter.reserve(address)
    try:
        issued = await service.login(body.username, body.password)
    except AuthenticationError:
        raise
    except BaseException:
        limiter.release(address, reservation)
        raise
    limiter.release(address, reservation)
    response.set_cookie(COOKIE_NAME, issued.token, max_age=8 * 3600, httponly=True,
                        secure=request.url.scheme == "https", samesite="strict", path="/")
    response.headers["Cache-Control"] = "no-store"
    return session_json(issued.identity)


@router.get("/session")
async def session_info(request: Request, response: Response):
    check_origin(request)
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(401, "Authentication required")
    identity = await get_auth_service(request).validate_session(token)
    response.headers["Cache-Control"] = "no-store"
    return session_json(identity)


@router.post("/logout", status_code=204)
async def logout(request: Request, response: Response, user: str = Depends(get_current_user)):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        await get_auth_service(request).logout(token)
    response.delete_cookie(COOKIE_NAME, path="/", secure=request.url.scheme == "https", httponly=True, samesite="strict")
