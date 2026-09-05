from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select

from api.auth import hash_password
from config import load_config
from db import database


@pytest_asyncio.fixture
async def auth_service(tmp_path):
    from core.auth_service import AuthService

    config = load_config(None, {"data_dir": tmp_path, "auth_password_hash": hash_password("old-password")})
    database.configure_database(config)
    try:
        await database.init_db()
        yield AuthService(database.get_session)
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_password_rotation_invalidates_old_password_and_sessions(auth_service):
    from core.auth_service import AuthenticationError
    from db.models import BrowserSession

    login = await auth_service.login("admin", "old-password")
    identity = await auth_service.validate_session(login.token)
    assert identity.username == "admin"
    async with database.get_session() as session:
        saved = (await session.execute(select(BrowserSession))).scalar_one()
        assert saved.token_digest != login.token
        assert len(saved.token_digest) == 64
    await auth_service.change_password("old-password", "new-password")
    with pytest.raises(AuthenticationError):
        await auth_service.authenticate("admin", "old-password")
    with pytest.raises(AuthenticationError):
        await auth_service.validate_session(login.token)
    assert (await auth_service.authenticate("admin", "new-password")).username == "admin"


@pytest.mark.asyncio
async def test_logout_and_expiry_reject_sessions(auth_service):
    from core.auth_service import AuthenticationError

    login = await auth_service.login("admin", "old-password")
    await auth_service.logout(login.token)
    await auth_service.logout(login.token)
    with pytest.raises(AuthenticationError):
        await auth_service.validate_session(login.token)
    login = await auth_service.login("admin", "old-password")
    auth_service.clock = lambda: datetime.now(timezone.utc) + timedelta(hours=8, seconds=1)
    with pytest.raises(AuthenticationError):
        await auth_service.validate_session(login.token)


@pytest.mark.asyncio
@pytest.mark.parametrize("password", ["short", "é" * 37])
async def test_invalid_password_lengths_do_not_rotate_credentials(auth_service, password):
    with pytest.raises(ValueError):
        await auth_service.change_password("old-password", password)
    assert (await auth_service.authenticate("admin", "old-password")).username == "admin"


@pytest.mark.asyncio
async def test_wrong_current_password_cannot_rotate(auth_service):
    from core.auth_service import AuthenticationError

    with pytest.raises(AuthenticationError):
        await auth_service.change_password("wrong-password", "new-password")
    assert (await auth_service.authenticate("admin", "old-password")).username == "admin"


@pytest.mark.asyncio
async def test_cookie_login_csrf_rotation_and_reserved_settings(auth_service):
    import httpx
    from api.app import create_app

    config = load_config(None, {"allowed_origins": "https://control.test"})
    app = create_app(config, auth_service=auth_service)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://control.test") as client:
        assert (await client.get("/api/auth/session")).status_code == 401
        login = await client.post("/api/auth/login", json={"username": "admin", "password": "old-password"}, headers={"Origin": "https://control.test"})
        assert login.status_code == 200
        assert "httponly" in login.headers["set-cookie"].lower()
        assert "secure" in login.headers["set-cookie"].lower()
        assert "samesite=strict" in login.headers["set-cookie"].lower()
        csrf = login.json()["csrf_token"]
        assert set(login.json()) == {"username", "csrf_token", "expires_at"}
        assert (await client.get("/api/auth/session")).status_code == 200
        password = {"current_password": "old-password", "new_password": "new-password"}
        assert (await client.post("/api/settings/password", json=password)).status_code == 403
        headers = {"Origin": "https://control.test", "X-CSRF-Token": csrf}
        assert (await client.put("/api/settings/password_hash", params={"value": "attack"}, headers=headers)).status_code == 422
        assert (await client.get("/api/settings/password_hash")).status_code == 404
        assert (await client.post("/api/settings/password", json=password, headers=headers)).status_code == 200
        assert (await client.get("/api/auth/session")).status_code == 401
        assert (await client.get("/api/settings", auth=("admin", "old-password"))).status_code == 401
        assert (await client.get("/api/settings", auth=("admin", "new-password"))).status_code == 200


@pytest.mark.asyncio
async def test_bad_origin_and_failed_login_rate_limit(auth_service):
    import httpx
    from api.app import create_app

    app = create_app(load_config(None, {"allowed_origins": "https://control.test"}), auth_service=auth_service)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://control.test") as client:
        assert (await client.post("/api/auth/login", json={"username": "admin", "password": "old-password"}, headers={"Origin": "https://evil.test"})).status_code == 403
        assert (await client.get("/api/settings", auth=("admin", "old-password"), headers={"Origin": "https://evil.test"})).status_code == 403
        for _ in range(5):
            response = await client.post("/api/auth/login", json={"username": "admin", "password": "incorrect"})
            assert response.status_code == 401
        response = await client.post("/api/auth/login", json={"username": "admin", "password": "incorrect"})
        assert response.status_code == 429
        assert int(response.headers["Retry-After"]) > 0


def test_websocket_requires_session_origin_and_closes_on_logout(tmp_path):
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect
    from api.app import create_app
    from core.auth_service import AuthService

    config = load_config(None, {"data_dir": tmp_path, "auth_password_hash": hash_password("old-password"), "allowed_origins": "https://control.test"})
    database.configure_database(config)
    service = AuthService(database.get_session)
    with TestClient(create_app(config, auth_service=service), base_url="https://control.test") as client:
        try:
            client.portal.call(database.init_db)
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect("wss://control.test/ws", headers={"Origin": "https://control.test"}):
                    pass
            login = client.post("/api/auth/login", json={"username": "admin", "password": "old-password"})
            assert login.status_code == 200
            with pytest.raises(WebSocketDisconnect):
                with client.websocket_connect("wss://control.test/ws", headers={"Origin": "https://evil.test"}):
                    pass
            with client.websocket_connect("wss://control.test/ws", headers={"Origin": "https://control.test"}) as websocket:
                websocket.send_json({"type": "ping"})
                assert websocket.receive_json()["type"] == "pong"
                logout = client.post("/api/auth/logout", headers={"Origin": "https://control.test", "X-CSRF-Token": login.json()["csrf_token"]})
                assert logout.status_code == 204
                with pytest.raises(WebSocketDisconnect):
                    websocket.receive_json()
        finally:
            client.portal.call(database.close_db)


@pytest.mark.asyncio
async def test_slow_socket_cannot_delay_another_clients_messages():
    import asyncio
    from api.websocket import ConnectionManager, WSMessage
    from core.auth_service import SessionIdentity

    class Socket:
        def __init__(self, slow=False):
            self.slow = slow
            self.received = asyncio.Event()
            self.closed = asyncio.Event()
        async def accept(self):
            pass
        async def send_text(self, text):
            if self.slow:
                await asyncio.Event().wait()
            self.received.set()
        async def close(self, code):
            self.closed.set()

    manager = ConnectionManager(queue_capacity=2, send_timeout=0.05)
    identity = SessionIdentity("admin", "digest", "csrf", datetime.now(timezone.utc) + timedelta(hours=1))
    async def verify():
        return identity
    slow, fast = Socket(True), Socket()
    await manager.connect(slow, identity, verify)
    await manager.connect(fast, identity, verify)
    try:
        await manager.broadcast(WSMessage("device_update", {"mac": "AA:BB:CC:DD:EE:FF"}))
        await asyncio.wait_for(fast.received.wait(), 0.2)
        await asyncio.wait_for(slow.closed.wait(), 0.3)
        assert fast in manager.active_connections
        assert slow not in manager.active_connections
    finally:
        await manager.close_sessions(None)


@pytest.mark.asyncio
async def test_failed_commit_preserves_password_and_live_session(auth_service):
    from contextlib import asynccontextmanager
    from sqlalchemy.exc import SQLAlchemyError
    from core.auth_service import AuthService

    login = await auth_service.login("admin", "old-password")
    @asynccontextmanager
    async def failing_scope():
        async with database.get_session() as session:
            yield session
            raise SQLAlchemyError("injected commit failure")
    failing = AuthService(failing_scope)
    with pytest.raises(SQLAlchemyError):
        await failing.change_password("old-password", "new-password")
    assert (await auth_service.authenticate("admin", "old-password")).username == "admin"
    assert (await auth_service.validate_session(login.token)).username == "admin"


@pytest.mark.asyncio
async def test_rotated_password_survives_restart_with_original_environment_seed(auth_service, tmp_path):
    from core.auth_service import AuthService, AuthenticationError

    await auth_service.change_password("old-password", "new-password")
    await database.close_db()
    config = load_config(None, {"data_dir": tmp_path, "auth_password_hash": hash_password("old-password")})
    database.configure_database(config)
    await database.init_db()
    restarted = AuthService(database.get_session)
    await restarted.ensure_configured()
    assert (await restarted.authenticate("admin", "new-password")).username == "admin"
    with pytest.raises(AuthenticationError):
        await restarted.authenticate("admin", "old-password")
