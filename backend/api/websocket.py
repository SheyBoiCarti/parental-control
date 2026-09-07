"""Authenticated, bounded WebSocket telemetry delivery."""

import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.exc import SQLAlchemyError

from api.auth import COOKIE_NAME, check_origin
from core.auth_service import AuthenticationError, AuthUnavailable


@dataclass
class WSMessage:
    type: str
    data: Any
    timestamp: str | None = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class Client:
    socket: WebSocket
    session_id: str
    queue: asyncio.Queue
    verify: Any
    sender: asyncio.Task | None = None


class ConnectionManager:
    def __init__(self, *, queue_capacity=100, send_timeout=5.0):
        self.clients = {}
        self.queue_capacity = queue_capacity
        self.send_timeout = send_timeout

    @property
    def active_connections(self):
        return list(self.clients)

    async def connect(self, websocket, identity, verify):
        await websocket.accept()
        client = Client(websocket, identity.session_id, asyncio.Queue(self.queue_capacity), verify)
        self.clients[websocket] = client
        client.sender = asyncio.create_task(self._send(client))

    async def _send(self, client):
        try:
            while True:
                message = await client.queue.get()
                await client.verify()
                await asyncio.wait_for(client.socket.send_text(message.to_json()), self.send_timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.disconnect(client.socket, code=1008)

    async def disconnect(self, websocket, *, code=1000):
        client = self.clients.pop(websocket, None)
        if client is None:
            return
        if client.sender is not None and client.sender is not asyncio.current_task():
            client.sender.cancel()
            await asyncio.gather(client.sender, return_exceptions=True)
        try:
            await asyncio.wait_for(websocket.close(code=code), 1.0)
        except (Exception, asyncio.CancelledError):
            pass

    async def close_sessions(self, digest):
        await asyncio.gather(*(
            self.disconnect(client.socket, code=1008)
            for client in list(self.clients.values())
            if digest is None or client.session_id == digest
        ))

    async def send_personal(self, message, websocket):
        client = self.clients.get(websocket)
        if client is None:
            return
        try:
            client.queue.put_nowait(message)
        except asyncio.QueueFull:
            await self.disconnect(websocket, code=1013)

    async def broadcast(self, message):
        await asyncio.gather(*(self.send_personal(message, socket) for socket in list(self.clients)))

    async def broadcast_device_update(self, data):
        await self.broadcast(WSMessage("device_update", data))

    async def broadcast_devices_list(self, data):
        await self.broadcast(WSMessage("devices_list", data))

    async def broadcast_rule_update(self, data):
        await self.broadcast(WSMessage("rule_update", data))

    async def broadcast_access_log(self, data):
        await self.broadcast(WSMessage("access_log", data))

    async def broadcast_bandwidth_stats(self, data):
        await self.broadcast(WSMessage("bandwidth_stats", data))

    async def broadcast_system_status(self, data):
        await self.broadcast(WSMessage("system_status", data))


ws_manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket):
    manager = websocket.app.state.ws_manager
    service = websocket.app.state.auth_service
    try:
        check_origin(websocket, required=True)
        if service is None:
            raise AuthUnavailable()
        token = websocket.cookies.get(COOKIE_NAME, "")

        async def verify():
            return await service.validate_session(token)

        # Hold the same lock as logout/rotation through registration so a
        # revocation cannot slip between validation and tracking the socket.
        async with service._mutation_lock:
            identity = await verify()
            await manager.connect(websocket, identity, verify)
        while websocket in manager.clients:
            await verify()
            try:
                data = await asyncio.wait_for(websocket.receive_text(), 1.0)
            except asyncio.TimeoutError:
                continue
            if len(data) > 4096:
                break
            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await manager.send_personal(WSMessage("error", "Invalid JSON"), websocket)
                continue
            if not isinstance(message, dict):
                continue
            if message.get("type") == "ping":
                await manager.send_personal(WSMessage("pong", None), websocket)
            elif message.get("type") == "subscribe":
                await manager.send_personal(WSMessage("subscribed", message.get("events", [])), websocket)
    except (AuthenticationError, HTTPException):
        if websocket not in manager.clients:
            await websocket.close(code=1008)
    except (AuthUnavailable, SQLAlchemyError):
        if websocket not in manager.clients:
            await websocket.close(code=1013)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await manager.disconnect(websocket, code=1008)
