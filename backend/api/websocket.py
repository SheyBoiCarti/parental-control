"""WebSocket manager for real-time updates."""

import asyncio
import json
import logging
from typing import Dict, List, Set, Any
from dataclasses import dataclass, asdict
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


@dataclass
class WSMessage:
    """WebSocket message structure."""
    type: str
    data: Any
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()

    def to_json(self) -> str:
        return json.dumps(asdict(self))


class ConnectionManager:
    """Manages WebSocket connections and broadcasts."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")

    async def send_personal(self, message: WSMessage, websocket: WebSocket):
        """Send message to a specific connection."""
        try:
            await websocket.send_text(message.to_json())
        except Exception as e:
            logger.error(f"Failed to send personal message: {e}")

    async def broadcast(self, message: WSMessage):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return

        async with self._lock:
            connections = self.active_connections.copy()

        disconnected = []

        for connection in connections:
            try:
                await connection.send_text(message.to_json())
            except Exception as e:
                logger.debug(f"Failed to send to connection: {e}")
                disconnected.append(connection)

        # Clean up disconnected clients
        for conn in disconnected:
            await self.disconnect(conn)

    async def broadcast_device_update(self, device_data: dict):
        """Broadcast device status update."""
        await self.broadcast(WSMessage(
            type="device_update",
            data=device_data
        ))

    async def broadcast_devices_list(self, devices: List[dict]):
        """Broadcast full device list."""
        await self.broadcast(WSMessage(
            type="devices_list",
            data=devices
        ))

    async def broadcast_rule_update(self, rule_data: dict):
        """Broadcast rule change."""
        await self.broadcast(WSMessage(
            type="rule_update",
            data=rule_data
        ))

    async def broadcast_access_log(self, log_data: dict):
        """Broadcast access log entry."""
        await self.broadcast(WSMessage(
            type="access_log",
            data=log_data
        ))

    async def broadcast_bandwidth_stats(self, stats: dict):
        """Broadcast bandwidth statistics."""
        await self.broadcast(WSMessage(
            type="bandwidth_stats",
            data=stats
        ))

    async def broadcast_system_status(self, status: dict):
        """Broadcast system status update."""
        await self.broadcast(WSMessage(
            type="system_status",
            data=status
        ))


# Global connection manager instance
ws_manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint handler."""
    await ws_manager.connect(websocket)

    try:
        while True:
            # Receive and handle messages from client
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
                await handle_client_message(websocket, message)
            except json.JSONDecodeError:
                await ws_manager.send_personal(
                    WSMessage(type="error", data="Invalid JSON"),
                    websocket
                )

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await ws_manager.disconnect(websocket)


async def handle_client_message(websocket: WebSocket, message: dict):
    """Handle incoming WebSocket messages from clients."""
    msg_type = message.get("type")

    if msg_type == "ping":
        await ws_manager.send_personal(
            WSMessage(type="pong", data=None),
            websocket
        )

    elif msg_type == "subscribe":
        # Client wants to subscribe to specific event types
        # For now, all clients receive all broadcasts
        await ws_manager.send_personal(
            WSMessage(type="subscribed", data=message.get("events", [])),
            websocket
        )

    else:
        logger.debug(f"Unknown message type: {msg_type}")
