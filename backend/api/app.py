"""FastAPI application setup."""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from api.routes import devices_router, rules_router, stats_router, settings_router
from api.websocket import websocket_endpoint

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="Parental Control API",
        description="Network management and parental control system",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json"
    )

    # CORS middleware for frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, restrict to frontend origin
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API routes
    app.include_router(devices_router, prefix="/api")
    app.include_router(rules_router, prefix="/api")
    app.include_router(stats_router, prefix="/api")
    app.include_router(settings_router, prefix="/api")

    # WebSocket endpoint
    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket_endpoint(websocket)

    # Health check
    @app.get("/health")
    async def health_check():
        return {"status": "healthy"}

    # API info
    @app.get("/api")
    async def api_info():
        return {
            "name": "Parental Control API",
            "version": "1.0.0",
            "endpoints": {
                "devices": "/api/devices",
                "rules": "/api/devices/{mac}/rules",
                "stats": "/api/stats",
                "settings": "/api/settings",
                "websocket": "/ws",
                "docs": "/api/docs"
            }
        }

    return app
