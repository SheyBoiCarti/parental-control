"""FastAPI application setup."""

import logging
from fastapi import FastAPI, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from config import AppConfig
from api.dashboard import install_dashboard
from api.routes import devices_router, rules_router, stats_router, settings_router
from api.websocket import websocket_endpoint, ws_manager
from api.routes.auth import router as auth_router, LoginLimiter
from core.auth_service import AuthenticationError, AuthUnavailable
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)


def create_app(config: AppConfig, *, auth_service=None) -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="Parental Control API",
        description="Network management and parental control system",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json"
    )
    app.state.config = config
    app.state.auth_service = auth_service
    app.state.login_limiter = LoginLimiter()
    app.state.ws_manager = ws_manager
    if auth_service is not None:
        auth_service.on_revoke(ws_manager.close_sessions)

    @app.exception_handler(AuthenticationError)
    async def authentication_error(request, error):
        return JSONResponse({"detail": "Invalid credentials or session"}, status_code=401)

    @app.exception_handler(AuthUnavailable)
    @app.exception_handler(SQLAlchemyError)
    async def unavailable(request, error):
        return JSONResponse({"detail": "Service unavailable"}, status_code=503)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        # FastAPI's default validation response includes submitted passwords.
        return JSONResponse({"detail": [
            {"loc": list(item["loc"]), "msg": item["msg"], "type": item["type"]}
            for item in error.errors()
        ]}, status_code=422)

    # CORS middleware for frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.allowed_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API routes
    app.include_router(devices_router, prefix="/api")
    app.include_router(rules_router, prefix="/api")
    app.include_router(stats_router, prefix="/api")
    app.include_router(settings_router, prefix="/api")
    app.include_router(auth_router, prefix="/api")

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

    install_dashboard(app, config)
    return app
