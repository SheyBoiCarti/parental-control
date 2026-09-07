"""Production dashboard delivery, separate from API and WebSocket routing."""

import re

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from starlette.staticfiles import StaticFiles

from config import AppConfig


def install_dashboard(app: FastAPI, config: AppConfig) -> None:
    if config.api_only:
        return
    root = config.static_dir.resolve()
    # StaticFiles confines decoded paths and symlinks to this directory.
    if (root / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=root / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def dashboard(path: str):
        if path not in {"", "login", "devices", "settings"} and not re.fullmatch(
            r"devices/(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", path
        ):
            raise HTTPException(404)
        index = (root / "index.html").resolve()
        if not index.is_relative_to(root) or not index.is_file():
            raise HTTPException(503, "Dashboard assets are missing; build and install the frontend or configure API_ONLY=true")
        return FileResponse(index, media_type="text/html", headers={"Cache-Control": "no-cache"})
