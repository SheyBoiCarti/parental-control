from fastapi.testclient import TestClient
import pytest

from api.app import create_app
from config import AppConfig


@pytest.fixture
def dashboard(tmp_path):
    root = tmp_path / "static"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html><title>Dashboard</title>")
    (root / "assets" / "app.js").write_text("console.log('dashboard')")
    (tmp_path / "secret.txt").write_text("private")
    return root


@pytest.mark.parametrize("path", ["/", "/login", "/devices", "/devices/AA:BB:CC:DD:EE:FF", "/settings"])
def test_client_routes_serve_index(dashboard, path):
    client = TestClient(create_app(AppConfig(static_dir=dashboard)))
    response = client.get(path)
    assert response.status_code == 200
    assert "<title>Dashboard</title>" in response.text
    assert response.headers["cache-control"] == "no-cache"


def test_assets_and_reserved_paths(dashboard):
    client = TestClient(create_app(AppConfig(static_dir=dashboard)))
    assert client.get("/assets/app.js").text == "console.log('dashboard')"
    for path in ("/assets/missing.js", "/api/missing", "/unknown", "/assets/%2e%2e/%2e%2e/secret.txt"):
        assert client.get(path).status_code == 404
    assert client.post("/settings").status_code == 405
    assert client.get("/health").json() == {"status": "healthy"}


def test_missing_dashboard_is_explicit_and_api_only_is_supported(tmp_path):
    config = AppConfig(static_dir=tmp_path / "missing")
    assert TestClient(create_app(config)).get("/").status_code == 503
    api_only = config.model_copy(update={"api_only": True})
    client = TestClient(create_app(api_only))
    assert client.get("/").status_code == 404
    assert client.get("/api").status_code == 200
