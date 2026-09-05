import os
from pathlib import Path
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from config import load_config


BACKEND = Path(__file__).resolve().parents[1]


def _clean_env(**values: str) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "API_HOST", "API_PORT", "NETWORK_INTERFACE", "GATEWAY_IP",
            "NETWORK_SUBNET", "AUTH_USERNAME", "AUTH_PASSWORD_HASH",
            "ALLOWED_ORIGINS", "HTTPS_CERT_FILE", "HTTPS_KEY_FILE",
            "ALLOW_INSECURE_DEVELOPMENT", "DATA_DIR",
        }
    }
    env.update(values)
    return env


def test_backend_sources_compile():
    for path in BACKEND.rglob("*.py"):
        if not {"venv", ".venv", "__pycache__"}.intersection(path.parts):
            compile(path.read_text(encoding="utf-8"), str(path), "exec")


def test_help_works_from_another_cwd_without_operational_imports(tmp_path: Path):
    completed = subprocess.run(
        [sys.executable, str(BACKEND / "main.py"), "--help"],
        cwd=tmp_path,
        env=_clean_env(DATA_DIR=str(tmp_path / "data")),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--interface" in completed.stdout
    assert not (tmp_path / "data").exists()


def test_imports_from_another_cwd_do_not_create_database_or_load_linux_networking(tmp_path: Path):
    script = (
        "import sys; "
        "import config; import db.database; import api.auth; import api.app; "
        "assert 'core.device_manager' not in sys.modules; "
        "assert 'utils.network_utils' not in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=_clean_env(PYTHONPATH=str(BACKEND), DATA_DIR=str(tmp_path / "data")),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert not (tmp_path / "data").exists()


def test_config_precedence_and_explicit_env_path_are_cwd_independent(
    env_file: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("API_PORT", "8082")
    monkeypatch.setenv("NETWORK_INTERFACE", "env0")

    config = load_config(
        env_file,
        {"api_port": 8083, "network_interface": "cli0"},
    )

    assert config.api_port == 8083
    assert config.network_interface == "cli0"
    assert config.gateway_ip == "192.0.2.1"
    assert config.network_subnet == "192.0.2.0/24"
    assert config.auth_password_hash == "$2b$12$file.hash.with.dollars"
    assert config.allowed_origins == ("https://control.example.test",)


def test_empty_optional_path_placeholders_keep_safe_defaults(tmp_path: Path):
    file = tmp_path / "empty.env"
    file.write_text(
        "DATA_DIR=\nHTTPS_CERT_FILE=\nHTTPS_KEY_FILE=\nAPP_SIGNATURES_FILE=\n",
        encoding="utf-8",
    )
    config = load_config(file, {})
    assert config.data_dir.is_absolute()
    assert config.https_cert_file is None
    assert config.https_key_file is None
    assert config.app_signatures_file.is_absolute()


def test_loopback_http_origin_requires_explicit_development_mode():
    with pytest.raises(ValidationError):
        load_config(None, {"allowed_origins": "http://127.0.0.1:5173"})
    config = load_config(
        None,
        {
            "allowed_origins": "http://127.0.0.1:5173",
            "allow_insecure_development": True,
        },
    )
    assert config.allowed_origins == ("http://127.0.0.1:5173",)


def test_non_loopback_listener_requires_tls_or_explicit_development_mode():
    with pytest.raises(ValidationError):
        load_config(None, {"api_host": "0.0.0.0"})
    config = load_config(
        None,
        {"api_host": "0.0.0.0", "allow_insecure_development": True},
    )
    assert config.api_host == "0.0.0.0"


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"api_port": 0}, "api_port"),
        ({"network_interface": "bad interface"}, "network_interface"),
        ({"gateway_ip": "999.1.1.1"}, "gateway_ip"),
        ({"network_subnet": "192.0.2.3/24"}, "network_subnet"),
        ({"allowed_origins": "*"}, "allowed_origins"),
        ({"allowed_origins": "http://control.example.test"}, "allowed_origins"),
    ],
)
def test_config_rejects_unsafe_values(overrides: dict[str, object], field: str):
    with pytest.raises(ValidationError) as error:
        load_config(None, overrides)
    assert field in str(error.value)


def test_app_factory_rejects_missing_auth_and_reports_unavailable_store():
    from api.app import create_app

    config = load_config(None, {"auth_password_hash": ""})
    with TestClient(create_app(config)) as client:
        assert client.get("/api/devices").status_code == 401

    configured = load_config(
        None,
        {
            "auth_username": "admin",
            "auth_password_hash": "$2b$12$c6Q5Kx8hQjLkQVpguJw9v.27kg5uqQOJrvn8z3M5ZPHD64PvBwY9u",
        },
    )
    with TestClient(create_app(configured)) as client:
        response = client.get("/api/devices", auth=("admin", "incorrect"))
    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}


def test_valid_basic_auth_reaches_protected_route():
    from api.app import create_app
    from api.auth import hash_password

    config = load_config(
        None,
        {"auth_username": "admin", "auth_password_hash": hash_password("secret-pass")},
    )
    with TestClient(create_app(config)) as client:
        response = client.get("/api/devices", auth=("admin", "secret-pass"))
    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}


def test_normal_startup_without_credentials_is_rejected_before_privileged_work(tmp_path: Path):
    completed = subprocess.run(
        [sys.executable, str(BACKEND / "main.py")],
        cwd=tmp_path,
        env=_clean_env(DATA_DIR=str(tmp_path / "data")),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 2
    assert "AUTH_PASSWORD_HASH" in completed.stderr
    assert not (tmp_path / "data").exists()


def test_component_construction_receives_network_overrides():
    from main import build_app_state

    calls: dict[str, tuple[object, ...]] = {}

    def fake(name: str):
        class Component:
            def __init__(self, *args: object, **kwargs: object):
                calls[name] = args + tuple(sorted(kwargs.items()))
        return Component

    config = load_config(
        None,
        {
            "network_interface": "lan7",
            "gateway_ip": "192.0.2.1",
            "network_subnet": "192.0.2.0/24",
        },
    )
    state = build_app_state(
        config,
        {
            "DeviceManager": fake("device"),
            "ARPSpoofer": fake("arp"),
            "PacketAnalyzer": fake("packet"),
            "TrafficController": fake("traffic"),
            "ContentBlocker": fake("content"),
            "DeviceBlocker": fake("blocker"),
        },
        gateway_mac="AA:BB:CC:DD:EE:01",
        local_mac="AA:BB:CC:DD:EE:02",
    )
    assert state.device_manager is not None
    assert calls["device"] == (
        ("gateway_ip", "192.0.2.1"),
        ("interface", "lan7"),
        ("network_subnet", "192.0.2.0/24"),
    )
    assert calls["packet"] == ("lan7",)
    assert calls["traffic"] == ("lan7",)
    assert calls["blocker"] == ("lan7",)


def test_cli_host_and_port_reach_runtime_config(monkeypatch: pytest.MonkeyPatch):
    import main

    captured = None

    async def fake_run(self):
        nonlocal captured
        captured = self.config

    monkeypatch.setattr(main.ParentalControlApp, "run", fake_run)
    password_hash = "$2b$12$c6Q5Kx8hQjLkQVpguJw9v.27kg5uqQOJrvn8z3M5ZPHD64PvBwY9u"
    monkeypatch.setenv("AUTH_PASSWORD_HASH", password_hash)
    assert main.main(["--host", "127.0.0.2", "--port", "9182"]) == 0
    assert captured.api_host == "127.0.0.2"
    assert captured.api_port == 9182


def test_server_config_uses_explicit_trusted_proxy_policy():
    from main import build_uvicorn_config

    config = load_config(
        None,
        {
            "auth_password_hash": "configured",
            "trusted_proxy_ips": "127.0.0.1,192.0.2.8",
        },
    )
    server_config = build_uvicorn_config(config, object())
    assert server_config.proxy_headers is True
    assert server_config.forwarded_allow_ips == "127.0.0.1,192.0.2.8"


def test_config_error_does_not_expose_bootstrap_secret():
    secret = "s3cr3t"
    with pytest.raises(ValidationError) as error:
        load_config(None, {"auth_password_hash": secret, "https_cert_file": "cert.pem"})
    assert secret not in str(error.value)
    assert "input_value" not in str(error.value)


def test_config_file_paths_do_not_change_with_working_directory(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    env = config_dir / "service.env"
    env.write_text("DATA_DIR=state\nHTTPS_CERT_FILE=cert.pem\nHTTPS_KEY_FILE=key.pem\n")
    monkeypatch.chdir(tmp_path)
    config = load_config(env)
    assert config.data_dir == config_dir / "state"
    assert config.https_cert_file == config_dir / "cert.pem"
    assert config.https_key_file == config_dir / "key.pem"


def test_local_password_reset_works_without_network_privileges(tmp_path, monkeypatch):
    import getpass
    import sqlite3
    import main
    from api.auth import verify_password

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "local-new-password")
    assert main.main(["--env-file", str(tmp_path / "missing.env"), "--reset-password"]) == 0
    with sqlite3.connect(tmp_path / "parental_control.db") as connection:
        encoded = connection.execute("SELECT password_hash FROM admin_credentials WHERE id=1").fetchone()[0]
    assert verify_password("local-new-password", encoded)


def test_existing_private_credential_does_not_require_environment_hash(tmp_path):
    import main
    (tmp_path / "parental_control.db").touch()
    # The preflight allows a persisted DB; AuthService verifies its actual
    # credential before any network startup, including empty/corrupt databases.
    main._require_startup_credentials(load_config(None, {"data_dir": tmp_path, "auth_password_hash": ""}))
