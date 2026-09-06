import importlib.util
from pathlib import Path


def installer_module():
    path = Path(__file__).resolve().parents[2] / "scripts" / "configure_install.py"
    spec = importlib.util.spec_from_file_location("configure_install", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_install_rerun_preserves_config_bytes(tmp_path):
    config = tmp_path / ".env"
    saved = b"AUTH_PASSWORD_HASH=$2b$12$unchanged\nNETWORK_INTERFACE=custom0\nAPI_PORT=8443\n"
    config.write_bytes(saved)
    assert not installer_module().configure(config, tmp_path / "unused", "eth0")
    assert config.read_bytes() == saved


def test_new_install_uses_template_and_selected_interface(tmp_path):
    config = tmp_path / ".env"
    template = tmp_path / "example"
    template.write_text("NETWORK_INTERFACE=eth0\nAPI_HOST=127.0.0.1\nAUTH_PASSWORD_HASH=\n")
    assert installer_module().configure(config, template, "enp2s0")
    assert "NETWORK_INTERFACE=enp2s0" in config.read_text()
    assert "API_HOST=127.0.0.1" in config.read_text()
