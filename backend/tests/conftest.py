import os
from pathlib import Path
import asyncio
import subprocess
import sys
import platform

import pytest

# Python 3.11 queries `ver` on Windows on its first platform lookup. Resolve
# interpreter metadata before installing the guard against application commands.
platform.uname()


@pytest.fixture(autouse=True)
def prevent_host_commands(monkeypatch: pytest.MonkeyPatch):
    """Portable tests may launch Python children, never host/network processes."""
    real_run = subprocess.run
    real_popen = subprocess.Popen

    def is_python(executable: object) -> bool:
        try:
            return Path(str(executable)).resolve() == Path(sys.executable).resolve()
        except OSError:
            return False

    def guarded_run(command, *args, **kwargs):
        executable = str(command[0] if isinstance(command, (list, tuple)) else command)
        if not is_python(executable):
            raise AssertionError(f"host command escaped test adapter: {executable}")
        return real_run(command, *args, **kwargs)

    def blocked_process(command, *args, **kwargs):
        executable = command[0] if isinstance(command, (list, tuple)) else command
        if not is_python(executable):
            raise AssertionError(f"host process escaped test adapter: {executable}")
        return real_popen(command, *args, **kwargs)

    async def blocked_async_process(program, *args, **kwargs):
        raise AssertionError(f"async host process escaped test adapter: {program}")

    monkeypatch.setattr(subprocess, "run", guarded_run)
    monkeypatch.setattr(subprocess, "Popen", blocked_process)
    for module_name in (
        "core.device_manager", "core.arp_spoofer", "core.packet_analyzer",
        "utils.network_utils",
    ):
        module = sys.modules.get(module_name)
        if module is not None:
            for name in ("srp", "sendp", "sniff"):
                if hasattr(module, name):
                    monkeypatch.setattr(
                        module, name,
                        lambda *a, _name=name, **k: (_ for _ in ()).throw(
                            AssertionError(f"raw network operation escaped test adapter: {_name}")
                        ),
                    )
    monkeypatch.setattr(asyncio, "create_subprocess_exec", blocked_async_process)
    monkeypatch.setattr(asyncio, "create_subprocess_shell", blocked_async_process)
    yield


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    path = tmp_path / "service.env"
    path.write_text(
        "AUTH_USERNAME=file-admin\n"
        "AUTH_PASSWORD_HASH=$2b$12$file.hash.with.dollars\n"
        "API_HOST=127.0.0.1\n"
        "API_PORT=8081\n"
        "NETWORK_INTERFACE=file0\n"
        "GATEWAY_IP=192.0.2.1\n"
        "NETWORK_SUBNET=192.0.2.0/24\n"
        "ALLOWED_ORIGINS=https://control.example.test\n",
        encoding="utf-8",
    )
    return path
