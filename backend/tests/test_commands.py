import asyncio
import subprocess
import sys

import pytest


def test_nonzero_command_raises_and_probe_retains_outcome():
    from utils.commands import CommandError, run_command
    argv = [sys.executable, "-c", "import sys; print('output'); sys.stderr.write('failure'); sys.exit(7)"]
    with pytest.raises(CommandError) as error:
        run_command(argv)
    assert error.value.result.returncode == 7
    result = run_command(argv, check=False)
    assert result.returncode == 7
    assert result.stdout.strip() == "output"
    assert result.stderr == "failure"


def test_missing_executable_is_a_typed_failure(monkeypatch):
    from utils.commands import CommandError, run_command
    def missing(*args, **kwargs):
        raise FileNotFoundError()
    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(CommandError) as error:
        run_command(["not-installed"])
    assert error.value.result.returncode == 127
    assert run_command(["not-installed"], check=False).returncode == 127


def test_command_timeout_is_bounded_and_does_not_expose_arguments():
    from utils.commands import CommandError, run_command
    with pytest.raises(CommandError) as error:
        run_command([sys.executable, "-c", "import time; time.sleep(5)", "secret-value"], timeout=0.05)
    assert error.value.result.returncode == 124
    assert "secret-value" not in str(error.value)


@pytest.mark.asyncio
async def test_async_runner_does_not_block_the_event_loop():
    from utils.commands import CommandRunner
    task = asyncio.create_task(CommandRunner().run([sys.executable, "-c", "import time; time.sleep(0.4)"]))
    progress = asyncio.Event()
    asyncio.get_running_loop().call_later(0.03, progress.set)
    await asyncio.wait_for(progress.wait(), 0.2)
    assert not task.done()
    assert (await task).returncode == 0
