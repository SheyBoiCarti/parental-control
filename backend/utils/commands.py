"""One bounded command contract for privileged adapters and portable tests."""

import asyncio
from pathlib import Path
import subprocess
from typing import NamedTuple


class CommandResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


class CommandError(RuntimeError):
    def __init__(self, program: str, result: CommandResult):
        self.result = result
        reason = {124: "timed out", 127: "is unavailable"}.get(result.returncode, f"failed with exit code {result.returncode}")
        # Arguments and stderr can contain sensitive values. Keep them out of
        # exception strings sent to API clients or routine application logs.
        super().__init__(f"{Path(program).name} {reason}")


def run_command(argv: list[str], check: bool = True, timeout: float = 10.0) -> CommandResult:
    if not argv or timeout <= 0:
        raise ValueError("A command and positive timeout are required")
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
        result = CommandResult(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired:
        result = CommandResult(124, "", "Command timed out")
    except OSError:
        result = CommandResult(127, "", "Executable unavailable")
    if check and result.returncode != 0:
        raise CommandError(argv[0], result)
    return result


class CommandRunner:
    async def run(self, argv: list[str], *, check: bool = True, timeout: float = 10.0) -> CommandResult:
        return await asyncio.to_thread(run_command, argv, check, timeout)
