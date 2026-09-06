"""Create initial service configuration without replacing existing settings."""

import argparse
import os
from pathlib import Path
import re


def configure(path: Path, template: Path, interface: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
        raise ValueError("Invalid network interface")
    if path.is_symlink():
        raise ValueError("Service configuration must be a regular file")
    if path.exists():
        if not path.is_file():
            raise ValueError("Service configuration must be a regular file")
        path.chmod(0o600)
        return False
    content = template.read_text(encoding="utf-8")
    content = re.sub(r"^NETWORK_INTERFACE=.*$", f"NETWORK_INTERFACE={interface}", content, flags=re.MULTILINE)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(content)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("template", type=Path)
    parser.add_argument("interface")
    args = parser.parse_args()
    created = configure(args.config, args.template, args.interface)
    print("Created configuration" if created else "Preserved existing configuration")
