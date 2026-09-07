#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${GITHUB_WORKSPACE:-$(pwd)}/artifacts/linux-kernel"
mkdir -p "$artifact_dir"

finish() {
  tc -s qdisc show dev pcdummy0 >"$artifact_dir/qdisc-final.txt" 2>&1 || true
  tc -s class show dev pcdummy0 >"$artifact_dir/class-final.txt" 2>&1 || true
  iptables-save >"$artifact_dir/iptables-final.txt" 2>&1 || true
  ip link del pcdummy0 2>/dev/null || true
}
trap finish EXIT

if [[ "$(id -u)" != "0" ]]; then
  echo "Linux integration harness must run as root" >&2
  exit 2
fi

if [[ "$(readlink /proc/self/ns/net)" == "$(readlink /proc/1/ns/net)" ]]; then
  echo "Refusing kernel tests outside a disposable network namespace" >&2
  exit 2
fi

export PC_DISPOSABLE_NETNS=1
ip link set lo up
ip link add pcdummy0 type dummy
ip link set pcdummy0 up

python_bin="${PYTHON:-}"
if [[ -z "$python_bin" ]]; then
  if command -v python >/dev/null 2>&1; then
    python_bin="python"
  elif [[ -x "backend/venv/bin/python" ]]; then
    python_bin="backend/venv/bin/python"
  else
    python_bin="python3"
  fi
fi

"$python_bin" -m pytest backend/tests/linux -q \
  --junitxml="$artifact_dir/junit.xml"
