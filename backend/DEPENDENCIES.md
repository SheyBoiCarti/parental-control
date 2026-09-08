# Dependency reproduction

Supported application targets are Python 3.11 and 3.12 on Linux. Portable tests also run on Windows; passing there does not validate Linux enforcement.

Install runtime and developer dependencies from the checked-in constraints:

```sh
python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt -c backend/constraints.txt
```

Regenerate the universal constraints from the two human-maintained inputs using uv 0.12.10:

```sh
uv pip compile backend/requirements.txt backend/requirements-dev.txt --universal --python-version 3.11 --output-file backend/constraints.txt
```

Universal resolution retains platform markers (including Linux uvloop). Validate the resulting constraints on both supported Python versions; a successful Windows installation is not evidence that Linux-only dependencies work. Changes to inputs require regenerating the output and running the complete matrix. Queue binding/system dependencies and privileged integration validation will be added with the inline enforcement stage.

The frontend uses `frontend/package-lock.json`; install with `npm ci` on Node 22.
