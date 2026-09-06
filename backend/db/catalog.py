"""Validated canonical application catalog import."""

import ipaddress
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from db.models import AppSignature, Setting


from utils.domains import canonical_domain


class CatalogApp(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,99}$")
    display_name: str = Field(min_length=1, max_length=100)
    domains: list[str]
    ip_ranges: list[str] = []

    @field_validator("domains")
    @classmethod
    def normalize_domains(cls, values):
        return sorted({canonical_domain(value) for value in values})

    @field_validator("ip_ranges")
    @classmethod
    def normalize_ranges(cls, values):
        return sorted({str(ipaddress.ip_network(value, strict=True)) for value in values})


class Catalog(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(ge=1, strict=True)
    apps: list[CatalogApp]

    @field_validator("apps")
    @classmethod
    def unique_names(cls, apps):
        if len({app.name for app in apps}) != len(apps):
            raise ValueError("Duplicate application identifiers")
        return apps


async def import_catalog(session, path: Path):
    try:
        catalog = Catalog.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Invalid application catalog at {path}; check JSON schema, version and domain patterns") from error
    existing = {app.app_name: app for app in (await session.execute(select(AppSignature))).scalars()}
    for item in catalog.apps:
        app = existing.get(item.name)
        if app is None:
            app = AppSignature(app_name=item.name, is_builtin=True)
            session.add(app)
        elif not app.is_builtin:
            continue
        app.display_name = item.display_name
        app.domains = item.domains
        app.ip_ranges = item.ip_ranges
    # Keep removed identifiers visible but remove stale built-in match data.
    names = {item.name for item in catalog.apps}
    for name, app in existing.items():
        if app.is_builtin and name not in names:
            app.domains = []
            app.ip_ranges = []
    version = await session.get(Setting, "app_catalog_version")
    if version is None:
        session.add(Setting(key="app_catalog_version", value=str(catalog.version)))
    else:
        version.value = str(catalog.version)
