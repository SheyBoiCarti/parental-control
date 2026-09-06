import json
import pytest
from sqlalchemy import select
from config import AppConfig
from db import database
from db.models import AppSignature


@pytest.mark.parametrize("source, expected", [("*.Example.COM.", "*.example.com"), ("BÜCHER.example", "xn--bcher-kva.example")])
def test_catalog_domain_normalization(source, expected):
    from db.catalog import canonical_domain
    assert canonical_domain(source) == expected


@pytest.mark.parametrize("source", ["https://example.com", "foo.*.com", "-bad.example", "example..com", "example.com/path"])
def test_catalog_rejects_non_domain_patterns(source):
    from db.catalog import canonical_domain
    with pytest.raises(ValueError):
        canonical_domain(source)


@pytest.mark.asyncio
async def test_catalog_updates_builtin_and_preserves_custom(tmp_path):
    path = tmp_path / "catalog.json"
    def write(version, domain):
        path.write_text(json.dumps({"version": version, "apps": [
            {"name": "example", "display_name": "Example", "domains": [domain], "ip_ranges": []},
            {"name": "custom", "display_name": "Shipped", "domains": [domain], "ip_ranges": []},
        ]}))
    write(1, "*.Example.COM.")
    database.configure_database(AppConfig(data_dir=tmp_path, app_signatures_file=path))
    try:
        await database.init_db()
        from core.content_blocker import ContentBlocker
        matcher = ContentBlocker()
        await matcher.initialize()
        matcher.add_app_block("AA:BB:CC:DD:EE:01", "example")
        assert matcher.should_block("AA:BB:CC:DD:EE:01", "example.com")
        async with database.get_session() as session:
            custom = (await session.execute(select(AppSignature).where(AppSignature.app_name == "custom"))).scalar_one()
            custom.is_builtin = False
            custom.domains = ["personal.test"]
        write(2, "*.new.example")
        await database.init_app_signatures()
        await database.init_app_signatures()
        await matcher._load_app_signatures()
        assert matcher.should_block("AA:BB:CC:DD:EE:01", "new.example")
        assert matcher.should_block("AA:BB:CC:DD:EE:01", "example.com") is None
        async with database.get_session() as session:
            apps = {a.app_name: a for a in (await session.execute(select(AppSignature))).scalars()}
            assert set(apps) == {"example", "custom"}
            assert apps["example"].domains == ["*.new.example"]
            assert apps["custom"].domains == ["personal.test"]
    finally:
        await database.close_db()


@pytest.mark.asyncio
async def test_invalid_catalog_fails_with_actionable_error(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text('{"version": 1, "apps": [{"name": "bad", "domains": ["https://example.com"]}]}')
    database.configure_database(AppConfig(data_dir=tmp_path, app_signatures_file=path))
    try:
        with pytest.raises(RuntimeError, match="Invalid application catalog"):
            await database.init_db()
    finally:
        await database.close_db()
