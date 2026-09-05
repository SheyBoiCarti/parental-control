"""Typed, side-effect-free application configuration."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from dotenv import dotenv_values
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent
DEFAULT_ENV_FILE = BACKEND_DIR / ".env"


class AppConfig(BaseModel):
    """Validated runtime settings constructed once at the process boundary."""

    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)

    data_dir: Path = PROJECT_DIR / "data"
    network_interface: str = "eth0"
    gateway_ip: str | None = None
    network_subnet: str | None = None
    arp_spoof_interval: float = Field(default=2.0, gt=0)
    device_scan_interval: float = Field(default=30.0, gt=0)
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8080, ge=1, le=65535)
    auth_username: str = "admin"
    auth_password_hash: str = Field(default="", repr=False)
    log_level: str = "INFO"
    allowed_origins: tuple[str, ...] = ()
    https_cert_file: Path | None = None
    https_key_file: Path | None = None
    allow_insecure_development: bool = False
    trusted_proxy_ips: tuple[str, ...] = ()
    inspection_budget_bytes: int = Field(default=65_536, ge=1)
    inspection_deadline_seconds: float = Field(default=5.0, gt=0)
    max_undecided_flows: int = Field(default=1_024, ge=1)
    event_queue_capacity: int = Field(default=10_000, ge=1)
    event_batch_size: int = Field(default=100, ge=1)
    event_flush_seconds: float = Field(default=1.0, gt=0)
    accounting_interval_seconds: float = Field(default=5.0, gt=0)
    telemetry_retention_days: int = Field(default=30, ge=1)
    retention_prune_interval_seconds: float = Field(default=3_600.0, gt=0)
    app_signatures_file: Path = PROJECT_DIR / "data" / "app_signatures.json"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "parental_control.db"

    @property
    def log_file(self) -> Path:
        return self.data_dir / "parental_control.log"

    @field_validator("network_interface")
    @classmethod
    def validate_interface(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", value):
            raise ValueError("network_interface must be a valid interface name")
        return value

    @field_validator("api_host")
    @classmethod
    def validate_api_host(cls, value: str) -> str:
        if value == "localhost":
            return value
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError("api_host must be an IP address or localhost") from error

    @field_validator("gateway_ip", mode="before")
    @classmethod
    def validate_gateway(cls, value: object) -> str | None:
        if value in (None, ""):
            return None
        return str(ipaddress.IPv4Address(str(value)))

    @field_validator("network_subnet", mode="before")
    @classmethod
    def validate_subnet(cls, value: object) -> str | None:
        if value in (None, ""):
            return None
        return str(ipaddress.IPv4Network(str(value), strict=True))

    @field_validator("allowed_origins", "trusted_proxy_ips", mode="before")
    @classmethod
    def split_lists(cls, value: object) -> object:
        if value in (None, ""):
            return ()
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return value

    @field_validator("allowed_origins")
    @classmethod
    def validate_origins(cls, origins: tuple[str, ...]) -> tuple[str, ...]:
        for origin in origins:
            try:
                parsed = urlsplit(origin)
                parsed.port
            except ValueError as error:
                raise ValueError("allowed_origins contains a malformed port") from error
            if (origin == "*" or parsed.scheme not in {"http", "https"} or not parsed.netloc
                    or parsed.username is not None or parsed.password is not None
                    or parsed.path or parsed.query or parsed.fragment):
                raise ValueError("allowed_origins must contain exact HTTPS origins")
        if len(set(origins)) != len(origins):
            raise ValueError("allowed_origins must not contain duplicates")
        return origins

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("unsupported log level")
        return normalized

    @model_validator(mode="after")
    def validate_tls_pair(self) -> "AppConfig":
        if bool(self.https_cert_file) != bool(self.https_key_file):
            raise ValueError("https_cert_file and https_key_file must be configured together")
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            if parsed.scheme == "http":
                if not self.allow_insecure_development or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                    raise ValueError("allowed_origins: HTTP requires the loopback-only insecure development option")
        try:
            host = ipaddress.ip_address(self.api_host) if self.api_host != "localhost" else None
        except ValueError:
            host = None
        is_loopback = self.api_host == "localhost" or (host is not None and host.is_loopback)
        if not is_loopback and not self.allow_insecure_development and not self.https_cert_file:
            raise ValueError("non-loopback API hosts require HTTPS configuration")
        return self


_ENV_TO_FIELD = {
    "DATA_DIR": "data_dir", "NETWORK_INTERFACE": "network_interface",
    "GATEWAY_IP": "gateway_ip", "NETWORK_SUBNET": "network_subnet",
    "ARP_SPOOF_INTERVAL": "arp_spoof_interval",
    "DEVICE_SCAN_INTERVAL": "device_scan_interval", "API_HOST": "api_host",
    "API_PORT": "api_port", "AUTH_USERNAME": "auth_username",
    "AUTH_PASSWORD_HASH": "auth_password_hash", "LOG_LEVEL": "log_level",
    "ALLOWED_ORIGINS": "allowed_origins", "HTTPS_CERT_FILE": "https_cert_file",
    "HTTPS_KEY_FILE": "https_key_file",
    "ALLOW_INSECURE_DEVELOPMENT": "allow_insecure_development",
    "TRUSTED_PROXY_IPS": "trusted_proxy_ips",
    "INSPECTION_BUDGET_BYTES": "inspection_budget_bytes",
    "INSPECTION_DEADLINE_SECONDS": "inspection_deadline_seconds",
    "MAX_UNDECIDED_FLOWS": "max_undecided_flows",
    "EVENT_QUEUE_CAPACITY": "event_queue_capacity",
    "EVENT_BATCH_SIZE": "event_batch_size", "EVENT_FLUSH_SECONDS": "event_flush_seconds",
    "ACCOUNTING_INTERVAL_SECONDS": "accounting_interval_seconds",
    "TELEMETRY_RETENTION_DAYS": "telemetry_retention_days",
    "RETENTION_PRUNE_INTERVAL_SECONDS": "retention_prune_interval_seconds",
    "APP_SIGNATURES_FILE": "app_signatures_file",
}


def _mapped(values: dict[str, Any]) -> dict[str, Any]:
    empty_uses_default = {"data_dir", "https_cert_file", "https_key_file", "app_signatures_file"}
    return {
        field: values[name]
        for name, field in _ENV_TO_FIELD.items()
        if name in values
        and values[name] is not None
        and not (values[name] == "" and field in empty_uses_default)
    }


def load_config(env_file: Path | None, cli_overrides: dict[str, object] | None = None) -> AppConfig:
    """Load config with CLI > process environment > env file > defaults."""
    file_values: dict[str, Any] = {}
    if env_file is not None and env_file.is_file():
        file_values = dict(dotenv_values(env_file, interpolate=False))
    values = _mapped(file_values)
    values.update(_mapped(dict(os.environ)))
    values.update({key: value for key, value in (cli_overrides or {}).items() if value is not None})
    # File and environment paths share the explicit configuration directory;
    # changing the service WorkingDirectory must not select another database.
    path_base = env_file.resolve().parent if env_file is not None else BACKEND_DIR
    for field in ("data_dir", "https_cert_file", "https_key_file", "app_signatures_file"):
        if values.get(field):
            value = Path(values[field])
            values[field] = value.resolve() if value.is_absolute() else (path_base / value).resolve()
    return AppConfig.model_validate(values)
