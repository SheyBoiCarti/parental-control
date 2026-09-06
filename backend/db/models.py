"""SQLAlchemy database models."""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON, Float, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship
from utils.rules import rule_identity_default

Base = declarative_base()


class Device(Base):
    """Network device model."""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String(17), unique=True, nullable=False, index=True)
    ip_address = Column(String(15), nullable=True)
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)
    friendly_name = Column(String(255), nullable=True)
    is_monitored = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_online = Column(Boolean, default=False)

    # Relationships
    rules = relationship("DeviceRule", back_populates="device", cascade="all, delete-orphan")
    bandwidth_logs = relationship("BandwidthLog", back_populates="device", cascade="all, delete-orphan")
    access_logs = relationship("AccessLog", back_populates="device", cascade="all, delete-orphan")
    enforcement_states = relationship(
        "DeviceEnforcement", back_populates="device", cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "friendly_name": self.friendly_name or self.hostname or self.mac_address,
            "is_monitored": self.is_monitored,
            "is_blocked": self.is_blocked,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "is_online": self.is_online,
        }


class DeviceRule(Base):
    """Rules applied to devices (bandwidth limits, app blocks, etc.)."""
    __tablename__ = "device_rules"
    __table_args__ = (UniqueConstraint("device_id", "rule_type", "canonical_value", name="ux_device_rule_identity"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    rule_type = Column(String(50), nullable=False)  # bandwidth, block_app, block_domain
    rule_value = Column(JSON, nullable=False)  # {limit_kbps: 1000} or {app: "tiktok"} or {domain: "example.com"}
    canonical_value = Column(String(255), nullable=False, default=rule_identity_default)
    validation_error = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    device = relationship("Device", back_populates="rules")

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "rule_type": self.rule_type,
            "rule_value": self.rule_value,
            "validation_error": self.validation_error,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DeviceEnforcement(Base):
    """Last verified runtime result for one device enforcement component."""
    __tablename__ = "device_enforcement"
    __table_args__ = (
        UniqueConstraint("device_id", "component", name="ux_device_enforcement_component"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    component = Column(String(32), nullable=False)
    state = Column(String(16), nullable=False, default="pending")
    last_error = Column(String(255), nullable=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    device = relationship("Device", back_populates="enforcement_states")


class BandwidthLog(Base):
    """Bandwidth usage logs."""
    __tablename__ = "bandwidth_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)

    # Relationships
    device = relationship("Device", back_populates="bandwidth_logs")


class AccessLog(Base):
    """Domain/app access logs."""
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), nullable=True, unique=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    domain = Column(String(255), nullable=False)
    action = Column(String(20), nullable=False)  # allowed, blocked
    app_name = Column(String(100), nullable=True)  # Detected app if any

    # Relationships
    device = relationship("Device", back_populates="access_logs")


class AppSignature(Base):
    """App identification signatures."""
    __tablename__ = "app_signatures"

    id = Column(Integer, primary_key=True, autoincrement=True)
    app_name = Column(String(100), unique=True, nullable=False)
    display_name = Column(String(100), nullable=False)
    domains = Column(JSON, nullable=False)  # List of domain patterns
    ip_ranges = Column(JSON, nullable=True)  # Optional IP ranges
    is_builtin = Column(Boolean, default=False)


class Setting(Base):
    """System settings key-value store."""
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AdminCredential(Base):
    """Private singleton administrator credential; never a general setting."""
    __tablename__ = "admin_credentials"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class BrowserSession(Base):
    __tablename__ = "browser_sessions"

    token_digest = Column(String(64), primary_key=True)
    credential_id = Column(Integer, ForeignKey("admin_credentials.id", ondelete="CASCADE"), nullable=False)
    credential_version = Column(Integer, nullable=False)
    csrf_token = Column(String(128), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
