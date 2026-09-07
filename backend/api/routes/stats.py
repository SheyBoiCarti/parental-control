"""Statistics API routes."""

from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func

from api.auth import get_current_user
from db.database import get_session
from db.models import Device, BandwidthLog, AccessLog

router = APIRouter(prefix="/stats", tags=["statistics"])


class BandwidthStatsResponse(BaseModel):
    """Bandwidth statistics response."""
    mac_address: str
    total_bytes_sent: int
    total_bytes_received: int
    hourly_stats: List[dict]


class AccessLogEntry(BaseModel):
    """Access log entry."""
    timestamp: str
    domain: str
    action: str
    app_name: Optional[str]
    rule_id: Optional[int]
    protocol: Optional[str]
    reason: Optional[str]


class AccessStatsResponse(BaseModel):
    """Access statistics response."""
    mac_address: str
    total_requests: int
    blocked_requests: int
    logs: List[AccessLogEntry]


class SystemStatsResponse(BaseModel):
    """System statistics response."""
    total_devices: int
    online_devices: int
    monitored_devices: int
    blocked_devices: int
    dns_queries_captured: int
    tls_connections_captured: int
    event_pipeline: Optional[dict] = None
    bandwidth_pipeline: Optional[dict] = None
    reconciliation_pipeline: Optional[dict] = None


# App state reference
_app_state = None


def set_app_state(state):
    global _app_state
    _app_state = state


def get_app_state():
    if _app_state is None:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return _app_state


@router.get("/system", response_model=SystemStatsResponse)
async def get_system_stats(user: str = Depends(get_current_user)):
    """Get overall system statistics."""
    state = get_app_state()

    async with get_session() as session:
        # Device counts
        total = await session.execute(select(func.count(Device.id)))
        total_devices = total.scalar_one()

        online = await session.execute(
            select(func.count(Device.id)).where(Device.is_online == True)
        )
        online_devices = online.scalar_one()

        monitored = await session.execute(
            select(func.count(Device.id)).where(Device.is_monitored == True)
        )
        monitored_devices = monitored.scalar_one()

        blocked = await session.execute(
            select(func.count(Device.id)).where(Device.is_blocked == True)
        )
        blocked_devices = blocked.scalar_one()

    # Packet analyzer stats
    analyzer_stats = state.packet_analyzer.get_stats()

    return SystemStatsResponse(
        total_devices=total_devices,
        online_devices=online_devices,
        monitored_devices=monitored_devices,
        blocked_devices=blocked_devices,
        dns_queries_captured=analyzer_stats.get("dns_queries", 0),
        tls_connections_captured=analyzer_stats.get("tls_connections", 0),
        event_pipeline=state.event_worker.stats() if getattr(state, "event_worker", None) else None,
        bandwidth_pipeline=(
            state.bandwidth_monitor.stats()
            if getattr(state, "bandwidth_monitor", None)
            else None
        ),
        reconciliation_pipeline=(
            state.reconciliation_worker.stats()
            if getattr(state, "reconciliation_worker", None)
            else None
        ),
    )


@router.get("/devices/{mac}/bandwidth", response_model=BandwidthStatsResponse)
async def get_device_bandwidth_stats(
    mac: str,
    hours: int = Query(default=24, ge=1, le=168),
    user: str = Depends(get_current_user)
):
    """Get bandwidth statistics for a device."""
    from utils.mac_utils import normalize_mac
    normalized_mac = normalize_mac(mac)

    async with get_session() as session:
        # Get device
        result = await session.execute(
            select(Device).where(Device.mac_address == normalized_mac)
        )
        device = result.scalar_one_or_none()

        if not device:
            raise HTTPException(status_code=404, detail=f"Device not found: {mac}")

        # Get bandwidth logs for time period
        since = datetime.utcnow() - timedelta(hours=hours)

        result = await session.execute(
            select(BandwidthLog)
            .where(
                BandwidthLog.device_id == device.id,
                BandwidthLog.timestamp >= since
            )
            .order_by(BandwidthLog.timestamp)
        )
        logs = result.scalars().all()

        # Aggregate totals
        total_sent = sum(log.bytes_sent for log in logs)
        total_received = sum(log.bytes_received for log in logs)

        # Group by hour
        hourly_stats = []
        current_hour = None
        hour_data = {"bytes_sent": 0, "bytes_received": 0}

        for log in logs:
            log_hour = log.timestamp.replace(minute=0, second=0, microsecond=0)

            if current_hour is None:
                current_hour = log_hour

            if log_hour != current_hour:
                hourly_stats.append({
                    "hour": current_hour.isoformat(),
                    **hour_data
                })
                current_hour = log_hour
                hour_data = {"bytes_sent": 0, "bytes_received": 0}

            hour_data["bytes_sent"] += log.bytes_sent
            hour_data["bytes_received"] += log.bytes_received

        # Add last hour
        if current_hour:
            hourly_stats.append({
                "hour": current_hour.isoformat(),
                **hour_data
            })

    return BandwidthStatsResponse(
        mac_address=normalized_mac,
        total_bytes_sent=total_sent,
        total_bytes_received=total_received,
        hourly_stats=hourly_stats
    )


@router.get("/devices/{mac}/access", response_model=AccessStatsResponse)
async def get_device_access_stats(
    mac: str,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=100, ge=1, le=1000),
    user: str = Depends(get_current_user)
):
    """Get access logs for a device."""
    from utils.mac_utils import normalize_mac
    normalized_mac = normalize_mac(mac)

    async with get_session() as session:
        # Get device
        result = await session.execute(
            select(Device).where(Device.mac_address == normalized_mac)
        )
        device = result.scalar_one_or_none()

        if not device:
            raise HTTPException(status_code=404, detail=f"Device not found: {mac}")

        since = datetime.utcnow() - timedelta(hours=hours)

        # Get total counts
        total_result = await session.execute(
            select(func.count(AccessLog.id))
            .where(
                AccessLog.device_id == device.id,
                AccessLog.timestamp >= since
            )
        )
        total_requests = total_result.scalar_one()

        blocked_result = await session.execute(
            select(func.count(AccessLog.id))
            .where(
                AccessLog.device_id == device.id,
                AccessLog.timestamp >= since,
                AccessLog.action == "blocked"
            )
        )
        blocked_requests = blocked_result.scalar_one()

        # Get recent logs
        result = await session.execute(
            select(AccessLog)
            .where(
                AccessLog.device_id == device.id,
                AccessLog.timestamp >= since
            )
            .order_by(AccessLog.timestamp.desc())
            .limit(limit)
        )
        logs = result.scalars().all()

    return AccessStatsResponse(
        mac_address=normalized_mac,
        total_requests=total_requests,
        blocked_requests=blocked_requests,
        logs=[
            AccessLogEntry(
                timestamp=log.timestamp.isoformat(),
                domain=log.domain,
                action=log.action,
                app_name=log.app_name,
                rule_id=log.rule_id,
                protocol=log.protocol,
                reason=log.reason,
            )
            for log in logs
        ]
    )


@router.get("/top-domains")
async def get_top_domains(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    user: str = Depends(get_current_user)
):
    """Get top accessed domains across all devices."""
    since = datetime.utcnow() - timedelta(hours=hours)

    async with get_session() as session:
        result = await session.execute(
            select(
                AccessLog.domain,
                func.count(AccessLog.id).label("count")
            )
            .where(AccessLog.timestamp >= since)
            .group_by(AccessLog.domain)
            .order_by(func.count(AccessLog.id).desc())
            .limit(limit)
        )
        rows = result.all()

    return {
        "domains": [
            {"domain": row.domain, "count": row.count}
            for row in rows
        ]
    }


@router.get("/top-blocked")
async def get_top_blocked(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    user: str = Depends(get_current_user)
):
    """Get top blocked domains across all devices."""
    since = datetime.utcnow() - timedelta(hours=hours)

    async with get_session() as session:
        result = await session.execute(
            select(
                AccessLog.domain,
                AccessLog.app_name,
                func.count(AccessLog.id).label("count")
            )
            .where(
                AccessLog.timestamp >= since,
                AccessLog.action == "blocked"
            )
            .group_by(AccessLog.domain, AccessLog.app_name)
            .order_by(func.count(AccessLog.id).desc())
            .limit(limit)
        )
        rows = result.all()

    return {
        "blocked": [
            {"domain": row.domain, "app": row.app_name, "count": row.count}
            for row in rows
        ]
    }
