"""Scan management endpoints."""

from ipaddress import ip_address, ip_network
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_admin, require_scope
from app.core.config import settings
from app.core.database import get_db
from app.core.scan_authorization import (
    ScanAuthorizationError,
    authorize_scan_host,
    authorize_scan_network,
)
from app.models import Scan, ScanNetwork

router = APIRouter()


def _is_authorized_network(cidr: str) -> bool:
    try:
        authorize_scan_network(cidr)
        return True
    except ScanAuthorizationError:
        return False


class ScanNetworkCreate(BaseModel):
    cidr: str
    name: str = Field(min_length=1, max_length=128)
    scan_type: Literal["discovery"] = "discovery"
    excluded_ips: list[str] = Field(default_factory=list, max_length=4096)

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        try:
            return str(ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError("invalid scan CIDR") from exc

    @model_validator(mode="after")
    def validate_exclusions(self) -> "ScanNetworkCreate":
        network = ip_network(self.cidr, strict=True)
        normalized = []
        for value in self.excluded_ips:
            try:
                address = ip_address(value)
            except ValueError as exc:
                raise ValueError("excluded_ips must contain IP addresses") from exc
            if address.version != network.version or address not in network:
                raise ValueError("excluded IP must belong to the scan CIDR")
            normalized.append(str(address))
        self.excluded_ips = sorted(set(normalized))
        return self


@router.get("", dependencies=[Depends(require_scope("scans:read", "analyst"))])
async def list_scans(db: AsyncSession = Depends(get_db), limit: int = 100):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(limit))
    return {
        "items": [
            {
                "id": str(s.id),
                "scan_type": s.scan_type,
                "target": s.target,
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "hosts_found": s.hosts_found,
                "error": s.error,
            }
            for s in result.scalars().all()
        ]
    }


@router.get("/networks", dependencies=[Depends(require_admin)])
async def list_networks(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanNetwork))
    return {
        "items": [
            {
                "id": str(n.id),
                "cidr": n.cidr,
                "name": n.name,
                "enabled": n.enabled,
                "scan_type": n.scan_type,
                "excluded_ips": n.excluded_ips,
                "authorized": _is_authorized_network(n.cidr),
            }
            for n in result.scalars().all()
        ]
    }


@router.post("/networks", status_code=201)
async def add_network(
    body: ScanNetworkCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    try:
        body.cidr = authorize_scan_network(body.cidr)
    except ScanAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    n = ScanNetwork(**body.model_dump())
    db.add(n)
    await audit(request, "scan_network_added", user, db, details={"cidr": body.cidr})
    await db.commit()
    return {"id": str(n.id)}


@router.post("/trigger")
async def trigger_scan_now(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("scans:trigger", "admin")),
):
    from app.workers.scan_tasks import run_all_network_scans

    if not settings.SCAN_NETWORKS:
        raise HTTPException(
            status_code=409,
            detail="Network scanning is disabled until SCAN_NETWORKS contains an authorized CIDR",
        )
    run_all_network_scans.delay()
    await audit(request, "manual_scan_trigger", user, db)
    await db.commit()
    return {"queued": True}


class ServiceScanRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        try:
            return str(authorize_scan_host(value))
        except ScanAuthorizationError as exc:
            raise ValueError(str(exc)) from exc


@router.post("/service")
async def trigger_service_scan(
    body: ServiceScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_scope("scans:trigger", "admin")),
):
    from app.workers.scan_tasks import service_scan_host

    service_scan_host.delay(body.ip)
    await audit(request, "manual_service_scan", user, db, details={"ip": body.ip})
    await db.commit()
    return {"queued": True, "ip": body.ip}
