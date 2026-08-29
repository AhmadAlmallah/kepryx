"""Bulk CSV import with hardening (C-02, H-01, H-04).

Fixes applied:
  - C-02: 50MB file size limit; streaming read
  - H-01: Rate limit 3 imports per user per 60s
  - H-04: Pre-scan for duplicate names within CSV
"""

import csv
import io
from typing import Any, NotRequired, TypedDict
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import audit, require_analyst
from app.core.database import get_db
from app.core.rate_limit import per_user_rate_limit

router = APIRouter()


MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50MB
MAX_ROWS_PER_IMPORT = 10000  # cap per single import

REQUIRED_FIELDS = {"name", "type"}
ALLOWED_FIELDS = {
    "name",
    "type",
    "os",
    "ip",
    "mac",
    "segment",
    "edr_status",
    "control_coverage",
    "network_exposure",
    "auth_method",
    "criticality",
    "data_classification",
    "last_patch",
    "eol_status",
    "software_stack",
    "cpe",
    "dependencies",
    "tags",
}
DEFAULTS = {
    "control_coverage": "partial",
    "network_exposure": "internal",
    "auth_method": "password",
    "criticality": "medium",
    "data_classification": "Internal",
    "segment": "Internal",
    "edr_status": "None",
    "type": "Unknown",
}


class ImportResults(TypedDict):
    created: int
    errors: list[dict[str, Any]]
    preview: list[dict[str, Any]]
    dry_run: NotRequired[bool]


@router.post(
    "/import-csv",
    dependencies=[Depends(require_analyst), Depends(per_user_rate_limit("bulk_import", 3, 60))],
)
async def import_assets_csv(
    request: Request,
    file: UploadFile = File(...),
    dry_run: bool = False,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst),
):
    """Bulk import assets from CSV. Max 50MB, max 10000 rows.

    H-04 fix: Pre-scans CSV for duplicate names BEFORE inserting. If duplicates
    found, returns error and aborts (atomic).
    """
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File must be .csv")

    # C-02 fix: streaming read with bounded buffer
    chunks = []
    total_bytes = 0
    while True:
        chunk = await file.read(1024 * 1024)  # 1MB chunks
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"File exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit",
            )
        chunks.append(chunk)
    content = b"".join(chunks)

    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File must be UTF-8 encoded") from exc

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty CSV")

    headers = set(h.strip().lower() for h in reader.fieldnames)
    missing = REQUIRED_FIELDS - headers
    if missing:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Missing required CSV columns: {sorted(missing)}",
        )

    # H-04 fix: pre-scan for duplicates within CSV
    all_rows = list(reader)
    if len(all_rows) > MAX_ROWS_PER_IMPORT:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"CSV has {len(all_rows)} rows, max allowed is {MAX_ROWS_PER_IMPORT}",
        )

    seen_names: dict[str, int] = {}
    duplicates: list[dict[str, Any]] = []
    for row_num, row in enumerate(all_rows, start=2):
        name = (row.get("name") or row.get("Name") or "").strip()
        if not name:
            continue
        if name in seen_names:
            duplicates.append({"row": row_num, "name": name, "first_seen": seen_names[name]})
        else:
            seen_names[name] = row_num
    if duplicates:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            {"error": "Duplicate asset names in CSV", "duplicates": duplicates[:10]},
        )

    # H-04 continued: also check against existing assets in DB
    if not dry_run:
        from app.models import Asset

        existing_query = await db.execute(
            select(Asset.name).where(Asset.name.in_(list(seen_names.keys())))
        )
        existing_names = {row[0] for row in existing_query}
        if existing_names:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                {
                    "error": "Asset names already exist in database",
                    "existing": sorted(existing_names)[:20],
                    "hint": "Update via PATCH or use unique names",
                },
            )

    from app.models import Asset
    from app.services.risk_engine import compute_risk

    results: ImportResults = {"created": 0, "errors": [], "preview": []}
    for row_num, row in enumerate(all_rows, start=2):
        try:
            data: dict[str, Any] = {k.strip().lower(): (v or "").strip() for k, v in row.items()}
            if not data.get("name"):
                results["errors"].append({"row": row_num, "error": "name is required"})
                continue

            for field, default in DEFAULTS.items():
                if not data.get(field):
                    data[field] = default

            for list_field in ("software_stack", "cpe", "dependencies", "tags"):
                if data.get(list_field):
                    data[list_field] = [s.strip() for s in data[list_field].split(";") if s.strip()]
                else:
                    data[list_field] = []

            eol = (data.get("eol_status") or "").lower()
            data["eol_status"] = eol in ("true", "1", "yes", "y")

            for nullable in ("ip", "mac"):
                if data.get(nullable) in ("N/A", "DHCP", "Unknown", "", None):
                    data[nullable] = None

            risk = compute_risk(
                {
                    "control_coverage": data["control_coverage"],
                    "network_exposure": data["network_exposure"],
                    "auth_method": data["auth_method"],
                    "criticality": data["criticality"],
                    "data_classification": data["data_classification"],
                    "eol_status": data["eol_status"],
                    "cves": [],
                }
            )

            # F-06 fix: OR instead of AND for shadow IT detection
            is_shadow = (data.get("edr_status") in ("None", "", None)) or (
                data["control_coverage"] == "none"
            )

            asset_data: dict[str, Any] = {
                "id": uuid4(),
                "name": data["name"],
                "type": data.get("type", "Unknown"),
                "os": data.get("os") or None,
                "ip": data.get("ip"),
                "mac": data.get("mac"),
                "segment": data["segment"],
                "edr_status": data.get("edr_status", "None"),
                "control_coverage": data["control_coverage"],
                "network_exposure": data["network_exposure"],
                "auth_method": data["auth_method"],
                "criticality": data["criticality"],
                "data_classification": data["data_classification"],
                "last_patch": data.get("last_patch") or None,
                "eol_status": data["eol_status"],
                "software_stack": data["software_stack"],
                "cpe": data["cpe"],
                "dependencies": data["dependencies"],
                "sources": ["csv_import"],
                "is_shadow": is_shadow,
                "tags": data["tags"],
                "risk_score": risk.score,
                "risk_tier": risk.tier,
                "risk_breakdown": risk.breakdown,
                "attrs": {},
            }

            if dry_run:
                if len(results["preview"]) < 10:
                    results["preview"].append(
                        {
                            "name": asset_data["name"],
                            "type": asset_data["type"],
                            "risk_tier": asset_data["risk_tier"],
                            "risk_score": asset_data["risk_score"],
                        }
                    )
            else:
                asset = Asset(**asset_data)
                db.add(asset)

            results["created"] += 1
        except Exception as e:
            results["errors"].append({"row": row_num, "error": str(e)[:200]})

    if not dry_run:
        await audit(
            request,
            "bulk_import_csv",
            user,
            db,
            resource_type="asset",
            details={
                "rows_processed": results["created"] + len(results["errors"]),
                "created": results["created"],
                "errors": len(results["errors"]),
                "filename": file.filename,
                "file_size_bytes": total_bytes,
            },
        )
        await db.commit()

    results["dry_run"] = dry_run
    return results
