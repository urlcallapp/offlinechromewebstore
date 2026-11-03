"""Administration: policy previews/exports and upload intake, never device management."""
import json
from pathlib import Path

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.policy import generate_policy
from app.blocklist import MALICIOUS_LIST_FILE
from app.routes.extensions import load_extensions, crx_filesystem_path

from app.admin_access import require_admin

router = APIRouter(dependencies=[Depends(require_admin)])
templates = Jinja2Templates(directory="app/templates")


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    extensions = load_extensions() or []
    available = [ext for ext in extensions if crx_filesystem_path(ext)]
    from app import intake
    return templates.TemplateResponse(request, "admin.html", {
        "extensions": available,
        "intake_configured": bool(intake.INTAKE_DIR),
        "uploads": intake.list_uploads(),
    })


@router.post("/api/admin/policy/export")
async def export_policy(request: Request):
    # No server writes, credentials, or remote URL fetches. A Host header is never
    # used to create policy: the admin supplies the managed clients' store origin.
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 128 * 1024:
            return JSONResponse({"error": "Policy request too large"}, status_code=413)
    try:
        spec = json.loads(body)
        catalog = load_extensions()
        if catalog is None:
            return JSONResponse({"error": "Build the local catalog first"}, status_code=409)
        available = [ext for ext in catalog if crx_filesystem_path(ext)]
        path = Path(MALICIOUS_LIST_FILE)
        blocked = json.loads(path.read_text()) if path.exists() else []
        if not isinstance(blocked, list):
            raise ValueError("Invalid blocklist")
        blocked = [item["id"] if isinstance(item, dict) else item for item in blocked]
        from app import config
        result = generate_policy(spec, available, blocked, assets_dir=config.ASSETS_DIR)
    except (OSError, ValueError, TypeError, KeyError):
        return JSONResponse({"error": "Invalid selection, URL, mode, or unavailable/blocked extension"}, status_code=422)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.get("/api/admin/intake")
async def intake_list():
    from app import intake
    return JSONResponse({"configured": bool(intake.INTAKE_DIR), "uploads": intake.list_uploads()})


@router.post("/api/admin/intake/upload")
async def intake_upload(request: Request):
    """Stage one first-party CRX (raw octet-stream body) for the offline build."""
    from app import intake
    from app.blocklist import load_blocked_ids
    if not intake.INTAKE_DIR:
        raise HTTPException(503, "Upload intake is not configured on this store")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() not in (
            "application/octet-stream", "application/x-chrome-extension"):
        raise HTTPException(415, "Send the CRX bytes as application/octet-stream")
    payload = bytearray()
    async for chunk in request.stream():
        payload.extend(chunk)
        if len(payload) > intake.MAX_UPLOAD:
            raise HTTPException(413, f"Package exceeds the {intake.MAX_UPLOAD} byte limit")
    try:
        staged = intake.stage_upload(bytes(payload), load_blocked_ids())
    except intake.InvalidPackage as exc:
        raise HTTPException(422, str(exc)) from exc
    return JSONResponse({"staged": staged,
                         "note": "The package goes live only after the next offline build consumes the intake directory."})


@router.delete("/api/admin/intake/{extension_id}/{version}")
async def intake_delete(extension_id: str, version: str):
    from app import intake
    try:
        removed = intake.delete_upload(extension_id, version)
    except RuntimeError:
        raise HTTPException(503, "Upload intake is not configured on this store") from None
    except intake.InvalidPackage as exc:
        raise HTTPException(404, str(exc)) from exc
    return JSONResponse({"removed": removed})
