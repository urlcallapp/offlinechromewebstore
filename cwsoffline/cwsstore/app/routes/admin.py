"""Read-only administration: policy previews/exports, never device management."""
import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.policy import generate_policy
from app.blocklist import MALICIOUS_LIST_FILE
from app.routes.extensions import load_extensions, crx_filesystem_path

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    extensions = load_extensions() or []
    available = [ext for ext in extensions if crx_filesystem_path(ext)]
    return templates.TemplateResponse(request, "admin.html", {"extensions": available})


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
        result = generate_policy(spec, available, blocked)
    except (OSError, ValueError, TypeError, KeyError):
        return JSONResponse({"error": "Invalid selection, URL, mode, or unavailable/blocked extension"}, status_code=422)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})
