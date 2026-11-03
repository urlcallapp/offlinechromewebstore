import json
import logging
import os
import xml.etree.ElementTree as ET
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    Response,
)
from fastapi.templating import Jinja2Templates

from app import config
from app.blocklist import filter_extensions, load_blocked_ids

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def load_extensions():
    if not os.path.exists(config.EXTENSIONS_FILE):
        return None
    with open(config.EXTENSIONS_FILE, "r") as handle:
        return filter_extensions(json.load(handle))


def find_extension(extensions, extension_id):
    if isinstance(extensions, list):
        for extension in extensions:
            if extension.get("extension_id") == extension_id:
                return extension
    return None


def crx_filesystem_path(extension):
    """Map a stored root-relative path_url onto the local artifacts directory."""
    versions = extension.get("versions") or []
    if not versions:
        return None
    path_url = versions[0]["path_url"]
    if path_url.startswith(config.ARTIFACTS_URL_PREFIX):
        path_url = path_url[len(config.ARTIFACTS_URL_PREFIX):]
    candidate = os.path.join(config.ARTIFACTS_DIR, path_url)
    return candidate if os.path.exists(candidate) else None


def _localname(tag):
    return tag.rsplit("}", 1)[-1]


def parse_updatecheck_appids(body):
    """Extract requested app IDs from a Chrome updatecheck request body."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    appids = []
    for element in root.iter():
        if _localname(element.tag) == "app":
            appid = element.attrib.get("appid")
            if appid:
                appids.append(appid)
    return appids


@router.get("/json")
async def serve_extensions_info_json():
    """Serve the extensions index, blocklist-filtered like every other route."""
    extensions = load_extensions()
    if extensions is None:
        return JSONResponse(
            content={"error": "extensions_info.json not found"}, status_code=404
        )
    return JSONResponse(content=extensions)


@router.api_route("/crx", methods=["GET", "POST"])
async def serve_update_feed(request: Request):
    """Chrome update feed, compatible with clients2.google.com/service/update2/crx.

    GET returns an update response for every mirrored extension. POST parses
    the updatecheck request Chrome sends and answers only for requested apps,
    reporting unknown IDs as noupdate.
    """
    extensions = load_extensions()
    if extensions is None:
        return JSONResponse(content={"error": "update feed not built"}, status_code=404)

    requested = set()
    if request.method == "POST":
        requested = set(parse_updatecheck_appids(await request.body()))
    elif "x" in request.query_params:
        # clients2-style GET: /crx?x=id%3D<extension_id>%26uc
        for part in request.query_params.get("x", "").split("&"):
            key, _, value = part.partition("=")
            if key == "id" and value:
                requested.add(value)
    if requested:
        extensions = [
            ext for ext in extensions if ext.get("extension_id") in requested
        ]

    xml_content = templates.get_template("update.xml").render(
        request=request, extensions=extensions
    )
    return Response(content=xml_content, media_type="application/xml")


@router.get("/extension/{extension_id}", response_class=HTMLResponse)
async def extension_page(request: Request, extension_id: str):
    """Render the details page of a specific extension."""
    extensions = load_extensions()
    extension = find_extension(extensions, extension_id) if extensions else None
    if extension is None:
        return JSONResponse(content={"error": "Extension not found"}, status_code=404)
    return templates.TemplateResponse(
        request,
        "extension.html",
        {
            "extension": extension,
            "current_year": datetime.now().year,
        },
    )


@router.get("/api/extensions/{extension_id}")
async def fetch_extension(extension_id: str):
    """Return the index entry of a specific extension as JSON."""
    extensions = load_extensions()
    if extensions is None:
        return JSONResponse(content={"error": "Extensions file not found"}, status_code=404)
    extension = find_extension(extensions, extension_id)
    if extension is None:
        return JSONResponse(content={"error": "Extension not found"}, status_code=404)
    return extension


@router.get("/download/{extension_id}")
async def download_extension(extension_id: str):
    """Download the newest mirrored CRX file for a specific extension."""
    if extension_id in load_blocked_ids():
        return JSONResponse(content={"error": "Extension is blocked"}, status_code=404)
    extensions = load_extensions()
    extension = find_extension(extensions, extension_id) if extensions else None
    if extension is None:
        return JSONResponse(content={"error": "Extension not found"}, status_code=404)
    crx_path = crx_filesystem_path(extension)
    if crx_path is None:
        return JSONResponse(content={"error": "CRX file not found"}, status_code=404)
    return FileResponse(
        crx_path, media_type="application/octet-stream", filename=f"{extension_id}.crx"
    )
