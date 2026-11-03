import json
import logging
import os
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import config
from app.blocklist import filter_extensions
from app.routes.extensions import router as extensions_router

logger = logging.getLogger(__name__)

app = FastAPI(title="Offline Chrome Web Store")

templates = Jinja2Templates(directory="app/templates")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

# The React storefront is the default at / (built assets are committed under
# app/static/app, so no npm step is needed at image build or run time) and
# stays reachable at /app/. The server-rendered pages are the classic
# storefront at /classic and /classic/extension/{id} - the no-JS fallback.
app.mount(
    "/app",
    StaticFiles(directory="app/static/app", html=True, check_dir=False),
    name="storefront_app",
)


def _guarded_file_response(root_dir, file_path, id_position):
    """Serve a file only if it is inside root_dir and its extension ID is not
    on the malicious blocklist. Extension-owned files are keyed by ID at
    id_position in the path."""
    from app.blocklist import load_blocked_ids

    parts = file_path.split("/")
    if len(parts) > id_position and parts[id_position] in load_blocked_ids():
        return JSONResponse(content={"error": "Extension is blocked"}, status_code=404)
    root = os.path.abspath(root_dir)
    full = os.path.abspath(os.path.join(root, file_path))
    if not (full == root or full.startswith(root + os.sep)):
        return JSONResponse(content={"error": "Not found"}, status_code=404)
    if os.path.isfile(full):
        return FileResponse(full)
    return JSONResponse(content={"error": "Not found"}, status_code=404)


@app.get("/assets/{file_path:path}", name="assets")
async def serve_asset(file_path: str):
    # assets/<extension_id>/...
    return _guarded_file_response(config.ASSETS_DIR, file_path, id_position=0)


@app.get("/artifacts/{file_path:path}", name="artifacts")
async def serve_artifact(file_path: str):
    # artifacts/extensions/<extension_id>/<version>/<file>.crx
    return _guarded_file_response(config.ARTIFACTS_DIR, file_path, id_position=1)

app.include_router(extensions_router)


def load_extensions():
    """Return the extensions index with blocked IDs filtered out."""
    if not os.path.exists(config.EXTENSIONS_FILE):
        return []
    with open(config.EXTENSIONS_FILE, "r") as handle:
        return filter_extensions(json.load(handle))


SPA_INDEX = os.path.join("app", "static", "app", "index.html")


@app.get("/", response_class=HTMLResponse, name="read_root")
async def read_root():
    """Serve the React storefront (the default)."""
    return FileResponse(SPA_INDEX)


@app.get("/classic", response_class=HTMLResponse, name="classic_storefront")
async def classic_storefront(request: Request):
    """Render the server-rendered homepage with the mirrored extensions."""
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "extensions": load_extensions(),
            "current_year": datetime.now().year,
        },
    )
