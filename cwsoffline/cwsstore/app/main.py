import json
import logging
import os
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import config
from app.routes.extensions import router as extensions_router

logger = logging.getLogger(__name__)

app = FastAPI(title="Offline Chrome Web Store")

templates = Jinja2Templates(directory="app/templates")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
# check_dir=False: these directories are mounted volumes that may not exist yet
# on first boot; the store should still start and report an empty catalog.
app.mount("/assets", StaticFiles(directory=config.ASSETS_DIR, check_dir=False), name="assets")
app.mount("/artifacts", StaticFiles(directory=config.ARTIFACTS_DIR, check_dir=False), name="artifacts")

app.include_router(extensions_router)


def load_extensions():
    """Return the extensions index, or an empty list when it does not exist yet."""
    if not os.path.exists(config.EXTENSIONS_FILE):
        return []
    with open(config.EXTENSIONS_FILE, "r") as handle:
        return json.load(handle)


@app.get("/", response_class=HTMLResponse, name="read_root")
async def read_root(request: Request):
    """Render the homepage with the mirrored extensions."""
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "extensions": load_extensions(),
            "current_year": datetime.now().year,
        },
    )
