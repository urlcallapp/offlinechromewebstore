"""Resolve extension metadata (version, name) from Google's update service."""
import logging
import xml.etree.ElementTree as ET
from collections import namedtuple

import requests
from bs4 import BeautifulSoup

from . import config

logger = logging.getLogger(__name__)

ExtensionDetails = namedtuple(
    "ExtensionDetails",
    ["name", "version", "extension_id", "codebase", "size", "hash_sha256"],
    defaults=[None, None, None],
)


def _localname(tag):
    """Strip an XML namespace from a tag name."""
    return tag.rsplit("}", 1)[-1]


def parse_updatecheck_response(content):
    """Parse an update2 updatecheck response.

    Returns (version, codebase, size, hash_sha256). The live service puts
    these as attributes on <updatecheck>; a child <manifest> element is
    accepted as a fallback. Raises ValueError on noupdate/error statuses.
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed XML in the update response: {exc}") from exc
    version = codebase = None
    size = hash_sha256 = None
    for element in root.iter():
        name = _localname(element.tag)
        if name == "updatecheck":
            status = element.attrib.get("status", "")
            if status and status != "ok":
                raise ValueError(f"Update service returned status {status!r}")
            version = element.attrib.get("version", version)
            codebase = element.attrib.get("codebase", codebase)
            size = element.attrib.get("size", size)
            hash_sha256 = element.attrib.get("hash_sha256", hash_sha256)
        elif name == "manifest":
            version = element.attrib.get("version", version)
    if not version:
        raise ValueError("No version information in the update response")
    return version, codebase, size, hash_sha256


def get_extension_version(extension_id, prodversion, timeout=None):
    """Return the latest published version of *extension_id*.

    Uses the same update2 updatecheck API that Chrome itself uses, which is
    far more reliable than scraping the web store's HTML.
    Raises ValueError when the service reports no update for the extension.
    """
    timeout = timeout or config.REQUEST_TIMEOUT
    params = {
        "response": "updatecheck",
        "prodversion": prodversion,
        # Without acceptformat the service answers "noupdate" even when a
        # newer CRX exists (verified against the live service).
        "acceptformat": "crx2,crx3",
        "x": f"id={extension_id}&uc",
    }
    response = requests.get(
        config.CHROME_STORE_URL,
        params=params,
        headers={"User-Agent": config.USER_AGENT},
        timeout=timeout,
    )
    response.raise_for_status()
    try:
        version, _, _, _ = parse_updatecheck_response(response.content)
    except ValueError as exc:
        raise ValueError(f"{exc} (extension {extension_id})")
    return version


def get_extension_name(extension_id, timeout=None):
    """Best-effort name lookup from the public web store page.

    Returns None when the name cannot be determined - callers should fall
    back to the configured name or the extension ID.
    """
    timeout = timeout or config.REQUEST_TIMEOUT
    url = f"{config.WEBSTORE_DETAIL_URL}/{extension_id}"
    try:
        response = requests.get(
            url, headers={"User-Agent": config.USER_AGENT}, timeout=timeout
        )
        if response.status_code != 200:
            return None
        soup = BeautifulSoup(response.content, "html.parser")
        heading = soup.find("h1", string=lambda text: text)
        if heading:
            return heading.get_text(strip=True)
    except requests.RequestException as exc:
        logger.debug("Name lookup failed for %s: %s", extension_id, exc)
    return None


def get_extension_details(extension_id, name=None, prodversion=None, timeout=None):
    """Return ExtensionDetails for *extension_id*.

    *name* may be supplied from local configuration (recommended_extensions.json);
    otherwise a best-effort web store lookup is attempted, then the ID itself.
    """
    prodversion = prodversion or config.CHROME_PROD_VERSION
    if not prodversion:
        from .chrome_version import get_latest_chrome_version

        prodversion = (
            get_latest_chrome_version(timeout=timeout or config.REQUEST_TIMEOUT)
            or config.FALLBACK_CHROME_PROD_VERSION
        )
    version, codebase, size, hash_sha256 = _get_version_and_metadata(
        extension_id, prodversion, timeout=timeout
    )
    resolved_name = name or get_extension_name(extension_id, timeout=timeout) or extension_id
    return ExtensionDetails(
        resolved_name, version, extension_id, codebase, size, hash_sha256
    )


def _get_version_and_metadata(extension_id, prodversion, timeout=None):
    timeout = timeout or config.REQUEST_TIMEOUT
    params = {
        "response": "updatecheck",
        "prodversion": prodversion,
        "acceptformat": "crx2,crx3",
        "x": f"id={extension_id}&uc",
    }
    response = requests.get(
        config.CHROME_STORE_URL,
        params=params,
        headers={"User-Agent": config.USER_AGENT},
        timeout=timeout,
    )
    response.raise_for_status()
    try:
        return parse_updatecheck_response(response.content)
    except ValueError as exc:
        raise ValueError(f"{exc} (extension {extension_id})")
