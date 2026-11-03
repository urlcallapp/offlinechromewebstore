"""Resolve extension metadata (version, name) from Google's update service."""
import logging
import xml.etree.ElementTree as ET
from collections import namedtuple

import requests
from bs4 import BeautifulSoup

from . import config

logger = logging.getLogger(__name__)

ExtensionDetails = namedtuple("ExtensionDetails", ["name", "version", "extension_id"])


def _localname(tag):
    """Strip an XML namespace from a tag name."""
    return tag.rsplit("}", 1)[-1]


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
        "x": f"id={extension_id}&uc",
    }
    response = requests.get(
        config.CHROME_STORE_URL,
        params=params,
        headers={"User-Agent": config.USER_AGENT},
        timeout=timeout,
    )
    response.raise_for_status()
    root = ET.fromstring(response.content)

    for element in root.iter():
        if _localname(element.tag) == "updatecheck":
            status = element.attrib.get("status", "")
            if status and status != "ok":
                raise ValueError(
                    f"Update service returned status {status!r} for {extension_id}"
                )
        if _localname(element.tag) == "manifest":
            version = element.attrib.get("version")
            if version:
                return version
    raise ValueError(f"No version information returned for {extension_id}")


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
    version = get_extension_version(extension_id, prodversion, timeout=timeout)
    resolved_name = name or get_extension_name(extension_id, timeout=timeout) or extension_id
    return ExtensionDetails(resolved_name, version, extension_id)
