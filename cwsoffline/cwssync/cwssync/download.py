"""Download Chrome extension CRX packages from Google's update service."""
import logging
import os
import re

import requests

from . import config

logger = logging.getLogger(__name__)


def slugify_name(name):
    """Make an extension name safe for use in a file name."""
    slug = re.sub(r"[^\w\-]+", "-", name.strip()).strip("-")
    return slug or "extension"


class ChromeExtensionDownloader:
    """Downloads CRX files into the artifacts directory layout:

    <artifacts_dir>/extensions/<extension_id>/<version>/<id>_<name>_<version>.crx
    """

    def __init__(self, artifacts_dir=None, store_url=None, prodversion=None, timeout=None):
        self.artifacts_dir = artifacts_dir or config.ARTIFACTS_DIR
        self.store_url = store_url or config.CHROME_STORE_URL
        self.prodversion = prodversion or config.CHROME_PROD_VERSION
        self.timeout = timeout or config.REQUEST_TIMEOUT

    def crx_path(self, extension_id, name, version):
        directory = os.path.join(self.artifacts_dir, "extensions", extension_id, version)
        filename = f"{extension_id}_{slugify_name(name)}_{version}.crx"
        return os.path.join(directory, filename)

    def _effective_prodversion(self):
        """Resolve the Chrome prodversion once; the update service answers
        204 No Content when the parameter is missing entirely."""
        if not self.prodversion:
            from .chrome_version import get_latest_chrome_version

            self.prodversion = (
                get_latest_chrome_version(timeout=self.timeout)
                or config.FALLBACK_CHROME_PROD_VERSION
            )
        return self.prodversion

    def download(self, extension_id, name, version, force=False):
        """Download one extension version. Returns the file path, or None on failure.

        Existing files are reused unless *force* is True (--syncall).
        """
        file_path = self.crx_path(extension_id, name, version)
        if os.path.exists(file_path) and not force:
            logger.info("Already mirrored, skipping: %s", file_path)
            return file_path

        params = {
            "response": "redirect",
            "nacl_arch": "x86-64",
            "acceptformat": "crx2,crx3",
            "prodversion": self._effective_prodversion(),
            "x": f"id={extension_id}&installsource=ondemand&uc",
        }
        try:
            response = requests.get(
                self.store_url,
                params=params,
                headers={"User-Agent": config.USER_AGENT},
                stream=True,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            logger.error("Error downloading extension %s: %s", extension_id, exc)
            return None

        if response.status_code != 200:
            logger.error(
                "Failed to download extension %s: HTTP %s",
                extension_id,
                response.status_code,
            )
            return None

        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as handle:
            for chunk in response.iter_content(chunk_size=8192):
                handle.write(chunk)
        logger.info("Successfully downloaded extension: %s", file_path)
        return file_path
