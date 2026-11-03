"""Client for the ExtensionTotal risk API.

The API key is read from the EXTENSIONTOTAL_API_KEY environment variable.
The client is import-safe without a key; only actual requests require one.
"""
import logging
import os

import requests

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://app.extensiontotal.com/api"


class ExtensionTotalClient:
    def __init__(self, api_key=None, base_url=DEFAULT_BASE_URL, timeout=30):
        self.api_key = api_key or os.environ.get("EXTENSIONTOTAL_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @property
    def available(self):
        """True when an API key is configured and requests can be made."""
        return bool(self.api_key)

    def get_extension_risk(self, extension_id):
        """Return the parsed risk report for *extension_id*.

        Raises RuntimeError when no API key is configured, requests.HTTPError
        on API errors.
        """
        if not self.api_key:
            raise RuntimeError(
                "EXTENSIONTOTAL_API_KEY is not set; risk lookups are disabled"
            )
        response = requests.post(
            f"{self.base_url}/getExtensionRisk",
            json={"q": extension_id},
            headers={"Content-Type": "application/json", "X-API-Key": self.api_key},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()
