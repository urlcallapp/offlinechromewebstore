"""Mirror the recommended Chrome extensions into the artifacts directory."""
import argparse
import json
import logging
import os
import time

import schedule

from . import config
from .details import get_extension_details
from .download import ChromeExtensionDownloader
from .malicious import MaliciousChecker

logger = logging.getLogger(__name__)


class ChromeExtensionSync:
    def __init__(self, extensions_file=None, downloader=None, checker=None):
        self.extensions_file = extensions_file or self._default_extensions_file()
        self.downloader = downloader or ChromeExtensionDownloader()
        self.checker = checker or MaliciousChecker()

    @staticmethod
    def _default_extensions_file():
        # Prefer the configured/cwd path, fall back to the file shipped next
        # to this package so the module works from any working directory.
        if os.path.exists(config.RECOMMENDED_EXTENSIONS_FILE):
            return config.RECOMMENDED_EXTENSIONS_FILE
        return os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "recommended_extensions.json",
        )

    def load_specified_extensions(self):
        """Load manually specified extensions, if the file exists.

        Same format as the recommended list: objects with id/name or plain
        ID strings. Missing file means no manual additions.
        """
        path = config.SPECIFIED_EXTENSIONS_FILE
        if not os.path.exists(path):
            return []
        with open(path, "r") as handle:
            return json.load(handle)

    def load_extensions(self):
        """Recommended extensions merged with manually specified ones.

        Manually specified entries win on ID conflicts so a custom name can
        override the recommended one.
        """
        merged = {}
        for ext in self.load_recommended_extensions() + self.load_specified_extensions():
            ext_id = ext["id"] if isinstance(ext, dict) else ext
            merged[ext_id] = ext
        return list(merged.values())

    def load_recommended_extensions(self):
        """Load the recommended extension list (objects with id and name)."""
        if not os.path.exists(self.extensions_file):
            logger.warning("Extensions file not found: %s", self.extensions_file)
            return []
        with open(self.extensions_file, "r") as handle:
            return json.load(handle)

    def sync_extensions(self, force=False):
        """Mirror every recommended extension, skipping existing files unless forced."""
        from datetime import datetime

        logger.info("Starting sync at %s", datetime.now())
        extensions = self.load_extensions()
        failures = 0

        for ext in extensions:
            extension_id = ext["id"] if isinstance(ext, dict) else ext
            configured_name = ext.get("name") if isinstance(ext, dict) else None
            if self.checker.is_malicious(extension_id):
                continue
            try:
                details = get_extension_details(extension_id, name=configured_name)
            except Exception as exc:
                logger.error("Could not resolve extension %s: %s", extension_id, exc)
                failures += 1
                continue
            if self.downloader.download(
                details.extension_id, details.name, details.version, force=force
            ) is None:
                failures += 1

        self.checker.malicious_list.save()
        logger.info(
            "Sync completed at %s (%d extensions, %d failures)",
            datetime.now(),
            len(extensions),
            failures,
        )
        return failures

    def run_forever(self, force=False):
        """Run an initial sync, then re-sync on the configured interval."""
        self.sync_extensions(force=force)
        schedule.every(config.SYNC_INTERVAL_HOURS).hours.do(self.sync_extensions)
        logger.info("Sync scheduled every %d hours", config.SYNC_INTERVAL_HOURS)
        while True:
            schedule.run_pending()
            time.sleep(60)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cwssync",
        description="Mirror Chrome Web Store extensions for offline use.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single sync and exit (no scheduler).",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--sync",
        action="store_true",
        help="Incremental sync: reuse already mirrored CRX files (default).",
    )
    mode.add_argument(
        "--syncall",
        action="store_true",
        help="Force re-download of every extension, even if already mirrored.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging."
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    syncer = ChromeExtensionSync()
    if args.once:
        raise SystemExit(1 if syncer.sync_extensions(force=args.syncall) else 0)
    syncer.run_forever(force=args.syncall)


if __name__ == "__main__":
    main()
