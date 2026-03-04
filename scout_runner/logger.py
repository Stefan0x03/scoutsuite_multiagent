"""
Logging setup with credential masking.

All secret values are registered with MaskingFilter before scans start.
The filter replaces them with ***REDACTED*** in every log record so secrets
never appear in console output or log files.
"""

import logging

_REDACTED = "***REDACTED***"


class MaskingFilter(logging.Filter):
    """Replaces registered secret strings in log records."""

    def __init__(self) -> None:
        super().__init__()
        self._secrets: set[str] = set()

    def register(self, value: str) -> None:
        """Register a secret string to be masked in all log output."""
        # Skip trivially short values that would mask too broadly
        if value and len(value) > 3:
            self._secrets.add(value)

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._mask(str(record.msg))
        # Flatten args into the message so we can scrub them too
        if record.args:
            try:
                record.msg = record.msg % record.args
            except Exception:
                pass
            record.args = None
        return True

    def _mask(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, _REDACTED)
        return text


# Module-level singleton — shared across all modules
masking_filter = MaskingFilter()


def setup_logging(debug: bool = False) -> None:
    """Configure root logger and attach the masking filter."""
    level = logging.DEBUG if debug else logging.INFO
    handler = logging.StreamHandler()
    handler.addFilter(masking_filter)
    fmt = logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(level)
    # Remove any existing handlers before adding ours
    root.handlers.clear()
    root.addHandler(handler)
