"""
utils/logging.py — Logging configuration for auth-audit.

Call ``configure_logging()`` once at pipeline startup (in ``main.py``) before
any other module runs. After that, every module can safely call
``logging.getLogger(__name__)`` without any further setup.

Features:
  - Rich console handler for colourised, structured output (when LOG_RICH=true)
  - Standard StreamHandler fallback for plain-text / CI environments
  - Optional file handler (when LOG_FILE is configured)
  - Consistent format: timestamp · level · module · message
  - Suppresses noisy third-party library loggers at WARNING level
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# Loggers from third-party libraries that are too verbose at DEBUG level
_NOISY_LOGGERS: tuple[str, ...] = (
    "httpx",
    "httpcore",
    "asyncio",
    "hpack",
)

_CONFIGURED = False  # Guard against double-configuration


def configure_logging(
    level: str = "INFO",
    use_rich: bool = True,
    log_file: Path | None = None,
) -> None:
    """
    Apply the global logging configuration.

    Args:
        level:    Logging level string: DEBUG | INFO | WARNING | ERROR.
        use_rich: Enable Rich's pretty console handler. Falls back to a
                  plain StreamHandler if Rich is not installed.
        log_file: Optional file path to tee log output. Creates parent
                  directories if they do not exist.

    This function is idempotent — safe to call multiple times, but will only
    apply configuration on the first call.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = []

    # -------------------------------------------------------------------------
    # Console handler
    # -------------------------------------------------------------------------
    if use_rich:
        try:
            from rich.logging import RichHandler

            console_handler = RichHandler(
                level=numeric_level,
                rich_tracebacks=True,
                tracebacks_show_locals=False,
                show_time=True,
                show_path=True,
                markup=True,
            )
            # Rich formats the time itself; use a minimal format string
            console_handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
            handlers.append(console_handler)
        except ImportError:
            use_rich = False  # Fall through to plain handler

    if not use_rich:
        plain_handler = logging.StreamHandler(sys.stderr)
        plain_handler.setLevel(numeric_level)
        plain_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        handlers.append(plain_handler)

    # -------------------------------------------------------------------------
    # File handler (optional)
    # -------------------------------------------------------------------------
    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        handlers.append(file_handler)

    # -------------------------------------------------------------------------
    # Root logger
    # -------------------------------------------------------------------------
    logging.basicConfig(level=numeric_level, handlers=handlers, force=True)

    # Quiet down noisy third-party loggers
    for noisy in _NOISY_LOGGERS:
        logging.getLogger(noisy).setLevel(logging.WARNING)


def configure_logging_from_settings() -> None:
    """
    Convenience wrapper: reads config.settings and calls configure_logging().

    Avoids a circular import by importing config lazily inside the function.
    """
    from config import settings  # noqa: PLC0415  (lazy import intentional)

    configure_logging(
        level=settings.log_level,
        use_rich=settings.log_rich,
        log_file=settings.log_file,
    )


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger.

    Thin wrapper around ``logging.getLogger`` provided for import convenience
    and to make the logging contract explicit in each module.

    Usage::

        from utils.logging import get_logger
        logger = get_logger(__name__)
    """
    return logging.getLogger(name)
