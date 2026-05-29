"""
utils/retry.py — Retry helpers for async network operations.

Provides two utilities built on ``tenacity``:

  ``retry_async``       — Context-manager style retry loop for any coroutine.
  ``with_http_retry``   — Decorator factory for Tier 1 HTTP probe functions.
  ``with_llm_retry``   — Decorator factory for Tier 2 Local LLM API functions.

All policies use exponential backoff with jitter.
Settings (attempts, base wait) are read lazily from ``config.settings`` to
avoid circular imports at module load time.

Usage — decorator::

    from utils.retry import with_http_retry

    @with_http_retry()
    async def my_probe() -> ProbeResult:
        ...

Usage — inline::

    from utils.retry import retry_async
    import httpx

    result = await retry_async(
        lambda: client.get(url),
        attempts=3,
        wait_base=1.0,
        retryable=(httpx.TransportError, httpx.TimeoutException),
    )
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from tenacity import (
    AsyncRetrying,
    RetryError,
    before_sleep_log,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Exceptions that warrant a retry for HTTP probes
_HTTP_RETRYABLE: tuple[type[Exception], ...] = (
    ConnectionError,
    OSError,
    TimeoutError,
)

try:
    import httpx

    _HTTP_RETRYABLE = _HTTP_RETRYABLE + (
        httpx.TransportError,
        httpx.TimeoutException,
    )
except ImportError:  # pragma: no cover
    pass


# ---------------------------------------------------------------------------
# Core helper
# ---------------------------------------------------------------------------


async def retry_async(
    coro_factory: Callable[[], Awaitable[T]],
    attempts: int = 3,
    wait_base: float = 1.0,
    wait_max: float = 30.0,
    retryable: tuple[type[Exception], ...] = _HTTP_RETRYABLE,
) -> T:
    """
    Run an async coroutine with exponential-backoff retry.

    Args:
        coro_factory: A zero-argument callable that returns a fresh coroutine
                      on each call (e.g. ``lambda: client.get(url)``).
        attempts:     Maximum total attempts (including the first try).
        wait_base:    Base wait time in seconds; doubles on each retry.
        wait_max:     Maximum wait between retries.
        retryable:    Exception types that trigger a retry.

    Returns:
        The return value of the coroutine on success.

    Raises:
        The last exception after all attempts are exhausted (``reraise=True``).
    """
    async for attempt in AsyncRetrying(
        retry=retry_if_exception_type(retryable),
        stop=stop_after_attempt(attempts),
        wait=wait_exponential(multiplier=wait_base, min=wait_base, max=wait_max),
        before_sleep=before_sleep_log(logger, logging.DEBUG),
        reraise=True,
    ):
        with attempt:
            return await coro_factory()

    # Unreachable — AsyncRetrying with reraise=True always raises or returns
    raise RuntimeError("retry_async: should not be reached")  # pragma: no cover


# ---------------------------------------------------------------------------
# Decorator factories
# ---------------------------------------------------------------------------


def with_http_retry() -> Callable:
    """
    Decorator that wraps an async function with the configured HTTP retry policy.

    Reads ``config.settings.http_retry_attempts`` and
    ``config.settings.http_retry_wait`` at call time (not at decoration time)
    so test overrides to settings take effect correctly.

    Usage::

        @with_http_retry()
        async def probe_something(url: str) -> ProbeResult:
            ...
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            from config import settings  # lazy import

            return await retry_async(
                lambda: func(*args, **kwargs),
                attempts=settings.http_retry_attempts,
                wait_base=settings.http_retry_wait,
                retryable=_HTTP_RETRYABLE,
            )

        return wrapper

    return decorator


def with_llm_retry() -> Callable:
    """
    Decorator that wraps an async function with the configured Local LLM retry policy.

    Reads ``config.settings.llm_retry_attempts`` at call time.
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            from config import settings  # lazy import

            return await retry_async(
                lambda: func(*args, **kwargs),
                attempts=settings.llm_retry_attempts,
                wait_base=1.0,
                retryable=_HTTP_RETRYABLE,
            )

        return wrapper

    return decorator
