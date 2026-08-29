"""Run async coroutines in Celery sync tasks with a reused event loop.

asyncio.run() creates a new loop per call which: leaks file descriptors,
re-creates DB connection pools per task, and breaks httpx persistent connections.
This helper keeps one loop per worker process.
"""

import asyncio
import logging
from collections.abc import Coroutine
from typing import TypeVar

logger = logging.getLogger(__name__)
T = TypeVar("T")

_loop: asyncio.AbstractEventLoop | None = None


def get_loop() -> asyncio.AbstractEventLoop:
    global _loop
    if _loop is None or _loop.is_closed():
        _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)
    return _loop


def run_async[T](coro: Coroutine[None, None, T]) -> T:
    """Run an async coroutine in the worker's persistent event loop."""
    loop = get_loop()
    return loop.run_until_complete(coro)


def close_loop():
    """Called on worker shutdown."""
    global _loop
    if _loop and not _loop.is_closed():
        _loop.close()
        _loop = None
