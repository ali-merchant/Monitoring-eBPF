"""Background file watcher: detects CSV changes and broadcasts SSE notifications."""

import asyncio
from pathlib import Path

from watchfiles import awatch, Change

BASE_DIR = Path(__file__).parent.parent
LOG_CSV = str(BASE_DIR / "hids_exec_log.csv")
RESULTS_CSV = str(BASE_DIR / "hids_final_results.csv")

# Debounce: suppress repeat events within 500ms of the first one
DEBOUNCE_S = 0.5

# SSE clients: each entry is an asyncio.Queue that main.py drains
_clients: list[asyncio.Queue] = []


def register_client(q: asyncio.Queue):
    _clients.append(q)


def unregister_client(q: asyncio.Queue):
    # _clients is a list; list has no .discard(), so use a plain membership check.
    if q in _clients:
        _clients.remove(q)


async def _broadcast(message: str):
    """Push a JSON string to every connected SSE queue."""
    dead = []
    for q in _clients:
        try:
            q.put_nowait(message)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        if q in _clients:
            _clients.remove(q)


async def watch_loop():
    """Long-running coroutine started by the FastAPI lifespan."""
    pending: dict[str, float] = {}  # path → time debounce fired

    async for changes in awatch(LOG_CSV, RESULTS_CSV):
        loop = asyncio.get_event_loop()
        now = loop.time()

        for change_type, path in changes:
            if change_type not in (Change.modified, Change.added):
                continue

            # Suppress if we already debounced this file recently
            if now - pending.get(path, 0) < DEBOUNCE_S:
                continue
            pending[path] = now

            if path == LOG_CSV:
                await _broadcast('{"type":"log_updated"}')
            elif path == RESULTS_CSV:
                await _broadcast('{"type":"model_updated"}')
