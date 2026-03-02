"""FastAPI application: REST endpoints + SSE notification stream."""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

import data_loader
import file_watcher


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start the file watcher as a background task
    task = asyncio.create_task(file_watcher.watch_loop())
    yield
    task.cancel()


app = FastAPI(title="HIDS Dashboard API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/api/summary")
def summary():
    return data_loader.get_summary()


@app.get("/api/events/timeline")
def timeline(bucket: int = Query(default=5, ge=1)):
    return data_loader.get_timeline(bucket_seconds=bucket)


@app.get("/api/events/distribution")
def distribution():
    return data_loader.get_event_distribution()


@app.get("/api/processes/top")
def top_processes(n: int = Query(default=15, ge=1, le=100)):
    return data_loader.get_top_processes(n=n)


@app.get("/api/events/rwx")
def rwx_events():
    return data_loader.get_rwx_events()


@app.get("/api/processes/tree")
def process_tree():
    return data_loader.get_process_tree()


@app.get("/api/model/results")
def model_results():
    return data_loader.get_model_results()


@app.get("/api/events/feed")
def event_feed():
    return data_loader.get_event_feed()


# ---------------------------------------------------------------------------
# SSE endpoint
# ---------------------------------------------------------------------------

@app.get("/api/stream")
async def stream():
    """One-directional SSE channel; emits log_updated / model_updated notifications."""
    q: asyncio.Queue = asyncio.Queue(maxsize=32)
    file_watcher.register_client(q)

    async def event_generator():
        try:
            # Keep-alive comment every 15 s so proxies don't close the connection
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            file_watcher.unregister_client(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
