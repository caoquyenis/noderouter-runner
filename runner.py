"""
Noderouter Python Runner — Tunnel Architecture
==============================================
Pure asyncio daemon. Establishes an outbound WebSocket tunnel to Go Core
and processes tasks over it:

  Sync Channel  →  req/res frames over the WebSocket tunnel  (< 5 s tasks)
  Async Channel →  PostgreSQL asyncpg LISTEN new_job + SKIP LOCKED claim
                   (long-running tasks; executed in isolated ProcessPoolExecutor)

Hot-reload triggered by PostgreSQL NOTIFY app_updated via asyncpg LISTEN.
No HTTP server is exposed — runners dial Core outbound; Core sends frames inward.
"""

import asyncio
import concurrent.futures
import contextlib
import hashlib
import hmac as hmac_lib
import importlib.util
import inspect
import json
import logging
import os
import platform
import re
import signal
import sys
import threading
import time

import asyncpg
import psycopg2
import websockets
from dotenv import load_dotenv

# ── Bootstrap ─────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [runner] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
CORE_WS_URL       = os.getenv("CORE_WS_URL", "ws://localhost:3000")
NODE_ID           = os.getenv("NODE_ID", "")
RUNNER_SECRET     = os.getenv("RUNNER_SECRET", "")
APPS_DIR          = os.getenv(
    "APPS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "apps"),
)
DATABASE_URL      = os.getenv("DATABASE_URL", "")
ASYNC_MAX_WORKERS = int(os.getenv("ASYNC_MAX_WORKERS", "4"))
SYNC_MAX_WORKERS  = int(os.getenv("SYNC_MAX_WORKERS", "8"))

_HMAC_TS_HEADER  = "X-Noderouter-Ts"
_HMAC_SIG_HEADER = "X-Noderouter-Sig"

_IS_WINDOWS = platform.system() == "Windows"

# ── Shutdown Coordination ──────────────────────────────────────────────────────
# Declared here; initialised as asyncio.Event() inside main().
_shutdown_event: asyncio.Event

# ── Worker Pools ───────────────────────────────────────────────────────────────
# Initialised in __main__ guard to avoid Windows spawn recursion.
_process_pool: concurrent.futures.ProcessPoolExecutor | None = None
_thread_pool:  concurrent.futures.ThreadPoolExecutor  | None = None

# ── DB Pool (asyncpg) ─────────────────────────────────────────────────────────
_db_pool: asyncpg.Pool | None = None

# ── App Registry ───────────────────────────────────────────────────────────────
_app_registry: dict = {}
_registry_lock = threading.Lock()   # sync lock — _load_app runs in thread pool
_conn_capable:  dict[int, bool] = {}


# ── HMAC Tunnel Signature ──────────────────────────────────────────────────────
def _compute_tunnel_sig(ts: str, node_id: str) -> str:
    """
    Compute the tunnel-handshake HMAC signature.
    Message scheme: "{timestamp}\\n{node_id}" — mirrors VerifyTunnelHandshake
    in middleware/hmac.go on the Go Core side.
    """
    message = f"{ts}\n{node_id}".encode()
    return "sha256=" + hmac_lib.new(
        RUNNER_SECRET.encode(), message, hashlib.sha256
    ).hexdigest()


# ── Backoff ────────────────────────────────────────────────────────────────────
def _backoff(attempt: int, base: float = 1.0, cap: float = 60.0) -> float:
    """Exponential backoff with ±25 % jitter, capped at `cap` seconds."""
    import random
    delay = min(base * (2 ** attempt), cap)
    return delay * (0.75 + random.random() * 0.5)


# ── App Name Validation ────────────────────────────────────────────────────────
_APP_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$')


def _validate_app_name(app_name: str) -> str | None:
    """Return an error string if app_name is unsafe, None if valid."""
    if not _APP_NAME_RE.match(app_name):
        return (
            f"invalid app name '{app_name}': must start with alphanumeric "
            "and contain only [a-zA-Z0-9_-] (max 128 chars)"
        )
    return None


def _resolve_app_path(app_name: str) -> str | None:
    """Return the absolute path to an app's entry point, or None if not found."""
    candidates = [
        os.path.join(APPS_DIR, app_name, "main.py"),
        os.path.join(APPS_DIR, f"{app_name}.py"),
    ]
    return next((p for p in candidates if os.path.isfile(p)), None)


def _load_app(app_name: str):
    """
    Dynamically load an app module from disk and atomically update the registry.
    Safe to call from thread pool workers (uses threading.Lock).

    Returns (module, None) on success or (None, error_message) on failure.
    """
    if err := _validate_app_name(app_name):
        return None, err

    app_path = _resolve_app_path(app_name)
    if app_path is None:
        return None, f"app '{app_name}' not found in {APPS_DIR}"

    try:
        spec   = importlib.util.spec_from_file_location(f"app_{app_name}", app_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:
        return None, f"failed to load app '{app_name}': {exc}"

    if not callable(getattr(module, "execute", None)):
        return None, f"app '{app_name}' does not expose a callable execute(data) function"

    accepts_conn = "conn" in inspect.signature(module.execute).parameters

    with _registry_lock:
        _app_registry[app_name] = module
    _conn_capable[id(module)] = accepts_conn
    log.info("App loaded: %s (%s) [conn-injection: %s]", app_name, app_path, accepts_conn)
    return module, None


def _get_app(app_name: str):
    """Return a cached app module, or None if not yet loaded."""
    with _registry_lock:
        return _app_registry.get(app_name)


def _preload_apps() -> None:
    """Warm the registry at startup by loading every app found on disk."""
    os.makedirs(APPS_DIR, exist_ok=True)
    loaded = 0
    for entry in sorted(os.scandir(APPS_DIR), key=lambda e: e.name):
        app_name = None
        if entry.is_dir() and os.path.isfile(os.path.join(entry.path, "main.py")):
            app_name = entry.name
        elif entry.is_file() and entry.name.endswith(".py") and entry.name != "__init__.py":
            app_name = entry.name[:-3]
        if app_name:
            _, err = _load_app(app_name)
            if err:
                log.warning("Preload skipped — %s", err)
            else:
                loaded += 1
    log.info("App preload complete: %d app(s) ready", loaded)


# ── Isolated subprocess entry point ───────────────────────────────────────────
def _execute_app_isolated(app_path: str, data: dict) -> dict:
    """
    Run an app in a separate subprocess (via ProcessPoolExecutor).
    Each invocation imports fresh — isolates the daemon from app memory leaks
    and native extension faults. Uses short-lived psycopg2 connections for any
    DB writes per the Direct DB Write Architecture.
    """
    spec   = importlib.util.spec_from_file_location("app_isolated", app_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.execute(data)


# ── DB helpers (async, asyncpg) ────────────────────────────────────────────────
_ALLOWED_JOB_FIELDS = frozenset({"status", "progress", "result", "error_message"})
_JOB_TABLE = "noderouter_core.job_queue"


async def _update_job(job_id: str, **fields) -> None:
    """
    Persist job state back to job_queue via the asyncpg pool.
    Only whitelisted column names are accepted to prevent injection.
    Progress writes should be batched (Blueprint 2 MVCC mitigation).
    """
    invalid = set(fields) - _ALLOWED_JOB_FIELDS
    if invalid:
        raise ValueError(f"Disallowed job fields: {invalid}")
    set_clause = ", ".join(f"{k} = ${i+2}" for i, k in enumerate(fields))
    values = list(fields.values())
    async with _db_pool.acquire() as conn:
        await conn.execute(
            f"UPDATE {_JOB_TABLE} SET {set_clause}, updated_at = NOW() WHERE id = $1",
            job_id, *values,
        )


async def _fetch_pending_job(job_id: str) -> tuple[str, dict] | None:
    """Fetch (app_name, payload) for a pending job assigned to this node."""
    async with _db_pool.acquire() as conn:
        if NODE_ID:
            row = await conn.fetchrow(
                f"SELECT app_name, payload FROM {_JOB_TABLE} "
                "WHERE id = $1 AND node_id = $2 AND status = 'pending'",
                job_id, NODE_ID,
            )
        else:
            row = await conn.fetchrow(
                f"SELECT app_name, payload FROM {_JOB_TABLE} "
                "WHERE id = $1 AND status = 'pending'",
                job_id,
            )
    if row is None:
        return None
    raw_payload = row["payload"]
    payload = raw_payload if isinstance(raw_payload, dict) else json.loads(raw_payload or "{}")
    return row["app_name"], payload


async def _claim_job(job_id: str) -> str | None:
    """
    Atomically transition a pending job to 'running' using SKIP LOCKED.
    Returns the claimed job_id, or None if already claimed by another worker.
    """
    async with _db_pool.acquire() as conn:
        if NODE_ID:
            row = await conn.fetchrow(
                f"""UPDATE {_JOB_TABLE}
                       SET status = 'running', updated_at = NOW()
                     WHERE id = (
                         SELECT id FROM {_JOB_TABLE}
                          WHERE id = $1 AND node_id = $2 AND status = 'pending'
                          FOR UPDATE SKIP LOCKED LIMIT 1
                     )
                    RETURNING id""",
                job_id, NODE_ID,
            )
        else:
            row = await conn.fetchrow(
                f"""UPDATE {_JOB_TABLE}
                       SET status = 'running', updated_at = NOW()
                     WHERE id = (
                         SELECT id FROM {_JOB_TABLE}
                          WHERE id = $1 AND status = 'pending'
                          FOR UPDATE SKIP LOCKED LIMIT 1
                     )
                    RETURNING id""",
                job_id,
            )
    return str(row["id"]) if row else None


def _recover_stuck_jobs_sync() -> None:
    """
    At startup, reset any jobs stuck in 'running' from a prior crashed instance
    back to 'pending' so they can be re-dispatched.
    Uses synchronous psycopg2 — called before the asyncio loop is fully running.
    """
    if not DATABASE_URL:
        return
    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                if NODE_ID:
                    cur.execute(
                        f"UPDATE {_JOB_TABLE} SET status='pending', updated_at=NOW() "
                        "WHERE node_id=%s AND status='running'",
                        (NODE_ID,),
                    )
                else:
                    cur.execute(
                        f"UPDATE {_JOB_TABLE} SET status='pending', updated_at=NOW() "
                        "WHERE status='running'"
                    )
                count = cur.rowcount
            conn.commit()
        if count:
            log.info("Startup recovery: reset %d stuck running job(s) to 'pending'", count)
    except Exception as exc:
        log.warning("Startup job recovery failed: %s", exc)


# ── Async job coroutine ────────────────────────────────────────────────────────
async def _run_async_job(job_id: str, app_name: str, payload: dict) -> None:
    """
    Claim and execute an async job in the isolated ProcessPoolExecutor.
    The SKIP LOCKED pattern guarantees only one worker claims each job even when
    multiple runners receive the same NOTIFY simultaneously.
    """
    claimed_id = await _claim_job(job_id)
    if claimed_id is None:
        log.debug("Job %s already claimed or not assigned to this node — skipping.", job_id)
        return

    log.info("Claimed async job %s (app: %s)", job_id, app_name)

    app_path = _resolve_app_path(app_name)
    if app_path is None:
        await _update_job(job_id, status="failed", error_message=f"app '{app_name}' not found")
        log.warning("Async job %s failed — app '%s' not found", job_id, app_name)
        return

    payload = {**payload, "_job_id": job_id}

    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(_process_pool, _execute_app_isolated, app_path, payload),
            timeout=300.0,
        )
        result_json = json.dumps(result) if not isinstance(result, str) else result
        await _update_job(job_id, status="completed", progress=100, result=result_json)
        log.info("Async job %s completed (app: %s)", job_id, app_name)
    except asyncio.TimeoutError:
        await _update_job(job_id, status="failed", error_message="job timed out after 300 s")
        log.error("Async job %s timed out", job_id)
    except Exception as exc:
        await _update_job(job_id, status="failed", error_message=str(exc))
        log.exception("Async job %s raised an unhandled error", job_id)


# ── Sync request handler (tunnel req frame) ────────────────────────────────────
async def _handle_req(ws, msg: dict) -> None:
    """
    Handle a single synchronous req frame received from Core over the tunnel.
    Executes module.execute(payload) in the thread pool and sends a res frame back.
    """
    rid      = msg.get("rid", "")
    app_name = msg.get("app", "")
    payload  = msg.get("payload") or {}

    async def _send_res(status: int, body: dict) -> None:
        frame = json.dumps({"type": "res", "rid": rid, "status": status, "body": body})
        try:
            await ws.send(frame)
        except Exception:
            pass  # tunnel may have closed between receive and send

    if err := _validate_app_name(app_name):
        await _send_res(400, {"error": err})
        return

    module = _get_app(app_name)
    if module is None:
        module, err = await asyncio.to_thread(_load_app, app_name)
        if err:
            await _send_res(404, {"error": err})
            return

    try:
        if isinstance(payload, (str, bytes)):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(_thread_pool, module.execute, payload)
        await _send_res(200, result if isinstance(result, dict) else {"result": result})
    except Exception as exc:
        log.exception("Sync execute error: app=%s rid=%s", app_name, rid)
        await _send_res(500, {"error": str(exc)})


# ── WebSocket Tunnel Loop ──────────────────────────────────────────────────────
async def _tunnel_loop() -> None:
    """
    Persistent outbound WebSocket tunnel to Go Core.
    Reconnects automatically using exponential backoff.

    Frame types (Core → Runner): hello, ping, req
    Frame types (Runner → Core): pong, res
    """
    attempt = 0
    uri = f"{CORE_WS_URL}/api/nodes/connect"

    while not _shutdown_event.is_set():
        try:
            ts = str(int(time.time()))
            headers = {
                "X-Node-ID":     NODE_ID,
                _HMAC_TS_HEADER: ts,
            }
            if RUNNER_SECRET and NODE_ID:
                headers[_HMAC_SIG_HEADER] = _compute_tunnel_sig(ts, NODE_ID)

            async with websockets.connect(uri, additional_headers=headers) as ws:
                attempt = 0
                log.info("[tunnel] Connected to core at %s", uri)

                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except Exception:
                        continue

                    t = msg.get("type")
                    if t == "hello":
                        log.info("[tunnel] Hello from core: node_name=%s", msg.get("node_name"))
                    elif t == "ping":
                        await ws.send(json.dumps({"type": "pong"}))
                    elif t == "req":
                        asyncio.create_task(_handle_req(ws, msg))

        except asyncio.CancelledError:
            return
        except Exception as exc:
            delay = _backoff(attempt)
            log.error("[tunnel] Error: %s — reconnecting in %.1fs", exc, delay)
            attempt += 1
            try:
                await asyncio.wait_for(_shutdown_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass


# ── PostgreSQL LISTEN Daemon (asyncpg) ─────────────────────────────────────────
async def _async_listener_loop() -> None:
    """
    Persistent PostgreSQL LISTEN daemon via asyncpg.
    Listens on new_job (trigger async job dispatch) and app_updated (hot-reload).
    Reconnects automatically with exponential backoff.
    """
    log.info("Async listener started — LISTEN new_job + app_updated (node_id: %s)", NODE_ID)
    attempt = 0

    async def _on_new_job(conn, pid, channel, payload):
        job_id = (payload or "").strip()
        if not job_id:
            return
        log.info("Received NOTIFY new_job: job_id=%s", job_id)
        try:
            result = await _fetch_pending_job(job_id)
            if result is None:
                log.debug("Job %s is not assigned to this node — ignored.", job_id)
                return
            job_app_name, job_payload = result
        except Exception as exc:
            log.warning("Failed to fetch job %s metadata: %s", job_id, exc)
            return
        asyncio.create_task(_run_async_job(job_id, job_app_name, job_payload))

    async def _on_app_updated(conn, pid, channel, payload):
        name = (payload or "").strip()
        if name:
            log.info("NOTIFY app_updated: hot-reloading '%s'", name)
            asyncio.create_task(asyncio.to_thread(_load_app, name))

    while not _shutdown_event.is_set():
        conn = None
        try:
            conn = await asyncpg.connect(DATABASE_URL)
            await conn.add_listener("new_job",     _on_new_job)
            await conn.add_listener("app_updated", _on_app_updated)
            log.info("Async listener: LISTEN channels registered")
            attempt = 0
            # Park until shutdown or connection drop.
            await _shutdown_event.wait()
        except asyncio.CancelledError:
            return
        except Exception as exc:
            delay = _backoff(attempt)
            log.error("Async listener error: %s — reconnecting in %.1fs", exc, delay)
            attempt += 1
            try:
                await asyncio.wait_for(_shutdown_event.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
        finally:
            if conn and not conn.is_closed():
                with contextlib.suppress(Exception):
                    await conn.close()


# ── Entry point ────────────────────────────────────────────────────────────────
async def main() -> None:
    global _shutdown_event, _db_pool
    _shutdown_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    if not _IS_WINDOWS:
        loop.add_signal_handler(signal.SIGTERM, _shutdown_event.set)
        loop.add_signal_handler(signal.SIGINT,  _shutdown_event.set)
    # Windows: KeyboardInterrupt is caught at the asyncio.run() level below.

    log.info("=" * 60)
    log.info("Noderouter Python Runner — Tunnel Architecture")
    log.info("  Core WS URL  : %s", CORE_WS_URL)
    log.info("  Node ID      : %s", NODE_ID or "(not set)")
    log.info("  Apps         : %s", APPS_DIR)
    log.info("  Async Chan   : %s", "enabled" if DATABASE_URL else "disabled (DATABASE_URL not set)")
    log.info("  Async Workers: %d", ASYNC_MAX_WORKERS)
    log.info("  Sync Workers : %d", SYNC_MAX_WORKERS)
    log.info("=" * 60)

    # Preload apps synchronously before accepting any tunnel requests.
    await asyncio.to_thread(_preload_apps)

    if DATABASE_URL:
        _db_pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=2,
            max_size=ASYNC_MAX_WORKERS + 4,
        )
        log.info("asyncpg pool initialized (min=2, max=%d)", ASYNC_MAX_WORKERS + 4)
        _recover_stuck_jobs_sync()
        asyncio.create_task(_async_listener_loop())
    else:
        log.info("Async channel disabled — set DATABASE_URL to enable.")

    asyncio.create_task(_tunnel_loop())

    await _shutdown_event.wait()
    log.info("Shutting down noderouter-runner…")

    if _db_pool:
        await _db_pool.close()
    if _process_pool:
        _process_pool.shutdown(wait=False)
    if _thread_pool:
        _thread_pool.shutdown(wait=False)


if __name__ == "__main__":
    if not RUNNER_SECRET:
        log.warning("RUNNER_SECRET is not set — HMAC auth disabled (dev mode only)")
    if not NODE_ID:
        log.warning("NODE_ID is not set — runner will be rejected by Core (set NODE_ID)")

    # Initialise executor pools before asyncio.run() to avoid Windows spawn recursion:
    # ProcessPoolExecutor uses 'spawn' on Windows, which re-imports this module in
    # every subprocess — module-level pool creation would cause infinite spawning.
    _process_pool = concurrent.futures.ProcessPoolExecutor(max_workers=ASYNC_MAX_WORKERS)
    _thread_pool  = concurrent.futures.ThreadPoolExecutor(
        max_workers=SYNC_MAX_WORKERS, thread_name_prefix="sync-worker",
    )

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Interrupted — exiting.")
    finally:
        if _process_pool:
            _process_pool.shutdown(wait=False)
        if _thread_pool:
            _thread_pool.shutdown(wait=False)
