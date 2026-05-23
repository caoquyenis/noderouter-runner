"""
Noderouter Python Runner — Hybrid Runtime Architecture
=======================================================
Implements both execution channels as described in Blueprint 1:

  Pull Health Check  →  GET  /health
  Sync Channel       →  POST /api/sync/<app_name>     (< 5 s tasks, inline response)
  Async Channel      →  PostgreSQL LISTEN new_job + SKIP LOCKED worker pool
                         (long-running tasks; result written back to job_queue)
  Push Heartbeat     →  background thread → POST /api/nodes/heartbeat on Go Core
                         (for edge nodes behind firewalls; set NODE_ID to enable)

Configuration is read from a .env file (see .env.example).
"""

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
import select
import signal
import sys
import threading
import time
import uuid
from functools import wraps

import psycopg2
import psycopg2.extensions
import psycopg2.pool
import requests
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request

# ── Bootstrap ─────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [runner] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
CORE_URL            = os.getenv("CORE_URL", "http://localhost:8080")
NODE_ID             = os.getenv("NODE_ID", "")          # UUID assigned by Go Core
PORT                = int(os.getenv("PORT", "8000"))
HEARTBEAT_INTERVAL  = int(os.getenv("HEARTBEAT_INTERVAL", "30"))   # seconds
APPS_DIR            = os.getenv(
    "APPS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "apps"),
)
# DSN for the async channel — must point to the same PostgreSQL used by Go Core.
# Runner plugins must use this DSN directly (psycopg2) for all DB access.
# Never route plugin DB queries through Core's /api/v1/query endpoint — that
# path exists only for browser/frontend mini-app clients and adds a needless
# extra network hop.
DATABASE_URL        = os.getenv("DATABASE_URL", "")
# Max concurrent async workers (each runs in an isolated subprocess).
ASYNC_MAX_WORKERS   = int(os.getenv("ASYNC_MAX_WORKERS", "4"))
# Shared HMAC-SHA256 secret for authenticating inbound requests from Go Core.
# Must match RUNNER_SECRET on the Core side. Empty = dev mode (no verification).
RUNNER_SECRET       = os.getenv("RUNNER_SECRET", "")

_HMAC_TS_HEADER  = "X-Noderouter-Ts"
_HMAC_SIG_HEADER = "X-Noderouter-Sig"
_REPLAY_WINDOW   = 30  # seconds

_IS_WINDOWS = platform.system() == "Windows"

# ── Shutdown Coordination ──────────────────────────────────────────────────────
# Set by SIGTERM/SIGINT; all daemon loops check this before sleeping or looping.
_shutdown_event = threading.Event()


def _handle_shutdown(signum, frame):  # noqa: ARG001
    log.info("Shutdown signal received — draining workers…")
    _shutdown_event.set()


signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)


# ── HMAC Auth ─────────────────────────────────────────────────────────────────
def _verify_core_request() -> bool:
    """
    Verify the HMAC-SHA256 signature that Go Core stamps on every inbound
    request (X-Noderouter-Ts + X-Noderouter-Sig headers).

    Signature scheme (must mirror middleware/hmac.go on the Core side):
        message  = f"{timestamp}\\n{sha256_hex(body)}"
        expected = "sha256=" + HMAC-SHA256(RUNNER_SECRET, message).hex()

    Returns True when the request is authentic or RUNNER_SECRET is not set
    (dev mode). Returns False on any verification failure.
    """
    if not RUNNER_SECRET:
        return True  # dev mode — no secret configured

    ts  = request.headers.get(_HMAC_TS_HEADER, "")
    sig = request.headers.get(_HMAC_SIG_HEADER, "")
    if not ts or not sig:
        return False

    try:
        ts_int = int(ts)
    except ValueError:
        return False

    if abs(time.time() - ts_int) > _REPLAY_WINDOW:
        return False  # stale or future-dated — replay attack guard

    body       = request.get_data()  # raw bytes
    body_hash  = hashlib.sha256(body).hexdigest()
    message    = f"{ts}\n{body_hash}".encode()
    expected   = "sha256=" + hmac_lib.new(
        RUNNER_SECRET.encode(), message, hashlib.sha256
    ).hexdigest()

    return hmac_lib.compare_digest(sig, expected)


def require_core_auth(f):
    """Decorator: reject requests that fail HMAC verification."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _verify_core_request():
            log.warning(
                "Rejected unauthenticated request to %s [req=%s]",
                request.path, getattr(g, "request_id", "-"),
            )
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ── App Name Validation ────────────────────────────────────────────────────────
# Prevents directory traversal: only alphanumeric, underscore, hyphen; max 128 chars.
_APP_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$')


def _validate_app_name(app_name: str) -> str | None:
    """Return an error string if app_name is unsafe, None if valid."""
    if not _APP_NAME_RE.match(app_name):
        return (
            f"invalid app name '{app_name}': must start with alphanumeric "
            "and contain only [a-zA-Z0-9_-] (max 128 chars)"
        )
    return None


# ── DB Connection Pool ─────────────────────────────────────────────────────────
# Initialized in __main__ when DATABASE_URL is present. None otherwise.
_db_pool: psycopg2.pool.ThreadedConnectionPool | None = None


@contextlib.contextmanager
def _db_conn():
    """
    Acquire a pooled connection; rollback on unhandled exception; always return to pool.
    Raises RuntimeError if the pool was not initialized (DATABASE_URL not set).
    """
    if _db_pool is None:
        raise RuntimeError("DB pool not initialized — is DATABASE_URL set?")
    conn = _db_pool.getconn()
    try:
        yield conn
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        _db_pool.putconn(conn)


# ── Job Queue Helpers ──────────────────────────────────────────────────────────
# Whitelist prevents SQL injection via caller-controlled column names.
_ALLOWED_JOB_FIELDS = frozenset({"status", "progress", "result", "error_message"})
_JOB_TABLE          = "noderouter_core.job_queue"


def _update_job(job_id: str, **fields) -> None:
    """
    Persist job state back to job_queue via the shared connection pool.
    Only whitelisted column names are accepted to prevent SQL injection.
    """
    invalid = set(fields) - _ALLOWED_JOB_FIELDS
    if invalid:
        raise ValueError(f"Disallowed job fields: {invalid}")

    set_clause = ", ".join(f"{k} = %s" for k in fields)
    values = list(fields.values()) + [job_id]
    with _db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE {_JOB_TABLE} SET {set_clause}, updated_at = NOW() WHERE id = %s",
                values,
            )
        conn.commit()


def _fetch_pending_job(job_id: str) -> tuple[str, dict] | None:
    """
    Fetch (app_name, payload) for a pending job assigned to this node.
    Returns None if the job is not pending or belongs to a different node.
    """
    with _db_conn() as conn:
        with conn.cursor() as cur:
            if NODE_ID:
                cur.execute(
                    f"SELECT app_name, payload FROM {_JOB_TABLE} "
                    "WHERE id = %s AND node_id = %s AND status = 'pending'",
                    (job_id, NODE_ID),
                )
            else:
                cur.execute(
                    f"SELECT app_name, payload FROM {_JOB_TABLE} "
                    "WHERE id = %s AND status = 'pending'",
                    (job_id,),
                )
            row = cur.fetchone()

    if row is None:
        return None
    app_name, raw_payload = row
    payload = raw_payload if isinstance(raw_payload, dict) else json.loads(raw_payload or "{}")
    return app_name, payload


def _claim_job(job_id: str) -> str | None:
    """
    Atomically transition a pending job to 'running' via SKIP LOCKED.
    Returns the claimed job_id, or None if already claimed by another worker.
    """
    with _db_conn() as conn:
        with conn.cursor() as cur:
            if NODE_ID:
                cur.execute(
                    f"""
                    UPDATE {_JOB_TABLE}
                       SET status = 'running', updated_at = NOW()
                     WHERE id = (
                         SELECT id FROM {_JOB_TABLE}
                          WHERE id = %s AND node_id = %s AND status = 'pending'
                          FOR UPDATE SKIP LOCKED
                          LIMIT 1
                     )
                    RETURNING id
                    """,
                    (job_id, NODE_ID),
                )
            else:
                cur.execute(
                    f"""
                    UPDATE {_JOB_TABLE}
                       SET status = 'running', updated_at = NOW()
                     WHERE id = (
                         SELECT id FROM {_JOB_TABLE}
                          WHERE id = %s AND status = 'pending'
                          FOR UPDATE SKIP LOCKED
                          LIMIT 1
                     )
                    RETURNING id
                    """,
                    (job_id,),
                )
            row = cur.fetchone()
        conn.commit()

    return row[0] if row else None


def _recover_stuck_jobs() -> None:
    """
    At startup, reset any jobs stuck in 'running' from a previous crashed instance
    back to 'pending' so they can be re-dispatched.
    """
    try:
        with _db_conn() as conn:
            with conn.cursor() as cur:
                if NODE_ID:
                    cur.execute(
                        f"UPDATE {_JOB_TABLE} SET status = 'pending', updated_at = NOW() "
                        "WHERE node_id = %s AND status = 'running'",
                        (NODE_ID,),
                    )
                else:
                    cur.execute(
                        f"UPDATE {_JOB_TABLE} SET status = 'pending', updated_at = NOW() "
                        "WHERE status = 'running'"
                    )
                count = cur.rowcount
            conn.commit()
        if count:
            log.info("Startup recovery: reset %d stuck running job(s) to 'pending'", count)
    except Exception as exc:
        log.warning("Startup job recovery failed: %s", exc)


# ── In-Memory App Registry ────────────────────────────────────────────────────
# Keyed by app name (str) → loaded module object.
_app_registry: dict = {}
_registry_lock = threading.Lock()
# Cache whether each loaded module's execute() accepts a 'conn' kwarg.
# Keyed by module object id; invalidated naturally when a module is hot-reloaded
# (new object, new id). Avoids repeated inspect.signature() calls per request.
_conn_capable: dict[int, bool] = {}


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

    The module is fully loaded before the registry lock is acquired, so concurrent
    sync requests always see either the old (valid) module or the new one — never
    an absent entry. Safe to call concurrently.

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

    # Atomic swap: old module continues serving until this point.
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


# ── Flask Application ──────────────────────────────────────────────────────────
app = Flask(__name__)


@app.before_request
def _attach_request_id():
    """Propagate or generate a correlation ID for every request."""
    g.request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())


@app.after_request
def _echo_request_id(response):
    response.headers["X-Request-Id"] = g.request_id
    return response


@app.route("/health", methods=["GET"])
def health():
    """
    Pull-based health probe.
    Go Core's health daemon calls this every 10 seconds to measure latency
    and determine node status (online / offline / unhealthy).
    """
    with _registry_lock:
        loaded_apps = list(_app_registry.keys())

    return jsonify({
        "status":      "ok",
        "service":     "noderouter-runner",
        "node_id":     NODE_ID or None,
        "apps_loaded": loaded_apps,
    }), 200


@app.route("/api/sync/<app_name>", methods=["POST"])
@require_core_auth
def sync_execute(app_name: str):
    """
    Synchronous execution channel.
    Go Core forwards lightweight tasks here via Lowest-Latency-First routing.
    The app must complete within ~5 seconds (enforced by Go Core's 30 s proxy timeout).
    """
    if err := _validate_app_name(app_name):
        return jsonify({"error": err}), 400

    # Retrieve from cache; lazy-load on cache miss.
    module = _get_app(app_name)
    if module is None:
        module, err = _load_app(app_name)
        if err:
            log.warning("[%s] Sync: unknown app '%s': %s", g.request_id, app_name, err)
            return jsonify({"error": err}), 404

    try:
        data = request.get_json(silent=True) or {}
        # Inject a pooled connection when the pool is available and the app
        # declares `conn` in its execute() signature. This eliminates the
        # per-request TCP+TLS+auth handshake that dominates latency on remote DBs.
        # Apps that don't declare `conn` (or when the pool isn't configured)
        # fall back to opening their own connection as before.
        if _db_pool is not None and _conn_capable.get(id(module), False):
            with _db_conn() as conn:
                result = module.execute(data, conn=conn)
        else:
            result = module.execute(data)
        log.info("[%s] Sync execute OK: app=%s", g.request_id, app_name)
        return jsonify(result), 200
    except Exception as exc:
        log.exception("[%s] App '%s' raised an unhandled error", g.request_id, app_name)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/reload/<app_name>", methods=["POST"])
@require_core_auth
def hot_reload(app_name: str):
    """
    Hot-reload a single app without restarting the daemon.
    The new module is fully loaded before being swapped into the registry —
    concurrent sync requests see the old module until the swap completes atomically.
    Called automatically when Go Core receives an app_updated NOTIFY.
    """
    if err := _validate_app_name(app_name):
        return jsonify({"error": err}), 400

    _, err = _load_app(app_name)
    if err:
        return jsonify({"error": err}), 404

    return jsonify({"message": f"app '{app_name}' reloaded"}), 200


# ── Async Channel — Shared ProcessPoolExecutor ─────────────────────────────────
# Both pools are initialized in __main__ to avoid the Windows spawn issue:
# on Windows, ProcessPoolExecutor uses the 'spawn' start method, which re-imports
# this module in every subprocess. Module-level pool creation would cause infinite
# recursive process spawning. The None sentinels are replaced before any worker
# thread runs.
_process_pool:    concurrent.futures.ProcessPoolExecutor | None = None
_async_thread_pool: concurrent.futures.ThreadPoolExecutor | None = None


def _execute_app_isolated(app_path: str, data: dict) -> dict:
    """
    Entry point for the shared ProcessPoolExecutor subprocess.
    Loads and runs the app in complete isolation — protects the daemon from
    app-level memory leaks or native extension faults.
    Each subprocess imports fresh; no shared state with the parent.
    """
    spec   = importlib.util.spec_from_file_location("app_isolated", app_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.execute(data)


def _run_async_job(job_id: str, app_name: str, payload: dict) -> None:
    """
    Claim a pending job and execute it in the shared process pool.
    The SKIP LOCKED pattern ensures only one worker claims each job, even when
    multiple runners receive the same NOTIFY simultaneously.
    """
    claimed_id = _claim_job(job_id)
    if claimed_id is None:
        log.debug("Job %s already claimed or not assigned to this node — skipping.", job_id)
        return

    log.info("Claimed async job %s (app: %s)", job_id, app_name)

    app_path = _resolve_app_path(app_name)
    if app_path is None:
        _update_job(job_id, status="failed", error_message=f"app '{app_name}' not found")
        log.warning("Async job %s failed — app '%s' not found", job_id, app_name)
        return

    # Inject _job_id so the app can write progress milestones back to the queue.
    payload = {**payload, "_job_id": job_id}

    try:
        future = _process_pool.submit(_execute_app_isolated, app_path, payload)
        result = future.result(timeout=300)  # 5-minute hard cap per job

        result_json = json.dumps(result) if not isinstance(result, str) else result
        _update_job(job_id, status="completed", progress=100, result=result_json)
        log.info("Async job %s completed (app: %s)", job_id, app_name)

    except concurrent.futures.TimeoutError:
        _update_job(job_id, status="failed", error_message="job timed out after 300 s")
        log.error("Async job %s timed out", job_id)
    except Exception as exc:
        _update_job(job_id, status="failed", error_message=str(exc))
        log.exception("Async job %s raised an unhandled error", job_id)


# ── Portable NOTIFY Wait ───────────────────────────────────────────────────────
def _wait_for_notify(conn, timeout: float = 60.0) -> None:
    """
    Block until NOTIFY events may be available on conn or timeout elapses.
    select() on Windows only supports sockets; psycopg2 connections expose a
    raw fd that may not be selectable there. Fall back to a 1-second sleep-poll
    on Windows so the listener stays portable without busy-spinning.
    """
    if _IS_WINDOWS:
        time.sleep(min(timeout, 1.0))
    else:
        select.select([conn], [], [], timeout)


def _backoff(attempt: int, base: float = 1.0, cap: float = 60.0) -> float:
    """Exponential backoff with ±25 % jitter, capped at `cap` seconds."""
    import random
    delay = min(base * (2 ** attempt), cap)
    return delay * (0.75 + random.random() * 0.5)


# ── Async Channel — PostgreSQL LISTEN/NOTIFY Daemon ───────────────────────────
def _hot_reload_app(app_name: str) -> None:
    """Reload an app in the background so the listener thread is not blocked."""
    _, err = _load_app(app_name)
    if err:
        log.warning("Hot-reload failed for '%s': %s", app_name, err)
    else:
        log.info("Hot-reload succeeded for '%s'", app_name)


def _async_listener_loop() -> None:
    """
    Persistent PostgreSQL LISTEN daemon.
    Maintains a dedicated autocommit connection to receive NOTIFY payloads.
    Each notification carries the job_id; the worker thread does the SKIP LOCKED claim.
    Reconnects automatically on connection loss using exponential backoff.
    """
    log.info("Async listener started — LISTEN new_job (node_id: %s)", NODE_ID)
    attempt = 0
    while not _shutdown_event.is_set():
        conn = None
        try:
            conn = psycopg2.connect(DATABASE_URL)
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            with conn.cursor() as cur:
                cur.execute("LISTEN new_job;")
                cur.execute("LISTEN app_updated;")

            log.info("Async listener: LISTEN new_job + app_updated registered")
            attempt = 0  # reset backoff counter on successful connect

            while not _shutdown_event.is_set():
                _wait_for_notify(conn, timeout=60.0)
                conn.poll()

                while conn.notifies:
                    notify = conn.notifies.pop(0)

                    # ── app_updated: hot-reload in a background thread ─────────
                    if notify.channel == "app_updated":
                        name = notify.payload.strip()
                        if name:
                            log.info("NOTIFY app_updated: hot-reloading '%s'", name)
                            threading.Thread(
                                target=_hot_reload_app, args=(name,),
                                daemon=True, name=f"reload-{name}",
                            ).start()
                        continue

                    # ── new_job: verify ownership, then dispatch ───────────────
                    job_id = notify.payload.strip()
                    if not job_id:
                        continue

                    log.info("Received NOTIFY new_job: job_id=%s", job_id)

                    try:
                        result = _fetch_pending_job(job_id)
                        if result is None:
                            log.debug("Job %s is not assigned to this node — ignored.", job_id)
                            continue
                        job_app_name, payload = result
                    except Exception as exc:
                        log.warning("Failed to fetch job %s metadata: %s", job_id, exc)
                        continue

                    _async_thread_pool.submit(_run_async_job, job_id, job_app_name, payload)

        except Exception as exc:
            delay = _backoff(attempt)
            log.error("Async listener error: %s — reconnecting in %.1f s", exc, delay)
            attempt += 1
            _shutdown_event.wait(timeout=delay)
        finally:
            if conn and not conn.closed:
                try:
                    conn.close()
                except Exception:
                    pass


# ── Heartbeat Push Daemon ──────────────────────────────────────────────────────
def _heartbeat_loop() -> None:
    """
    Push-based heartbeat for edge nodes that cannot be probed inbound.
    Sends POST /api/nodes/heartbeat to Go Core at a fixed interval.
    Only active when NODE_ID is configured.
    """
    if not NODE_ID:
        log.info(
            "NODE_ID not set — heartbeat push disabled. "
            "Go Core will use pull-based health checks instead."
        )
        return

    log.info(
        "Heartbeat push enabled → %s/api/nodes/heartbeat every %ds",
        CORE_URL, HEARTBEAT_INTERVAL,
    )

    session = requests.Session()
    while not _shutdown_event.is_set():
        try:
            resp = session.post(
                f"{CORE_URL}/api/nodes/heartbeat",
                json={"node_id": NODE_ID},
                timeout=5,
            )
            if resp.status_code == 200:
                log.info("Heartbeat → core OK")
            else:
                log.warning("Heartbeat → core %d: %s", resp.status_code, resp.text[:120])
        except requests.RequestException as exc:
            log.warning("Heartbeat failed: %s", exc)

        _shutdown_event.wait(timeout=HEARTBEAT_INTERVAL)


# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not RUNNER_SECRET:
        log.warning("RUNNER_SECRET is not set — HMAC auth disabled (dev mode only)")

    log.info("=" * 60)
    log.info("Noderouter Python Runner")
    log.info("  Core URL     : %s", CORE_URL)
    log.info("  Node ID      : %s", NODE_ID or "(not set)")
    log.info("  Apps         : %s", APPS_DIR)
    log.info("  Port         : %d", PORT)
    log.info("  Async Chan   : %s", "enabled" if DATABASE_URL else "disabled (DATABASE_URL not set)")
    log.info("  Async Workers: %d", ASYNC_MAX_WORKERS)
    log.info("=" * 60)

    _preload_apps()

    if DATABASE_URL:
        # Initialize the shared DB pool before starting any DB-using threads.
        _db_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2, maxconn=ASYNC_MAX_WORKERS + 4, dsn=DATABASE_URL,
        )
        log.info("DB connection pool initialized (min=2, max=%d)", ASYNC_MAX_WORKERS + 4)

        _recover_stuck_jobs()

        # Initialize shared worker pools inside __main__ to avoid the Windows spawn
        # issue: ProcessPoolExecutor uses 'spawn' on Windows, which re-imports this
        # module in every subprocess — module-level pool creation would recurse.
        _process_pool = concurrent.futures.ProcessPoolExecutor(max_workers=ASYNC_MAX_WORKERS)
        _async_thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=ASYNC_MAX_WORKERS, thread_name_prefix="async-worker",
        )

        if not NODE_ID:
            log.warning(
                "NODE_ID is not set — async listener will claim any pending job "
                "(dev / single-runner mode). Set NODE_ID for multi-runner deployments."
            )

        listener_thread = threading.Thread(
            target=_async_listener_loop,
            daemon=True,
            name="async-listener",
        )
        listener_thread.start()
    else:
        log.info("Async channel disabled — set DATABASE_URL to enable.")

    hb_thread = threading.Thread(target=_heartbeat_loop, daemon=True, name="heartbeat")
    hb_thread.start()

    # Use Werkzeug's built-in server for the test instance.
    # For production, replace with: gunicorn -w 4 runner:app
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
