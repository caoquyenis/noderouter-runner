# Noderouter Python Runner

Flask daemon that loads app modules into RAM, routes synchronous calls inline, and claims async jobs from a PostgreSQL queue. Go Core (`noderouter-core` on port 3000) is the only public entry point — this runner is an internal execution backend.

---

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in DATABASE_URL and RUNNER_SECRET at minimum
python runner.py
```

> **Production:** replace `python runner.py` with `gunicorn -w 4 runner:app`

---

## Environment Variables (`.env`)

| Variable             | Required | Default                 | Purpose                                                                                                      |
| -------------------- | -------- | ----------------------- | ------------------------------------------------------------------------------------------------------------ |
| `APPS_DIR`           | **Yes**  | `./apps`                | Absolute path to the directory that holds app packages                                                       |
| `DATABASE_URL`       | **Yes**  | —                       | PostgreSQL DSN — enables the async job channel and the shared connection pool                                |
| `RUNNER_SECRET`      | **Yes**  | _(empty = dev mode)_    | Shared HMAC-SHA256 secret — must match `RUNNER_SECRET` on Go Core. Empty disables auth (dev only)            |
| `PORT`               | No       | `8000`                  | Flask listen port                                                                                            |
| `NODE_ID`            | No       | _(empty)_               | UUID from `noderouter_core.nodes`. Set for multi-runner deployments; leave empty in single-runner / dev mode |
| `CORE_URL`           | No       | `http://localhost:8080` | Go Core base URL — used only when `NODE_ID` is set (push heartbeat)                                          |
| `ASYNC_MAX_WORKERS`  | No       | `4`                     | Max concurrent async job workers (each runs in an isolated subprocess)                                       |
| `HEARTBEAT_INTERVAL` | No       | `30`                    | Seconds between push heartbeats (only when `NODE_ID` is set)                                                 |

---

## Security — HMAC Request Authentication

Every inbound request from Go Core is signed with HMAC-SHA256. The runner rejects any request that fails verification with `401 Unauthorized`.

**Signature scheme** (mirrors `middleware/hmac.go` on the Core side):

```
message  = f"{unix_timestamp}\n{sha256_hex(raw_body)}"
expected = "sha256=" + HMAC-SHA256(RUNNER_SECRET, message).hexdigest()
```

Headers sent by Go Core on every request:

| Header             | Value                             |
| ------------------ | --------------------------------- |
| `X-Noderouter-Ts`  | Unix timestamp (integer, seconds) |
| `X-Noderouter-Sig` | `sha256=<hex>`                    |

The runner rejects signatures older than **30 seconds** (replay-attack guard). Set `RUNNER_SECRET` to the same value on both sides — leaving it empty skips verification entirely and logs a warning at startup.

---

## Runner Endpoints

| Method | Path                     | Auth | Description                                                                                      |
| ------ | ------------------------ | ---- | ------------------------------------------------------------------------------------------------ |
| `GET`  | `/health`                | None | Pull-based health probe — Go Core calls this every 10 s to set node `status` and `latency_ms`    |
| `POST` | `/api/sync/<app_name>`   | HMAC | Executes `app.execute(data)` inline and returns the result. No subprocess.                       |
| `POST` | `/api/reload/<app_name>` | HMAC | Manually hot-reloads an app from disk (normally triggered automatically by `app_updated` NOTIFY) |

> **All production traffic goes through Go Core**, not directly to the runner.  
> Sync: `POST /api/sync/:app_name` → Go Core → runner  
> Async: `POST /api/async/:app_name` → Go Core → `job_queue` → runner claims via LISTEN/NOTIFY

### Health response shape

```json
{
  "status": "ok",
  "service": "noderouter-runner",
  "node_id": "<uuid or null>",
  "apps_loaded": ["app_hello_world", "..."]
}
```

Every request and response carries an `X-Request-Id` correlation header (propagated from Go Core or generated fresh if absent).

---

## Registering the Runner with Go Core

1. Start Go Core and this runner.
2. Open `/admin/nodes` → **+ Add Node**:
   - **Name**: any label (e.g. `local-runner`)
   - **Endpoint URL**: `http://localhost:8000`
   - **Location Type**: `localhost`
3. Click **Ping** — status flips to **online**.
4. Copy the node UUID and set `NODE_ID=<uuid>` in `.env` if you need push heartbeats or multi-runner job filtering.

---

## Building an App

An app is a directory (or ZIP bundle) containing at minimum `manifest.json` and `main.py`.

### App name constraints

App names are validated against `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$` (must start with alphanumeric, max 128 chars). This prevents directory traversal attacks. Names that fail validation are rejected with `400 Bad Request`.

### Directory layout

```
app_<name>/
├── manifest.json     ← required metadata
├── main.py           ← required: must expose def execute(data: dict) -> dict
├── index.html        ← optional frontend (served by Go Core)
├── index.js
├── style.css
└── libs/             ← optional local dependencies
```

The runner resolves apps in this order:

1. `{APPS_DIR}/{app_name}/main.py` ← preferred (package directory)
2. `{APPS_DIR}/{app_name}.py` ← flat single-file fallback

### `manifest.json`

```json
{
  "app_name": "app_hello_world",
  "display_name": "Hello World",
  "version": "1.0.0",
  "description": "Short description shown in the admin UI."
}
```

> `app_name` must match the directory name exactly. It is used as the URL segment in both sync (`/api/sync/<app_name>`) and async (`/api/async/<app_name>`) routes.

### `main.py` — the only required interface

Every app must expose exactly one function:

```python
def execute(data: dict) -> dict:
    ...
```

The runner calls `execute(data)` and serialises the return value as JSON. Raise any `Exception` to return a `500` on the sync channel or mark the job `failed` on the async channel.

---

## Action Routing Pattern

For apps with multiple operations, dispatch on `data["action"]`:

```python
def execute(data: dict) -> dict:
    action = str(data.get("action", "")).strip()

    if action == "create":
        return _create(data)
    if action == "list":
        return _list()
    if action == "delete":
        return _delete(data)
    if action == "run_report":          # long-running → dispatch via async channel
        return _run_report(data)

    # Default / fallback
    return {"message": "ok"}
```

---

## Sync Channel — Fast Operations (target < 5 s)

**Caller:** `POST /api/sync/<app_name>` through Go Core (30-second hard proxy timeout).  
**Target execution time: < 5 seconds.** The 30 s proxy timeout is a safety net, not a budget.

### Option A — own connection (simple)

```python
def execute(data: dict) -> dict:
    import psycopg2, os

    dsn = os.getenv("DATABASE_URL")
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name FROM public.my_table ORDER BY id DESC")
            rows = cur.fetchall()
        # connection closed automatically at end of with block

    return {"rows": [{"id": r[0], "name": r[1]} for r in rows]}
```

### Option B — pooled connection injection (lower latency)

When `DATABASE_URL` is set and your `execute()` declares a `conn` keyword argument, the runner injects a pre-warmed connection from its shared `ThreadedConnectionPool` (min=2, max=`ASYNC_MAX_WORKERS + 4`). This eliminates the per-request TCP + auth handshake overhead.

```python
def execute(data: dict, conn=None) -> dict:
    # conn is injected by the runner when the pool is available
    with conn.cursor() as cur:
        cur.execute("SELECT id, name FROM public.my_table ORDER BY id DESC")
        rows = cur.fetchall()
    return {"rows": [{"id": r[0], "name": r[1]} for r in rows]}
```

> Apps that do not declare `conn`, or when `DATABASE_URL` is not set, fall back to Option A automatically.

**Rules:**

- Return a plain `dict` — it is serialised to JSON automatically.
- Never hold open connections across calls.
- Raise any `Exception` to return `{"error": "..."}` with HTTP 500.

---

## Async Channel — Long-Running Jobs

**Caller:** `POST /api/async/<app_name>` through Go Core → writes a row to `noderouter_core.job_queue` → fires `NOTIFY new_job, '<job_id>'` → runner claims and runs in an isolated subprocess via `ProcessPoolExecutor`.

### LISTEN channels

The runner's persistent listener subscribes to two PostgreSQL channels:

| Channel       | Payload    | Action                                                     |
| ------------- | ---------- | ---------------------------------------------------------- |
| `new_job`     | `job_id`   | Claim the job via SKIP LOCKED and dispatch to process pool |
| `app_updated` | `app_name` | Hot-reload the named app in a background thread            |

The listener reconnects automatically on connection loss using **exponential backoff** (base 1 s, cap 60 s, ±25 % jitter).

### Startup job recovery

At startup, the runner resets any jobs stuck in `running` status (left by a previous crashed instance) back to `pending` so they can be re-dispatched automatically.

### What the runner injects

Before calling `execute(data)` in the subprocess, the runner adds:

```python
data["_job_id"] = "<uuid>"    # the job_queue row id — use this for progress writes
```

### Progress write-back (10 % milestones only)

Write progress at fixed milestones to avoid PostgreSQL dead-tuple bloat (MVCC constraint):

```python
import os, time, psycopg2

def execute(data: dict) -> dict:
    job_id    = data.get("_job_id", "")
    dsn       = os.getenv("DATABASE_URL", "")
    total     = 100     # units of work
    milestone = 10      # write every 10 %
    last_reported = 0

    for i in range(total):
        # ... do work ...
        time.sleep(0.5)

        progress = int(((i + 1) / total) * 100)

        if job_id and dsn and progress >= last_reported + milestone:
            last_reported = (progress // milestone) * milestone
            try:
                with psycopg2.connect(dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE noderouter_core.job_queue "
                            "SET progress = %s, updated_at = NOW() WHERE id = %s",
                            (last_reported, job_id),
                        )
                    conn.commit()
            except Exception:
                pass    # never crash the job over a progress write

    return {"message": "done", "processed": total}
```

**Rules:**

- The subprocess has **no shared state** with the daemon — import everything you need inside `execute()`.
- Hard timeout: **300 seconds** (5 minutes). Jobs exceeding this are marked `failed`.
- `progress` goes 0 → 99 during execution; the runner writes `100` on successful completion.
- Do **not** emit a DB write on every iteration — batch at fixed milestones to prevent MVCC bloat.

### Polling job status

```
GET /api/async/jobs/<job_id>     (through Go Core, JWT required)
```

Response:

```json
{
  "id": "3224e900-...",
  "app_name": "app_hello_world",
  "status": "running",
  "progress": 40,
  "result": null,
  "error_message": null,
  "created_at": "2026-05-23T15:54:47Z",
  "updated_at": "2026-05-23T15:57:03Z"
}
```

`status` lifecycle: `pending` → `running` → `completed` | `failed`

---

## Local Dependencies (`libs/`)

Place third-party packages not available in the runner's base environment inside `libs/` and inject at the top of `main.py`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "libs"))
import my_local_package
```

Default packages already available in the runner: `psycopg2`, `requests`, `flask`.

---

## Deploying an App

### Via Go Core admin UI

1. Zip the app directory: `Compress-Archive -Path app_<name>\* -DestinationPath app_<name>.zip`
2. Go to `/admin/apps` → **Deploy Bundle** → upload the ZIP.
3. Go Core extracts to `{APPS_DIR}/<app_name>/` and fires `NOTIFY app_updated, '<app_name>'`.
4. The runner's listener receives the NOTIFY and hot-reloads the module atomically — **no restart needed**.

### Via API

```bash
curl -X POST http://localhost:3000/admin/api/nodes/deploy \
     -H "Authorization: Bearer <jwt>" \
     -F "file=@app_hello_world.zip"
```

### Hot-reload behaviour

The new module is **fully loaded from disk before** it is swapped into the registry. Concurrent sync requests continue serving the old module until the atomic swap completes — there is no window where an app is absent.

---

## Reference App — `app_hello_world`

Full working example demonstrating both channels: sync CRUD (greet, create/list/update/delete products) and async long-running job with progress milestones.

```bash
# Sync — default greeting
curl -s -X POST http://localhost:3000/api/sync/app_hello_world \
     -H "Authorization: Bearer <jwt>" \
     -H "Content-Type: application/json" \
     -d '{}'

# Sync — list products
curl -s -X POST http://localhost:3000/api/sync/app_hello_world \
     -H "Authorization: Bearer <jwt>" \
     -H "Content-Type: application/json" \
     -d '{"action":"list_products"}'

# Async — 60-second test job with progress milestones
curl -s -X POST http://localhost:3000/api/async/app_hello_world \
     -H "Authorization: Bearer <jwt>" \
     -H "Content-Type: application/json" \
     -d '{"action":"start_async_job"}'
# → {"job_id":"...","status":"pending","node":"..."}

# Poll status
curl -s http://localhost:3000/api/async/jobs/<job_id> \
     -H "Authorization: Bearer <jwt>"
```

Source: `app_hello_world/main.py`
