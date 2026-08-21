"""
dispatcher.py — runs as PID 2 inside the bwrap sandbox.

Startup sequence (ALL of this runs BEFORE user code is imported):
  1. Pop SANDBOX_DB_CONFIG — establish DB connection, remove details from env.
  2. Pop HTTP_PROXY_UNIX   — patch urllib3 to route through Unix socket proxy.
  3. Import ai_code_sandbox (user code).
  4. Call the requested function, injecting `db=<connection>` if declared.
  5. Print __RESULT__:<json> on stdout.

What the AI code sees in os.environ:
  PATH, PYTHONPATH                  always
  HTTP_PROXY, HTTPS_PROXY, NO_PROXY if network is enabled
  (nothing else — no database details, no socket paths, no credentials)

What the AI code receives as a function parameter:
  db=<connection object>  if the function declares a `db` parameter
                          and database access is enabled in policy
"""
import inspect
import json
import os
import sys
import socket
import traceback

sys.path.append("/sandbox")


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Pop SANDBOX_DB_CONFIG and establish the connection
# ─────────────────────────────────────────────────────────────────────────────

_raw_db_cfg = os.environ.pop("SANDBOX_DB_CONFIG", "")
try:
    _db_cfg = json.loads(_raw_db_cfg) if _raw_db_cfg else {}
except json.JSONDecodeError as _e:
    import sys
    print(f'[dispatcher] FATAL: malformed SANDBOX_DB_CONFIG: {_e}', file=sys.stderr)
    sys.exit(1)


def _establish_db_connection(cfg: dict):
    """Connect to the DB proxy Unix socket.

    The proxy owns the real credentials, hostname, and database name.
    The sandbox only needs to know WHERE the proxy socket is (mount path)
    and WHICH driver protocol to speak (postgres or mysql).
    """
    if not cfg:
        return None

    driver = cfg.get("driver", "postgres").lower()
    mount  = cfg.get("mount",  "")
    if not mount:
        return None

    try:
        if driver in ("postgres", "postgresql", "pg"):
            import psycopg2
            return psycopg2.connect(host=mount)

        if driver in ("mysql", "mariadb"):
            import pymysql
            return pymysql.connect(
                unix_socket=os.path.join(mount, "mysql.sock"),
                user=os.environ.get("MYSQL_USER", "sandbox"),
                db=os.environ.get("MYSQL_DATABASE", ""),
                autocommit=True,
            )

    except Exception as exc:
        print(f"[dispatcher] DB connection error: {exc}", file=sys.stderr)

    return None


_db_conn = _establish_db_connection(_db_cfg)


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Pop HTTP_PROXY_UNIX and patch urllib3
#
# Instead of starting a bridge thread (which needs clone/threading),
# we monkey-patch urllib3.util.connection.create_connection to route
# connections to a fake proxy hostname through the Unix socket directly.
#
# This works for: requests, urllib3, httpx (via proxy env vars),
# and any library that respects HTTP_PROXY / HTTPS_PROXY.
#
# No threading. No asyncio. No extra syscalls.
# ─────────────────────────────────────────────────────────────────────────────

_PROXY_SOCK_PATH = os.environ.pop("HTTP_PROXY_UNIX", "")
if _PROXY_SOCK_PATH and not os.path.isabs(_PROXY_SOCK_PATH):
    print(f'[dispatcher] WARNING: HTTP_PROXY_UNIX is not absolute: {_PROXY_SOCK_PATH!r}; ignoring', file=sys.stderr)
    _PROXY_SOCK_PATH = ''

if _PROXY_SOCK_PATH:
    # Fake hostname — urllib3 will try to connect to this; we intercept it.
    _FAKE_HOST = "__sbx_egress__.invalid"

    try:
        import urllib3.util.connection as _uc
        _orig_create_connection = _uc.create_connection

        def _patched_create_connection(address, *args, **kwargs):
            host, port = address
            if host == _FAKE_HOST:
                # Route to egress proxy Unix socket instead of TCP
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect(_PROXY_SOCK_PATH)
                s.settimeout(None)  # restore blocking for actual data transfer
                return s
            return _orig_create_connection(address, *args, **kwargs)

        _uc.create_connection = _patched_create_connection

    except ImportError:
        pass  # urllib3 not available — HTTP_PROXY env var still set below

    # Point HTTP libraries at the fake host — our patch handles the connection
    os.environ["HTTP_PROXY"]  = f"http://{_FAKE_HOST}:80"
    os.environ["HTTPS_PROXY"] = f"http://{_FAKE_HOST}:80"
    os.environ["NO_PROXY"]    = "localhost,127.0.0.1"
    

# ─────────────────────────────────────────────────────────────────────────────
# Step 3+4 — Import user code and call the requested function
# ─────────────────────────────────────────────────────────────────────────────

def _inject_db(func, kwargs: dict) -> dict:
    """Add db=<connection> to kwargs if the function declares a `db` parameter."""
    if _db_conn is None:
        return kwargs
    try:
        params = inspect.signature(func).parameters
    except (ValueError, TypeError):
        return kwargs
    if "db" in params:
        kwargs = dict(kwargs)
        kwargs.setdefault("db", _db_conn)
    return kwargs


def main() -> None:
    try:
        import ai_code_sandbox as code

        with open("/sandbox/request.json") as f:
            request = json.load(f)

        func_name = request["function"]
        args      = request.get("args",   [])
        kwargs    = request.get("kwargs", {})

        if request.get("class_name"):
            cls      = getattr(code, request["class_name"])
            instance = cls(
                *request.get("init_args",   []),
                **request.get("init_kwargs", {}),
            )
            func = getattr(instance, func_name)
        else:
            func = getattr(code, func_name)

        kwargs = _inject_db(func, kwargs)
        result = func(*args, **kwargs)
        print(f"__RESULT__:{json.dumps(result)}")

    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
