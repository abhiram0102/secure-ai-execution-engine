"""
db_proxy.py
Database Proxy (SQL Firewall) - driver-neutral skeleton.

Architecture:
  Sandbox (bwrap)                   Host side (db_proxy)
  -----------------                 -------------------------------------------
  DB client library                 Listens on UNIX socket: <sandbox_mount>/<sock>
    PGHOST=/tmp/pg  --- wire ----> Selects driver plugin from policy
                                        - driver.connect_upstream()  (TCP + TLS)
                                        - driver.intercept_auth()    (rewrite creds)
                                        - driver.filter_client_frames() (allowlist)
                                        v
                                    Upstream DB: db.host.example:<port>

The sandbox side never changes. All protocol- and dialect-specific work
lives in `core.db_drivers.<name>`; this module only owns the UNIX-socket
lifecycle, connection wiring, and shutdown.

Policy connection config (v2, driver-neutral):
  {
    "name":              "primary",
    "driver":            "postgres",          # NEW - selects plugin
    "sandbox_mount":     "/tmp/pg",           # where proxy listens
    "listen_socket":     "/tmp/pg/.s.PGSQL.5432",  # optional override
    "upstream_host":     "db.example.com",
    "upstream_port":     5432,                # defaulted from driver if unset
    "upstream_ssl":      true,
    "upstream_ssl_verify": true,
    "upstream_ssl_mode": "verify-full",
    "upstream_ssl_ca_path": "...",
    "upstream_ssl_client_cert_path": "...",
    "upstream_ssl_client_key_path":  "...",
    "upstream_ssl_server_cn": "...",
    "password_env":      "BWRAP_DB_PASS",
    "allowed_tables":    { ... },             # driver-specific policy shape
    "blocked_statements":[ ... ]
  }

Legacy policies without a `driver` field default to "postgres" for
back-compat.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from typing import Dict, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.policy_loader import PolicyLoader

from core.db_drivers import DBDriver, load as load_driver
from core.db_drivers.postgres import build_ssl_context as _build_ssl_context  # used by tests/test_db_proxy_tls.py

log = logging.getLogger("db_proxy")
BUFFER_SIZE = 65536


# ===========================================================================
# Byte relay (driver-neutral)
# ===========================================================================

async def _relay(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """Blindly copy bytes from reader -> writer until EOF."""
    try:
        while True:
            chunk = await reader.read(BUFFER_SIZE)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
        pass


# ===========================================================================
# DB Proxy - driver-neutral connection multiplexer
# ===========================================================================

class DBProxy:
    """
    Driver-agnostic connection handler. Delegates all wire-format work to
    the configured `DBDriver` plugin.

    The constructor keeps the legacy positional signature for back-compat
    with existing callers/tests; `driver` may be passed by keyword.
    """

    def __init__(
        self,
        allowed_tables: Dict,
        blocked_statements,
        conn_cfg: Dict,
        timeout: int = 15,
        password_env: str = "",
        driver: Optional[DBDriver] = None,
    ) -> None:
        self.allowed_tables     = allowed_tables
        self.blocked_statements = [s.upper() for s in blocked_statements]
        self.conn_cfg           = conn_cfg
        self.timeout            = timeout
        self.password_env       = password_env
        self.driver             = driver or load_driver(conn_cfg.get("driver", "postgres"))
        self.upstream_host      = conn_cfg.get("upstream_host") or conn_cfg.get("host", "")
        self.upstream_port      = int(conn_cfg.get("upstream_port") or conn_cfg.get("port") or self.driver.default_port)

    async def handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        server_writer: Optional[asyncio.StreamWriter] = None
        try:
            server_reader, server_writer = await self.driver.connect_upstream(
                self.upstream_host,
                self.upstream_port,
                self.conn_cfg,
                self.timeout,
            )

            ok = await self.driver.intercept_auth(
                client_reader, client_writer,
                server_reader, server_writer,
                self.conn_cfg, self.password_env,
            )
            if not ok:
                return

            policy = {
                "allowed_tables":     self.allowed_tables,
                "blocked_statements": self.blocked_statements,
            }
            await asyncio.gather(
                self.driver.filter_client_frames(
                    client_reader, server_writer, client_writer, policy
                ),
                _relay(server_reader, client_writer),
                return_exceptions=True,
            )
        except Exception as exc:
            log.debug("Connection error: %s", exc)
        finally:
            for w in (client_writer, server_writer):
                if w is not None:
                    try:
                        w.close()
                        await w.wait_closed()
                    except Exception:
                        pass


# ===========================================================================
# Startup / entry point
# ===========================================================================

def _resolve_listen_socket(conn: Dict, driver: DBDriver, sandbox_mount: str) -> str:
    """Pick the UNIX socket path this proxy listens on."""
    explicit = conn.get("listen_socket")
    if sandbox_mount:
        return os.path.join(sandbox_mount, driver.default_socket_name)
    if explicit:
        os.makedirs(os.path.dirname(explicit), exist_ok=True)
        return explicit
    mount = conn.get("sandbox_mount", "/tmp/pg")
    os.makedirs(mount, exist_ok=True)
    return os.path.join(mount, driver.default_socket_name)


async def run_proxy(policy_path: str, sandbox_mount: str = "") -> None:
    loader = PolicyLoader(policy_path)
    policy = loader.load()

    db_cfg = policy.get("database", {})
    if not db_cfg.get("enabled", False):
        log.info("Database access disabled in policy. DB proxy not started.")
        return

    # Connection details from env — policy provides which connection + what's allowed
    conn_name = db_cfg.get("connection", "primary")
    conn      = PolicyLoader.load_connection_from_env(conn_name)
    conn["allowed_tables"]     = db_cfg.get("allowed_tables", {})
    conn["blocked_statements"] = db_cfg.get("blocked_statements", [])

    driver_name   = conn.get("driver", "postgres")
    driver        = load_driver(driver_name)
    upstream_host = conn.get("host", "")
    upstream_port = int(conn.get("port") or driver.default_port)
    timeout       = int(conn.get("timeout", 15))
    password_env  = conn.get("password_env", "")

    if not upstream_host:
        log.error("DB_%s_HOST is not set in environment", conn_name.upper())
        return

    proxy_socket = _resolve_listen_socket(conn, driver, sandbox_mount)
    if os.path.exists(proxy_socket):
        os.remove(proxy_socket)

    proxy = DBProxy(conn["allowed_tables"], conn["blocked_statements"],
                    conn, timeout, password_env, driver=driver)

    server = await asyncio.start_unix_server(proxy.handle_client, path=proxy_socket)
    os.chmod(proxy_socket, 0o666)   # allow sandbox user to connect

    log.info(
        "DB proxy [%s] listening on %s  ->  %s:%d  "
        "(ssl_mode=%s, ssl=%s, verify=%s, timeout=%d)",
        driver.name, proxy_socket, upstream_host, upstream_port,
        conn.get("upstream_ssl_mode", "(legacy)"),
        conn.get("upstream_ssl", True), conn.get("upstream_ssl_verify", True), timeout,
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _shutdown(*args):
        log.info("Shutdown signal received. Closing DB proxy server...")
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _shutdown)
        loop.add_signal_handler(signal.SIGTERM, _shutdown)
    except NotImplementedError:
        # Windows fallback
        signal.signal(signal.SIGINT,  lambda s, f: loop.call_soon_threadsafe(_shutdown))
        signal.signal(signal.SIGTERM, lambda s, f: loop.call_soon_threadsafe(_shutdown))

    async with server:
        shutdown_task = asyncio.create_task(stop_event.wait())
        serve_task    = asyncio.create_task(server.serve_forever())

        await asyncio.wait(
            [shutdown_task, serve_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        if stop_event.is_set():
            log.info("Draining active connections...")
            server.close()
            await server.wait_closed()
            if os.path.exists(proxy_socket):
                os.remove(proxy_socket)
            log.info("DB proxy shut down cleanly.")


def _harden_process() -> None:
    """Best-effort process hardening applied at proxy startup.

    The proxy holds the real DB password in `os.environ` for the lifetime of
    the process. We reduce the blast radius:

      * `PR_SET_DUMPABLE = 0` — the kernel refuses to core-dump the process
        even if it segfaults. Without this, a crash could persist the env
        (and thus the password) to disk.
      * `/proc/<pid>/environ` becomes root-only readable as a side effect of
        DUMPABLE=0 on Linux.

    No-op on non-Linux hosts and on kernels that do not export PR_SET_DUMPABLE
    (silent — this is defence-in-depth, not the primary control).
    """
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        PR_SET_DUMPABLE = 4
        rc = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        if rc != 0:
            log.debug("prctl(PR_SET_DUMPABLE, 0) rc=%d errno=%d",
                      rc, ctypes.get_errno())
    except (OSError, AttributeError):
        pass  # non-Linux or libc missing — best-effort only


def main() -> None:
    parser = argparse.ArgumentParser(description="Bubble-Wrap DB Proxy (driver-plugin)")
    parser.add_argument("--policy",        default="config/sandbox_policy.json")
    parser.add_argument("--sandbox-mount", default="",
                        help="Host path for proxy UNIX socket dir (overrides policy sandbox_mount)")
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    )

    _harden_process()


    asyncio.run(run_proxy(args.policy, args.sandbox_mount))


if __name__ == "__main__":
    main()
