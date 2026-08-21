"""
Bounded sqlglot parser shared across drivers.

`sqlglot.parse` can spend significant CPU on pathological input — deeply
nested UNIONs, WITH RECURSIVE cycles, or huge IN lists — even when the
payload fits inside the 100 KiB firewall cap. Because the proxy is single-
threaded per connection, a slow parse blocks every subsequent query on
that same UNIX socket.

`parse_with_timeout` runs `sqlglot.parse` on a small process-wide thread
pool with a hard wall-clock timeout. Timeouts raise `SQLParseTimeout`
which callers translate into a driver-native ERROR (SQLSTATE 42501 for
PG, error 1064 for MySQL) so the client sees a clean "blocked" message
rather than a hung connection.

Rationale for a shared executor rather than one-per-call:
  * `ThreadPoolExecutor.__init__` is not free (thread startup cost).
  * We cap workers so a burst of expensive parses cannot fork-bomb the
    proxy's thread table.
  * The executor is module-global and picked up by every driver.
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutureTimeout
from typing import Any, List, Optional

try:
    import sqlglot
except ImportError:  # pragma: no cover - proxy refuses to start without sqlglot
    sqlglot = None  # type: ignore

log = logging.getLogger("db_proxy.sql_parse")


class SQLParseTimeout(Exception):
    """Raised when `sqlglot.parse` exceeds the configured wall-clock budget."""


# Bounded thread pool — even under adversarial load, at most this many
# parses run in parallel. Excess parses queue and receive their own
# timeout deadlines. Chosen small: parses are CPU-bound and the proxy
# process is not a compute server.
_MAX_PARSE_WORKERS = 4
_DEFAULT_PARSE_TIMEOUT_SEC = 1.0

_executor_lock = threading.Lock()
_executor: Optional[ThreadPoolExecutor] = None


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is not None:
        return _executor
    with _executor_lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=_MAX_PARSE_WORKERS,
                thread_name_prefix="sqlglot-parse",
            )
    return _executor


def parse_with_timeout(
    sql: str,
    dialect: str,
    *,
    timeout: float = _DEFAULT_PARSE_TIMEOUT_SEC,
) -> List[Any]:
    """Parse `sql` under `dialect` with a hard `timeout` (seconds).

    Raises:
        SQLParseTimeout           — parser exceeded the timeout budget.
        sqlglot.errors.ParseError — sqlglot's own parse failure.
        RuntimeError              — sqlglot not installed.
    """
    if sqlglot is None:
        raise RuntimeError("sqlglot is not installed — DB proxy cannot parse SQL")

    future = _get_executor().submit(sqlglot.parse, sql, read=dialect)
    try:
        return future.result(timeout=timeout)
    except _FutureTimeout:
        # We cannot forcibly kill the parser thread in CPython; the worker
        # will eventually finish and free its slot. Timeout is what the
        # caller cares about: the CONNECTION doesn't wait any longer.
        # Log the offending query so operators can add specific blocks.
        log.warning(
            "sqlglot.parse exceeded %.2fs on %s dialect (query prefix=%r)",
            timeout, dialect, sql[:120],
        )
        raise SQLParseTimeout(
            f"SQL parse exceeded {timeout}s budget"
        ) from None


def shutdown() -> None:
    """Best-effort executor teardown. Safe to call at proxy shutdown."""
    global _executor
    with _executor_lock:
        if _executor is not None:
            _executor.shutdown(wait=False, cancel_futures=True)
            _executor = None
