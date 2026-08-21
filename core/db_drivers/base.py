"""
core.db_drivers.base
=====================

Abstract interface every DB proxy driver implements.

The proxy skeleton in `core.db_proxy` is intentionally protocol-agnostic:
it owns the UNIX-socket listener, connection lifecycle, and shutdown/logging,
and delegates all wire-format work to a `DBDriver` implementation.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple


class DBDriver(ABC):
    """
    Protocol-specific driver plugin.

    Lifecycle per client connection (owned by `DBProxy.handle_client`):
        1. `connect_upstream()`   - open TCP (+ optional TLS) to real DB.
        2. `intercept_auth()`     - mediate login handshake; rewrite any
                                    credential the sandbox tried to send
                                    with the real one from `password_env`.
        3. `filter_client_frames()` - loop reading client frames, validate
                                     each via `validate_action()`, forward
                                     to server or close on deny.

    Concurrent server->client relay is a plain byte copy owned by the
    proxy skeleton (results never need firewalling).
    """

    # ---- driver identity -------------------------------------------------
    name: str = ""
    """Short lowercase identifier matching the policy's `driver` field."""

    default_port: int = 0
    """Default upstream TCP port when policy omits `upstream_port`."""

    default_socket_name: str = ""
    """Default UNIX socket basename inside `sandbox_mount` (e.g. `.s.PGSQL.5432`)."""

    # ---- lifecycle hooks -------------------------------------------------
    @abstractmethod
    async def connect_upstream(
        self,
        host: str,
        port: int,
        cfg: Dict,
        timeout: int = 15,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a connection to the upstream DB, performing any
        driver-specific TLS negotiation (e.g. Postgres SSLRequest,
        MySQL capability-flag TLS switch, MSSQL PRELOGIN)."""

    @abstractmethod
    async def intercept_auth(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        server_reader: asyncio.StreamReader,
        server_writer: asyncio.StreamWriter,
        cfg: Dict,
        password_env: str,
    ) -> bool:
        """Mediate the login handshake. Returns True on success."""

    @abstractmethod
    async def filter_client_frames(
        self,
        client_reader: asyncio.StreamReader,
        server_writer: asyncio.StreamWriter,
        client_writer: asyncio.StreamWriter,
        policy: Dict,
    ) -> None:
        """Read client frames, validate each, forward on ALLOW, drop on DENY.

        `policy` is the driver-specific policy subtree (for the PG driver
        this contains `allowed_tables` and `blocked_statements`)."""

    @abstractmethod
    def validate_action(
        self,
        action: Any,
        policy: Dict,
    ) -> Tuple[bool, str]:
        """Return (allowed, reason) for a single parsed action.

        `action` is driver-specific: a SQL string for SQL drivers,
        a parsed BSON op for Mongo, a RESP command tuple for Redis, etc.
        Kept public so callers (benchmarks, tests) can exercise policy
        logic without spinning up a real socket."""
