"""
core.db_drivers
================

Driver-plugin layer for the Bubble-Wrap DB proxy.

Each driver owns the wire protocol, auth interception, and per-driver
action allowlist for a specific database engine. The proxy skeleton
(`core.db_proxy.DBProxy`) is driver-agnostic and delegates everything
protocol-specific to the driver selected by the policy's
`database.connections[].driver` field.

Ship-in-tree drivers:
    postgres    - PostgreSQL v3 wire protocol (default; back-compat)

Adding a driver:
    1. Subclass `DBDriver` in a new module under `core/db_drivers/`.
    2. Register it in `_DRIVERS` below (or via `register()` at import time).
    3. Extend `config/sandbox_policy.schema.json` with the driver's
       `policy` subshape.
"""

from __future__ import annotations

from typing import Dict, Type

from .base import DBDriver
from .postgres import PostgresDriver
from .mysql import MySQLDriver

_DRIVERS: Dict[str, Type[DBDriver]] = {
    "postgres":   PostgresDriver,
    "postgresql": PostgresDriver,
    "pg":         PostgresDriver,
    "mysql":      MySQLDriver,
    "mariadb":    MySQLDriver,
}


def register(name: str, cls: Type[DBDriver]) -> None:
    """Register a driver class. Names are case-insensitive."""
    _DRIVERS[name.lower()] = cls


def load(name: str) -> DBDriver:
    """
    Instantiate the driver plugin selected by `name`.

    Raises ValueError with the list of available drivers if `name` is unknown,
    so a mistyped policy fails hard at startup rather than silently defaulting.
    """
    key = (name or "postgres").lower()
    cls = _DRIVERS.get(key)
    if cls is None:
        available = ", ".join(sorted(set(_DRIVERS)))
        raise ValueError(
            f"Unknown DB driver {name!r}. Available drivers: {available}"
        )
    return cls()


__all__ = ["DBDriver", "PostgresDriver", "MySQLDriver", "load", "register"]
