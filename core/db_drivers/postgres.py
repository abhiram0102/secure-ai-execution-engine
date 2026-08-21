"""
core.db_drivers.postgres
=========================

PostgreSQL v3 wire-protocol driver.

Owns everything that is Postgres-specific: the SSLRequest handshake,
StartupMessage parsing, MD5 auth interception, `Q`/`P` frame filtering,
sqlglot-based SQL AST validation with the `postgres` dialect, and the
`PG_*` system-function blocklist.

The proxy skeleton in `core.db_proxy` is unaware of any of this.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import socket
import ssl
import struct
from typing import Dict, List, Optional, Tuple

try:
    import sqlglot
    import sqlglot.expressions as exp
except ImportError:  # pragma: no cover - policy blocks all queries without it
    sqlglot = None  # type: ignore

from .base import DBDriver
from ._limits import MAX_CLIENT_PACKET_BYTES, OversizedPacketError
from ._sql_parse import parse_with_timeout, SQLParseTimeout

log = logging.getLogger("db_proxy.postgres")


# PostgreSQL protocol error/severity fields:
#   https://www.postgresql.org/docs/current/protocol-error-fields.html
# 42501 = insufficient_privilege — the closest standard SQLSTATE for
# "proxy refused this action for policy reasons".
_PG_DENY_SQLSTATE = "42501"


def _pg_error_response(reason: str, sqlstate: str = _PG_DENY_SQLSTATE) -> bytes:
    """Build a Postgres v3 ErrorResponse frame.

    Sends a machine-parseable error the client library can surface to its
    caller as a normal database exception (psycopg2 -> OperationalError,
    asyncpg -> InternalServerError). Without this the client sees an
    opaque "server closed the connection" — hard to test against and
    confusing to operators debugging denied queries.
    """
    body = (
        b"S" + b"ERROR\x00"
        + b"V" + b"ERROR\x00"
        + b"C" + sqlstate.encode("ascii") + b"\x00"
        + b"M" + reason.encode("utf-8", errors="replace")[:900] + b"\x00"
        + b"\x00"    # end of fields
    )
    return b"E" + struct.pack("!I", len(body) + 4) + body

# PostgreSQL SSLRequest magic (8-byte message: length=8, code=80877103)
_PG_SSL_REQUEST = struct.pack("!II", 8, 80877103)


# ---------------------------------------------------------------------------
# Shared TLS context builder — driver-neutral but lives here so any TLS-using
# driver can import it. Re-exported from `core.db_proxy` for back-compat with
# existing tests (`from core.db_proxy import _build_ssl_context`).
# ---------------------------------------------------------------------------

def build_ssl_context(cfg: Dict) -> ssl.SSLContext:
    """
    Build an SSLContext from a policy connection dict, honouring:
        upstream_ssl_mode            disable|allow|prefer|require|verify-ca|verify-full
        upstream_ssl_verify          (legacy bool; overridden by mode when both set)
        upstream_ssl_ca_path         path to PEM CA bundle for server verification
        upstream_ssl_client_cert_path / upstream_ssl_client_key_path
                                     mTLS client credentials
        upstream_ssl_server_cn       pinned server CN

    Failure to load any explicitly-configured file raises immediately so a
    misconfigured policy fails hard rather than silently downgrading.
    """
    mode = (cfg.get("upstream_ssl_mode") or "").strip().lower()
    legacy_verify = bool(cfg.get("upstream_ssl_verify", True))

    ca = cfg.get("upstream_ssl_ca_path")
    if ca:
        ctx = ssl.create_default_context(cafile=ca)
    else:
        ctx = ssl.create_default_context()

    cert = cfg.get("upstream_ssl_client_cert_path")
    key = cfg.get("upstream_ssl_client_key_path")
    if cert:
        ctx.load_cert_chain(certfile=cert, keyfile=key or cert)

    if mode == "verify-full":
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif mode == "verify-ca":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
    elif mode in ("require", "prefer", "allow"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif mode == "disable":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        if legacy_verify:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    return ctx


# ---------------------------------------------------------------------------
# SQL firewall (public - kept importable for benchmarks/tests)
# ---------------------------------------------------------------------------

def validate_sql(
    sql: str,
    allowed_tables: Dict[str, List[str]],
    blocked_statements: List[str],
) -> Tuple[bool, str]:
    """
    Default-deny Postgres SQL firewall. See original db_proxy.validate_sql
    for full rule documentation; behavior is unchanged.
    """
    if not sqlglot:
        return False, "sqlglot not installed - all queries blocked"

    if len(sql.encode("utf-8")) > 100000:
        return False, "Query payload exceeds maximum allowed size (100KB)"

    try:
        parsed = parse_with_timeout(sql, "postgres")
    except SQLParseTimeout as exc:
        return False, f"SQL parse timeout: {exc}"
    except Exception as exc:
        return False, f"SQL parse error: {exc}"

    for stmt in parsed:
        if stmt is None:
            continue

        if isinstance(stmt, exp.Command):
            return False, "Session manipulation (SET/SHOW/Command) is strictly blocked."

        for f in stmt.find_all(exp.Func):
            fname = f.name.upper()
            if fname.startswith("PG_"):
                return False, f"Direct access to Postgres system functions ({fname}) is blocked."

        stmt_type = stmt.key.upper()
        if stmt_type == "TRUNCATETABLE":
            stmt_type = "TRUNCATE"

        op = stmt_type
        if op in ("UNION", "INTERSECT", "EXCEPT"):
            op = "SELECT"

        if op in ("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "TRANSACTION"):
            continue

        global_allowed_ops = {o.upper() for ops in allowed_tables.values() for o in ops}
        if op not in global_allowed_ops:
            return False, f"Statement type '{op}' is explicitly blocked (not in allowed list)"

        for table in stmt.find_all(exp.Table):
            tname = table.name
            if tname not in allowed_tables:
                return False, f"Table '{tname}' is not in the allowed list"
            allowed_for_table = [o.upper() for o in allowed_tables[tname]]
            if op not in allowed_for_table:
                return False, (
                    f"Operation '{op}' not permitted on table '{tname}'. "
                    f"Allowed: {allowed_tables[tname]}"
                )

    return True, "ok"


# ---------------------------------------------------------------------------
# Upstream connect (PG SSLRequest handshake + optional TLS wrap)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SASL / SCRAM-SHA-256 helpers (Postgres 14+ default authentication)
# ---------------------------------------------------------------------------

def _parse_sasl_mechanisms(payload: bytes) -> "list[str]":
    """Extract the mechanism list from an AuthenticationSASL body.

    Server body after the 4-byte auth-type = a series of null-terminated
    mechanism strings, ended by an extra NUL."""
    names = []
    for chunk in payload.split(b"\x00"):
        if not chunk:
            continue
        try:
            names.append(chunk.decode("ascii"))
        except UnicodeDecodeError:
            continue
    return names


async def _read_pg_frame(reader: asyncio.StreamReader) -> Tuple[bytes, int, bytes]:
    """Read one v3 frame: (type_byte, msg_len, payload)."""
    type_byte = await reader.readexactly(1)
    msg_len_bytes = await reader.readexactly(4)
    msg_len = struct.unpack("!I", msg_len_bytes)[0]
    if msg_len < 4 or msg_len - 4 > MAX_CLIENT_PACKET_BYTES:
        raise OversizedPacketError("server", msg_len, MAX_CLIENT_PACKET_BYTES)
    payload = await reader.readexactly(msg_len - 4)
    return type_byte, msg_len, payload


async def _run_scram_sha256(
    server_reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter,
    user: str,
    password: str,
) -> bool:
    """Complete the SCRAM-SHA-256 exchange on the upstream socket.

    Returns True on server signature verification; False on any protocol
    or crypto error. This function does NOT touch the client socket —
    the caller controls that. It consumes exactly two `R` frames from
    the server (AuthenticationSASLContinue, AuthenticationSASLFinal).
    """
    from ._scram import ScramClient, ScramError

    client = ScramClient(username=user, password=password)
    client_first = client.build_client_first()

    # SASLInitialResponse ('p'): [mechanism NUL][int32 len][client-first-message]
    mech = b"SCRAM-SHA-256\x00"
    body = mech + struct.pack("!I", len(client_first)) + client_first
    server_writer.write(b"p" + struct.pack("!I", 4 + len(body)) + body)
    await server_writer.drain()

    # Expect AuthenticationSASLContinue (R, code=11) with server-first-message
    try:
        t, _mlen, payload = await _read_pg_frame(server_reader)
    except (asyncio.IncompleteReadError, OversizedPacketError) as exc:
        log.error("SCRAM: failed to read server-first frame: %s", exc)
        return False
    if t != b"R" or len(payload) < 4:
        log.error("SCRAM: expected 'R' frame after client-first, got %r", t)
        return False
    if struct.unpack("!I", payload[:4])[0] != 11:
        log.error("SCRAM: expected SASLContinue (code 11)")
        return False

    server_first = payload[4:]
    try:
        client_final = client.build_client_final(server_first)
    except ScramError as exc:
        log.error("SCRAM client-final failed: %s", exc)
        return False

    # SASLResponse ('p') with client-final
    server_writer.write(
        b"p" + struct.pack("!I", 4 + len(client_final)) + client_final
    )
    await server_writer.drain()

    # Expect AuthenticationSASLFinal (R, code=12) with server signature
    try:
        t, _mlen, payload = await _read_pg_frame(server_reader)
    except (asyncio.IncompleteReadError, OversizedPacketError) as exc:
        log.error("SCRAM: failed to read server-final frame: %s", exc)
        return False
    if t == b"E":
        log.warning("SCRAM: server returned ErrorResponse")
        return False
    if t != b"R" or len(payload) < 4:
        log.error("SCRAM: expected 'R' after client-final, got %r", t)
        return False
    if struct.unpack("!I", payload[:4])[0] != 12:
        log.error("SCRAM: expected SASLFinal (code 12)")
        return False

    try:
        client.verify_server_final(payload[4:])
    except ScramError as exc:
        log.error("SCRAM: server signature verification failed: %s", exc)
        return False

    return True


def _connect_upstream_ssl_sync(host: str, port: int, cfg: Dict, timeout: int = 15) -> socket.socket:
    """Blocking helper: sends PG SSLRequest, then wraps the socket with TLS.

    For 'prefer' and 'allow' modes, falls back to plaintext if the server
    refuses SSL (responds 'N'). For 'require'/'verify-*', raises on refusal.
    """
    mode = (cfg.get("upstream_ssl_mode") or "").strip().lower()
    fallback_ok = mode in ("prefer", "allow")

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(_PG_SSL_REQUEST)
        response = sock.recv(1)
        if response != b"S":
            if fallback_ok:
                # Server doesn't support SSL — fall back to plain TCP
                log.debug("Upstream %s:%d declined SSL (%r); falling back to plaintext (mode=%s)",
                          host, port, response, mode)
                return sock   # return the plain socket, caller uses it directly
            raise ConnectionError(
                f"Upstream {host}:{port} rejected SSL negotiation "
                f"(server responded {response!r}). "
                "Set upstream_ssl_mode=disable if the server cannot do TLS."
            )
        ctx = build_ssl_context(cfg)
        server_cn = cfg.get("upstream_ssl_server_cn") or host
        return ctx.wrap_socket(sock, server_hostname=server_cn)
    except Exception:
        sock.close()
        raise


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

class PostgresDriver(DBDriver):
    name = "postgres"
    default_port = 5432
    default_socket_name = ".s.PGSQL.5432"

    async def connect_upstream(
        self,
        host: str,
        port: int,
        cfg: Dict,
        timeout: int = 15,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        mode = (cfg.get("upstream_ssl_mode") or "").strip().lower()
        use_ssl = cfg.get("upstream_ssl", True)
        if mode == "disable":
            use_ssl = False

        if use_ssl:
            loop = asyncio.get_event_loop()
            raw_sock = await loop.run_in_executor(
                None, _connect_upstream_ssl_sync, host, port, cfg, timeout
            )
            # _connect_upstream_ssl_sync returns either:
            #   • an SSL-wrapped socket (server accepted SSL), or
            #   • a plain socket (server declined, mode is prefer/allow fallback)
            # asyncio.open_connection(sock=...) works for both.
            return await asyncio.open_connection(sock=raw_sock)

        log.warning(
            "DB proxy connecting to %s:%d over PLAIN TCP - credentials and "
            "queries will traverse the wire in cleartext. Set "
            "upstream_ssl_mode=verify-full in the policy for production.",
            host, port,
        )
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)

    async def intercept_auth(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        server_reader: asyncio.StreamReader,
        server_writer: asyncio.StreamWriter,
        cfg: Dict,
        password_env: str,
    ) -> bool:
        try:
            startup_len_bytes = await client_reader.readexactly(4)
            startup_len = struct.unpack("!I", startup_len_bytes)[0]
            if startup_len < 4:
                return False
            if startup_len - 4 > MAX_CLIENT_PACKET_BYTES:
                log.warning(
                    "PG startup payload length %d exceeds cap %d — dropping",
                    startup_len, MAX_CLIENT_PACKET_BYTES,
                )
                return False
            startup_payload = await client_reader.readexactly(startup_len - 4)

            protocol_version = startup_payload[:4]
            if struct.unpack("!I", protocol_version)[0] == 80877103:
                # SSLRequest from sandbox - proxy always replies 'N' (no SSL on
                # the UNIX socket hop; the sandbox<->proxy segment is local).
                client_writer.write(b"N")
                await client_writer.drain()
                startup_len_bytes = await client_reader.readexactly(4)
                startup_len = struct.unpack("!I", startup_len_bytes)[0]
                if startup_len < 4 or startup_len - 4 > MAX_CLIENT_PACKET_BYTES:
                    log.warning(
                        "PG post-SSLRequest startup length %d out of range — dropping",
                        startup_len,
                    )
                    return False
                startup_payload = await client_reader.readexactly(startup_len - 4)

            user = ""
            pairs_data = startup_payload[4:-1]
            parts = pairs_data.split(b"\0")
            for i in range(0, len(parts) - 1, 2):
                if parts[i] == b"user":
                    user = parts[i + 1].decode("utf-8", errors="ignore")

            server_writer.write(startup_len_bytes + startup_payload)
            await server_writer.drain()

            while True:
                type_byte = await server_reader.readexactly(1)
                msg_len_bytes = await server_reader.readexactly(4)
                msg_len = struct.unpack("!I", msg_len_bytes)[0]
                payload = await server_reader.readexactly(msg_len - 4)

                if type_byte == b"R":  # Authentication
                    auth_type = struct.unpack("!I", payload[:4])[0]
                    if auth_type == 0:  # AuthOK
                        client_writer.write(type_byte + msg_len_bytes + payload)
                        await client_writer.drain()
                        break
                    if auth_type == 5:  # MD5Password
                        salt = payload[4:8]
                        pw = os.environ.get(password_env, "")
                        if not pw:
                            log.warning(
                                "Upstream requested MD5 password, but password_env "
                                "is empty or unset on host."
                            )
                            return False
                        m1 = hashlib.md5((pw + user).encode("utf-8")).hexdigest()
                        m2 = hashlib.md5(m1.encode("ascii") + salt).hexdigest()
                        response = b"md5" + m2.encode("ascii") + b"\0"
                        resp_len = 4 + len(response)
                        server_writer.write(b"p" + struct.pack("!I", resp_len) + response)
                        await server_writer.drain()
                        continue
                    if auth_type == 10:  # AuthenticationSASL
                        mechanisms = _parse_sasl_mechanisms(payload[4:])
                        if "SCRAM-SHA-256" not in mechanisms:
                            log.error(
                                "Upstream offers SASL mechanisms %r but "
                                "SCRAM-SHA-256 not among them", mechanisms,
                            )
                            return False
                        pw = os.environ.get(password_env, "")
                        if not pw:
                            log.warning(
                                "Upstream requested SCRAM, but password_env "
                                "%r is empty or unset on host.", password_env,
                            )
                            return False
                        ok = await _run_scram_sha256(
                            server_reader, server_writer, user, pw,
                        )
                        if not ok:
                            return False
                        # After SCRAM completes the server sends
                        # AuthenticationOk on its own; loop back and let
                        # the auth_type == 0 branch forward it.
                        continue
                    log.error("Unsupported auth type from server: %d", auth_type)
                    return False
                elif type_byte == b"E":  # ErrorResponse
                    client_writer.write(type_byte + msg_len_bytes + payload)
                    await client_writer.drain()
                    return False
                else:
                    client_writer.write(type_byte + msg_len_bytes + payload)
                    await client_writer.drain()

            return True
        except Exception as e:
            log.error("Auth interception failed: %s", e)
            return False

    async def filter_client_frames(
        self,
        client_reader: asyncio.StreamReader,
        server_writer: asyncio.StreamWriter,
        client_writer: asyncio.StreamWriter,
        policy: Dict,
    ) -> None:
        allowed_tables = policy.get("allowed_tables", {})
        blocked_statements = policy.get("blocked_statements", [])

        while True:
            type_byte = await client_reader.readexactly(1)
            msg_len_bytes = await client_reader.readexactly(4)
            msg_len = struct.unpack("!I", msg_len_bytes)[0]

            if msg_len < 4:
                log.warning("Malformed message (type=%r, length=%d) - dropping",
                            type_byte, msg_len)
                client_writer.close()
                return
            if msg_len - 4 > MAX_CLIENT_PACKET_BYTES:
                log.warning(
                    "PG client frame type=%r length=%d exceeds cap %d - dropping",
                    type_byte, msg_len, MAX_CLIENT_PACKET_BYTES,
                )
                client_writer.close()
                return

            payload = await client_reader.readexactly(msg_len - 4)
            msg_type = type_byte.decode("ascii", errors="ignore")

            if msg_type in ("Q", "P"):
                sql = self._extract_sql(msg_type, payload)
                if sql is None:
                    log.error("Failed to extract SQL from message type=%r - dropping", msg_type)
                    client_writer.close()
                    return

                allowed, reason = self.validate_action(
                    sql, {"allowed_tables": allowed_tables, "blocked_statements": blocked_statements}
                )
                if not allowed:
                    log.warning("Blocked query [%s]: %s - %s", msg_type, sql[:120], reason)
                    client_writer.write(_pg_error_response(
                        f"Query blocked by proxy: {reason}"
                    ))
                    try:
                        await client_writer.drain()
                    except Exception:
                        pass
                    client_writer.close()
                    return

                log.debug("Allowed query [%s]: %s", msg_type, sql[:80])

            server_writer.write(type_byte + msg_len_bytes + payload)
            await server_writer.drain()

    def validate_action(self, action, policy: Dict) -> Tuple[bool, str]:
        """`action` is the SQL string for this driver."""
        return validate_sql(
            action,
            policy.get("allowed_tables", {}),
            policy.get("blocked_statements", []),
        )

    @staticmethod
    def _extract_sql(msg_type: str, payload: bytes) -> Optional[str]:
        """Extract the SQL string from a Q or P wire protocol payload."""
        try:
            if msg_type == "Q":
                return payload.split(b"\x00")[0].decode("utf-8")
            if msg_type == "P":
                parts = payload.split(b"\x00")
                if len(parts) >= 2:
                    return parts[1].decode("utf-8")
            return None
        except Exception:
            return None
