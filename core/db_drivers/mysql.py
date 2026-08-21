"""
core.db_drivers.mysql
======================

MySQL / MariaDB v10 wire-protocol driver.

Supports:
  - HandshakeV10 negotiation
  - `mysql_native_password` (MySQL 5.7 default, MariaDB default)
  - `caching_sha2_password` (MySQL 8.0 default) - fast path AND full-auth
    fallback (cleartext over TLS, per MySQL server behavior on cold cache)
  - AuthSwitchRequest handling
  - Optional TLS upgrade via `SSLRequest` packet before HandshakeResponse41
  - COM_QUERY and COM_STMT_PREPARE SQL firewall via sqlglot(read="mysql")
  - MySQL-specific dangerous-clause blocklist:
        LOAD_FILE(), SLEEP(), BENCHMARK(), GET_LOCK()
        INTO OUTFILE / INTO DUMPFILE (data exfil)
        LOAD DATA [LOCAL] INFILE (client-side file read escape)
        HANDLER (row-locked cursor bypass)

The credential substitution model matches the Postgres driver: the sandbox
sends its own HandshakeResponse41 (which the proxy discards), and the proxy
builds a fresh HandshakeResponse41 to the upstream server using the real
password from `os.environ[password_env]`.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import ssl
import struct
from typing import Dict, List, Optional, Tuple

try:
    import sqlglot
    import sqlglot.expressions as exp
except ImportError:  # pragma: no cover
    sqlglot = None  # type: ignore

from .base import DBDriver
from ._limits import (
    MAX_CLIENT_PACKET_BYTES,
    MAX_SERVER_PACKET_BYTES,
    OversizedPacketError,
)
from ._sql_parse import parse_with_timeout, SQLParseTimeout
from .postgres import build_ssl_context  # driver-neutral TLS builder
_CLIENT_LOCAL_FILES                  = 0x00000080

log = logging.getLogger("db_proxy.mysql")


# ===========================================================================
# Protocol constants
# ===========================================================================

# Capability flags (subset we need)
CLIENT_LONG_PASSWORD                 = 0x00000001
CLIENT_LONG_FLAG                     = 0x00000004
CLIENT_CONNECT_WITH_DB               = 0x00000008
CLIENT_PROTOCOL_41                   = 0x00000200
CLIENT_SSL                           = 0x00000800
CLIENT_TRANSACTIONS                  = 0x00002000
CLIENT_SECURE_CONNECTION             = 0x00008000
CLIENT_MULTI_STATEMENTS              = 0x00010000
CLIENT_MULTI_RESULTS                 = 0x00020000
CLIENT_PLUGIN_AUTH                   = 0x00080000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
CLIENT_DEPRECATE_EOF                 = 0x01000000

# Base capabilities we advertise upstream. Response-format flags
# (CLIENT_DEPRECATE_EOF, CLIENT_MULTI_RESULTS) are NOT set here — they
# are mirrored from the sandbox client's HandshakeResponse41 so the
# server emits the packet format the client actually understands.
_UPSTREAM_CAPS_BASE = (
    CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
)

# Response packet type bytes
_PKT_OK   = 0x00
_PKT_EOF  = 0xFE
_PKT_ERR  = 0xFF
_PKT_AUTH_SWITCH   = 0xFE  # (distinguished from EOF by length)
_PKT_AUTH_MORE     = 0x01

# caching_sha2_password AuthMoreData signals
_CSHA2_FAST_AUTH_OK      = 0x03
_CSHA2_FULL_AUTH_NEEDED  = 0x04

# Client commands we care about
_COM_QUERY         = 0x03
_COM_STMT_PREPARE  = 0x16
_COM_QUIT          = 0x01

_MAX_PAYLOAD = 100 * 1024  # 100 KB firewall cap


# ===========================================================================
# Packet framing (MySQL: 3-byte LE length + 1-byte seq_id + payload)
# ===========================================================================

async def read_packet(
    reader: asyncio.StreamReader,
    max_len: int = MAX_CLIENT_PACKET_BYTES,
) -> Tuple[int, bytes]:
    """Read one MySQL packet. Returns (seq_id, payload).

    Enforces `max_len`: a client packet whose declared length exceeds the
    cap raises `OversizedPacketError` before `readexactly` allocates the
    buffer. This is the first line of defence against a wire-length DoS
    (a 24-bit length can request up to ~16 MiB per frame).
    """
    header = await reader.readexactly(4)
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    seq_id = header[3]
    if length > max_len:
        raise OversizedPacketError("client", length, max_len)
    payload = await reader.readexactly(length) if length else b""
    return seq_id, payload


def build_packet(seq_id: int, payload: bytes) -> bytes:
    """Wrap payload with a MySQL packet header."""
    length = len(payload)
    return bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, seq_id & 0xFF]) + payload


def _read_null_str(buf: bytes, off: int) -> Tuple[bytes, int]:
    end = buf.index(b"\x00", off)
    return buf[off:end], end + 1


def _read_lenenc_int(buf: bytes, off: int) -> Tuple[int, int]:
    b = buf[off]
    if b < 0xFB:
        return b, off + 1
    if b == 0xFC:
        return int.from_bytes(buf[off + 1:off + 3], "little"), off + 3
    if b == 0xFD:
        return int.from_bytes(buf[off + 1:off + 4], "little"), off + 4
    if b == 0xFE:
        return int.from_bytes(buf[off + 1:off + 9], "little"), off + 9
    raise ValueError(f"invalid lenenc marker {b:#x}")


def _write_lenenc_str(s: bytes) -> bytes:
    n = len(s)
    if n < 0xFB:
        return bytes([n]) + s
    if n < (1 << 16):
        return bytes([0xFC]) + n.to_bytes(2, "little") + s
    if n < (1 << 24):
        return bytes([0xFD]) + n.to_bytes(3, "little") + s
    return bytes([0xFE]) + n.to_bytes(8, "little") + s


# ===========================================================================
# Auth scramble math
# ===========================================================================

def scramble_native(password: bytes, seed: bytes) -> bytes:
    """`mysql_native_password`:
        SHA1(password) XOR SHA1( seed + SHA1( SHA1(password) ) )

    Returns 20-byte token. Empty password -> empty token."""
    if not password:
        return b""
    sha1_pw = hashlib.sha1(password).digest()
    sha1_sha1_pw = hashlib.sha1(sha1_pw).digest()
    seeded = hashlib.sha1(seed + sha1_sha1_pw).digest()
    return bytes(a ^ b for a, b in zip(sha1_pw, seeded))


def scramble_sha256(password: bytes, seed: bytes) -> bytes:
    """`caching_sha2_password` (fast-auth token):
        SHA256(password) XOR SHA256( SHA256(SHA256(password)) + seed )

    Returns 32-byte token. Empty password -> empty token."""
    if not password:
        return b""
    sha_pw = hashlib.sha256(password).digest()
    sha_sha_pw = hashlib.sha256(sha_pw).digest()
    seeded = hashlib.sha256(sha_sha_pw + seed).digest()
    return bytes(a ^ b for a, b in zip(sha_pw, seeded))


# ===========================================================================
# HandshakeV10 parser
# ===========================================================================

class HandshakeV10:
    __slots__ = ("protocol_version", "server_version", "connection_id",
                 "capabilities", "charset", "status", "auth_plugin_name",
                 "auth_data")

    def __init__(self, payload: bytes) -> None:
        if not payload or payload[0] != 0x0A:
            raise ValueError(f"unexpected handshake protocol version {payload[:1]!r}")
        self.protocol_version = 10
        server_version, off = _read_null_str(payload, 1)
        self.server_version = server_version.decode("utf-8", errors="replace")
        self.connection_id = int.from_bytes(payload[off:off + 4], "little")
        off += 4
        salt1 = payload[off:off + 8]
        off += 8
        off += 1  # filler
        cap_lo = int.from_bytes(payload[off:off + 2], "little")
        off += 2
        self.charset = 0
        self.status = 0
        self.capabilities = cap_lo
        auth_data_len = 8
        salt2 = b""
        if off < len(payload):
            self.charset = payload[off]
            off += 1
            self.status = int.from_bytes(payload[off:off + 2], "little")
            off += 2
            cap_hi = int.from_bytes(payload[off:off + 2], "little")
            off += 2
            self.capabilities |= (cap_hi << 16)
            if self.capabilities & CLIENT_PLUGIN_AUTH:
                auth_data_len = payload[off]
                off += 1
            else:
                off += 1  # filler
            off += 10  # reserved
            if self.capabilities & CLIENT_SECURE_CONNECTION:
                need = max(13, auth_data_len - 8)
                salt2 = payload[off:off + need]
                # trailing NUL if present is not part of scramble
                if salt2.endswith(b"\x00"):
                    salt2 = salt2[:-1]
                off += need
            if self.capabilities & CLIENT_PLUGIN_AUTH:
                plugin, _ = _read_null_str(payload, off)
                self.auth_plugin_name = plugin.decode("utf-8", errors="replace")
            else:
                self.auth_plugin_name = "mysql_native_password"
        else:
            self.auth_plugin_name = "mysql_native_password"

        self.auth_data = (salt1 + salt2)[:20]  # 20-byte scramble seed


# ===========================================================================
# HandshakeResponse41 builder
# ===========================================================================

def build_ssl_request(caps: int, charset: int) -> bytes:
    """SSLRequest packet: 32-byte header, no user/pass, sets CLIENT_SSL bit."""
    caps |= CLIENT_SSL
    payload = (
        caps.to_bytes(4, "little")
        + (0xFFFFFF).to_bytes(4, "little")  # max_packet_size = 16 MiB
        + bytes([charset or 33])
        + b"\x00" * 23
    )
    return payload


def build_handshake_response41(
    user: str,
    password: bytes,
    dbname: str,
    auth_data: bytes,
    auth_plugin: str,
    server_caps: int,
    charset: int,
    client_caps: int = 0,
) -> Tuple[bytes, int]:
    """Return (payload, effective_client_caps).

    Capability negotiation:
      * Start with our driver defaults (`_UPSTREAM_CAPS_BASE`).
      * OR in any *response-format* flags the sandbox client actually
        negotiated (CLIENT_DEPRECATE_EOF, CLIENT_MULTI_RESULTS,
        CLIENT_PS_MULTI_RESULTS) so the row-set framing the client
        expects lines up with what the server emits.
      * Then intersect with what the server offers.
      * CLIENT_SSL is never propagated (proxy owns that hop).
      * CLIENT_LOCAL_FILES is never propagated (LOAD DATA LOCAL is
        blocked at the SQL parser anyway; belt-and-suspenders).
      * CLIENT_MULTI_STATEMENTS is never propagated (one statement per
        packet, matches PG posture)."""
    _MIRROR_FROM_CLIENT = 0x01000000 | CLIENT_MULTI_RESULTS  # DEPRECATE_EOF + MULTI_RESULTS
    caps = _UPSTREAM_CAPS_BASE | (client_caps & _MIRROR_FROM_CLIENT)
    if dbname:
        caps |= CLIENT_CONNECT_WITH_DB
    else:
        caps &= ~CLIENT_CONNECT_WITH_DB
    caps &= ~CLIENT_SSL
    caps &= ~_CLIENT_LOCAL_FILES
    caps &= ~CLIENT_MULTI_STATEMENTS
    # Only negotiate flags the server actually offers
    caps &= server_caps | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH

    if auth_plugin == "mysql_native_password":
        token = scramble_native(password, auth_data)
    elif auth_plugin == "caching_sha2_password":
        token = scramble_sha256(password, auth_data)
    else:
        token = b""

    payload = (
        caps.to_bytes(4, "little")
        + (0xFFFFFF).to_bytes(4, "little")
        + bytes([charset or 33])
        + b"\x00" * 23
        + user.encode("utf-8") + b"\x00"
        + _write_lenenc_str(token)
    )
    if dbname:
        payload += dbname.encode("utf-8") + b"\x00"
    payload += auth_plugin.encode("utf-8") + b"\x00"
    return payload, caps


# ===========================================================================
# SQL firewall
# ===========================================================================

# Belt-and-suspenders regexes: parser-independent block for the most
# dangerous MySQL-only clauses. Case-insensitive, multiline-safe.
_MYSQL_HARD_BLOCK = re.compile(
    r"""(
        \bINTO\s+(OUTFILE|DUMPFILE)\b
      | \bLOAD\s+DATA\s+(LOCAL\s+)?INFILE\b
      | \bHANDLER\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)
_MYSQL_BLOCKED_FUNCS = {
    "LOAD_FILE", "SLEEP", "BENCHMARK",
    "GET_LOCK", "RELEASE_LOCK", "RELEASE_ALL_LOCKS",
    "MASTER_POS_WAIT", "SOURCE_POS_WAIT",
}

# Session-neutral SET statements every MySQL client sends automatically
# right after auth (SET NAMES, autocommit, timezone, isolation level).
# These do NOT change parser semantics — unlike `SET sql_mode` which can
# enable ANSI_QUOTES and flip identifier quoting. The allowlist is a
# STRICT enumeration; everything else that parses as a Command is denied.
_SAFE_SET_RE = re.compile(
    r"""^\s*SET\s+(
           NAMES\s+[A-Za-z0-9_]+(\s+COLLATE\s+[A-Za-z0-9_]+)?
         | CHARACTER\s+SET\s+[A-Za-z0-9_]+
         | (SESSION\s+)?AUTOCOMMIT\s*=\s*[01]
         | (SESSION\s+)?TIME_ZONE\s*=\s*'[^';\\]+'
         | (SESSION\s+)?TRANSACTION\s+ISOLATION\s+LEVEL\s+
              (READ\s+UNCOMMITTED|READ\s+COMMITTED|REPEATABLE\s+READ|SERIALIZABLE)
         | (SESSION\s+)?WAIT_TIMEOUT\s*=\s*\d+
         | (SESSION\s+)?NET_(READ|WRITE)_TIMEOUT\s*=\s*\d+
    )\s*;?\s*$""",
    re.IGNORECASE | re.VERBOSE,
)


def validate_mysql_sql(
    sql: str,
    allowed_tables: Dict[str, List[str]],
    blocked_statements: List[str],
) -> Tuple[bool, str]:
    """Default-deny MySQL SQL firewall (mirror of the PG variant)."""
    if not sqlglot:
        return False, "sqlglot not installed - all queries blocked"

    if len(sql.encode("utf-8")) > _MAX_PAYLOAD:
        return False, "Query payload exceeds maximum allowed size (100KB)"

    m = _MYSQL_HARD_BLOCK.search(sql)
    if m:
        return False, f"Dangerous MySQL clause blocked: {m.group(0).upper()}"

    # Allow a strict enumeration of session-neutral SET commands that
    # every MySQL client sends automatically post-auth. Anything else
    # that parses as a Command is denied below.
    if _SAFE_SET_RE.match(sql):
        return True, "ok"

    try:
        parsed = parse_with_timeout(sql, "mysql")
    except SQLParseTimeout as exc:
        return False, f"SQL parse timeout: {exc}"
    except Exception as exc:
        return False, f"SQL parse error: {exc}"

    blocked_set = {s.upper() for s in blocked_statements}

    for stmt in parsed:
        if stmt is None:
            continue

        if isinstance(stmt, exp.Command):
            return False, "Session manipulation (SET/SHOW/Command) is strictly blocked."

        # Block dangerous functions
        for f in stmt.find_all(exp.Func):
            fname = f.name.upper()
            if fname in _MYSQL_BLOCKED_FUNCS:
                return False, f"MySQL function '{fname}' is blocked."

        # Block INTO OUTFILE / DUMPFILE at AST level too
        into = stmt.args.get("into") if hasattr(stmt, "args") else None
        if into is not None and getattr(into, "name", "").upper() in ("OUTFILE", "DUMPFILE"):
            return False, "INTO OUTFILE/DUMPFILE is blocked."

        stmt_type = stmt.key.upper()
        if stmt_type == "TRUNCATETABLE":
            stmt_type = "TRUNCATE"

        op = stmt_type
        if op in ("UNION", "INTERSECT", "EXCEPT"):
            op = "SELECT"

        if op in blocked_set:
            return False, f"Statement type '{op}' is explicitly blocked."

        if op in ("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "TRANSACTION", "USE"):
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


# ===========================================================================
# Driver
# ===========================================================================

class MySQLDriver(DBDriver):
    name = "mysql"
    default_port = 3306
    default_socket_name = "mysql.sock"

    async def connect_upstream(
        self,
        host: str,
        port: int,
        cfg: Dict,
        timeout: int = 15,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        # MySQL TLS is negotiated INSIDE the handshake (mid-stream STARTTLS),
        # so we open plain TCP here and defer the TLS wrap to intercept_auth.
        return await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

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
            # 1) Server -> HandshakeV10. Rewrite the capability flags before
            #    forwarding to the sandbox: the sandbox<->proxy hop is a local
            #    UNIX socket, so TLS is nonsense; and we never want to advertise
            #    LOAD DATA LOCAL to the sandbox (belt-and-suspenders vs the SQL
            #    firewall's LOAD DATA block). We MUST keep the true capabilities
            #    we saw from the server for our own upstream negotiation.
            seq, payload = await read_packet(server_reader, MAX_SERVER_PACKET_BYTES)
            hs = HandshakeV10(payload)
            sandbox_payload = _strip_caps_for_sandbox(payload)
            client_writer.write(build_packet(seq, sandbox_payload))
            await client_writer.drain()

            # 2) Client -> HandshakeResponse41. Consume and DISCARD its auth
            #    response; we substitute our own using the real password.
            client_seq, client_payload = await read_packet(client_reader)
            user = _extract_response_user(client_payload)
            client_caps = _extract_response_caps(client_payload)
            dbname = cfg.get("dbname", "")
            if not user:
                # Fall back to config-declared user
                user = cfg.get("user", "")
            if not user:
                log.error("MySQL: could not determine user from client packet or config")
                return False

            password = os.environ.get(password_env, "").encode("utf-8")
            if not password:
                log.warning("MySQL: password_env %r is empty; upstream auth will fail", password_env)

            # 3) Optional TLS upgrade to upstream
            use_ssl, ssl_ctx = _resolve_upstream_tls(cfg, hs.capabilities)
            if use_ssl:
                if not (hs.capabilities & CLIENT_SSL):
                    raise ConnectionError(
                        f"Upstream advertises no CLIENT_SSL capability but "
                        f"upstream_ssl_mode={cfg.get('upstream_ssl_mode')!r} demands TLS."
                    )
                ssl_req = build_ssl_request(_UPSTREAM_CAPS_BASE, hs.charset)
                server_writer.write(build_packet(client_seq, ssl_req))
                await server_writer.drain()
                server_reader, server_writer = await _wrap_writer_tls(
                    server_writer, ssl_ctx, cfg.get("upstream_ssl_server_cn") or cfg.get("upstream_host", "")
                )
                # Next packet from real client would collide with client_seq+1;
                # keep the same seq for HandshakeResponse41 as if we hadn't upgraded.
                client_seq += 1
            else:
                log.warning(
                    "MySQL upstream %s:%d over PLAIN TCP - credentials/queries in cleartext. "
                    "Set upstream_ssl_mode=verify-full for production.",
                    cfg.get("upstream_host", ""), int(cfg.get("upstream_port") or 3306),
                )

            # 4) Send our HandshakeResponse41 to the server with the REAL password.
            resp, _ = build_handshake_response41(
                user=user,
                password=password,
                dbname=dbname,
                auth_data=hs.auth_data,
                auth_plugin=hs.auth_plugin_name,
                server_caps=hs.capabilities,
                charset=hs.charset,
                client_caps=client_caps,
            )
            server_writer.write(build_packet(client_seq, resp))
            await server_writer.drain()

            # 5) Drive the auth loop with the server (AuthSwitch, sha2 full auth, OK/ERR).
            ok = await self._drive_server_auth(
                server_reader, server_writer,
                password, hs.auth_data, hs.auth_plugin_name,
            )
            if not ok:
                # Signal the client with a generic ERR packet so it fails cleanly.
                _write_error(client_writer, 1045, "28000", "Access denied via proxy")
                await client_writer.drain()
                return False

            # 6) Tell the client "auth OK" via a synthetic OK packet.
            _write_ok(client_writer, seq_id=2)
            await client_writer.drain()

            # Stash the (possibly upgraded) server streams back for the caller.
            self._server_reader = server_reader
            self._server_writer = server_writer
            return True
        except Exception as e:
            log.error("MySQL auth interception failed: %s", e)
            return False

    async def _drive_server_auth(
        self,
        server_reader: asyncio.StreamReader,
        server_writer: asyncio.StreamWriter,
        password: bytes,
        seed: bytes,
        auth_plugin: str,
    ) -> bool:
        current_plugin = auth_plugin
        current_seed = seed
        while True:
            seq, payload = await read_packet(server_reader, MAX_SERVER_PACKET_BYTES)
            if not payload:
                return False
            marker = payload[0]

            if marker == _PKT_OK:
                return True
            if marker == _PKT_ERR:
                errno = int.from_bytes(payload[1:3], "little")
                msg = payload[3:].decode("utf-8", errors="replace")
                log.warning("MySQL upstream auth ERR %d: %s", errno, msg)
                return False

            if marker == _PKT_AUTH_SWITCH and len(payload) > 1:
                # AuthSwitchRequest: new plugin + fresh seed
                plugin_end = payload.index(b"\x00", 1)
                current_plugin = payload[1:plugin_end].decode("utf-8", errors="replace")
                seed_blob = payload[plugin_end + 1:]
                if seed_blob.endswith(b"\x00"):
                    seed_blob = seed_blob[:-1]
                current_seed = seed_blob[:20]
                if current_plugin == "mysql_native_password":
                    token = scramble_native(password, current_seed)
                elif current_plugin == "caching_sha2_password":
                    token = scramble_sha256(password, current_seed)
                else:
                    log.warning("MySQL: unsupported auth plugin %r", current_plugin)
                    return False
                server_writer.write(build_packet(seq + 1, token))
                await server_writer.drain()
                continue

            if marker == _PKT_AUTH_MORE and current_plugin == "caching_sha2_password":
                if len(payload) < 2:
                    return False
                signal = payload[1]
                if signal == _CSHA2_FAST_AUTH_OK:
                    # Server will send OK next
                    continue
                if signal == _CSHA2_FULL_AUTH_NEEDED:
                    # Full auth would transmit the cleartext password. MySQL's
                    # protocol only makes this safe when the upstream socket is
                    # already TLS-wrapped (or a local UNIX socket, which the
                    # proxy never uses for upstream). We REFUSE cleartext full-
                    # auth outright rather than log-and-continue — the operator
                    # must either enable upstream TLS or prewarm the server's
                    # auth cache with a TLS-capable client so subsequent proxy
                    # connections hit fast-auth (0x03).
                    if not isinstance(
                        server_writer.get_extra_info("ssl_object"),
                        ssl.SSLObject,
                    ):
                        log.error(
                            "caching_sha2_password full-auth requested on a "
                            "non-TLS upstream socket — refusing to send the "
                            "cleartext password. Fix: set "
                            "upstream_ssl_mode=verify-full (or verify-ca) in "
                            "the DB connection policy, or prewarm the server's "
                            "auth cache out-of-band."
                        )
                        return False
                    server_writer.write(build_packet(seq + 1, password + b"\x00"))
                    await server_writer.drain()
                    continue
                return False

            log.warning("MySQL: unexpected packet marker 0x%02x during auth", marker)
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

        # Route to the (possibly TLS-upgraded) server writer captured in auth
        server_writer = getattr(self, "_server_writer", server_writer)

        while True:
            try:
                seq, payload = await read_packet(client_reader)
            except asyncio.IncompleteReadError:
                return
            except OversizedPacketError as exc:
                log.warning("MySQL frame dropped: %s", exc)
                _write_error(
                    client_writer, 1153, "S1000",
                    f"Packet too large (limit {exc.limit}B)", seq_id=1,
                )
                await client_writer.drain()
                client_writer.close()
                return
            if not payload:
                server_writer.write(build_packet(seq, payload))
                await server_writer.drain()
                continue

            cmd = payload[0]

            if cmd == _COM_QUIT:
                server_writer.write(build_packet(seq, payload))
                await server_writer.drain()
                return

            if cmd in (_COM_QUERY, _COM_STMT_PREPARE):
                sql = payload[1:].decode("utf-8", errors="replace")
                allowed, reason = validate_mysql_sql(sql, allowed_tables, blocked_statements)
                if not allowed:
                    log.warning("Blocked MySQL query [cmd=0x%02x]: %s - %s",
                                cmd, sql[:120], reason)
                    _write_error(client_writer, 1142, "42000",
                                 f"Query blocked by proxy: {reason}",
                                 seq_id=seq + 1)
                    await client_writer.drain()
                    client_writer.close()
                    return
                log.debug("Allowed MySQL query [cmd=0x%02x]: %s", cmd, sql[:80])

            server_writer.write(build_packet(seq, payload))
            await server_writer.drain()

    def validate_action(self, action, policy: Dict) -> Tuple[bool, str]:
        """`action` is the SQL string."""
        return validate_mysql_sql(
            action,
            policy.get("allowed_tables", {}),
            policy.get("blocked_statements", []),
        )

    # Server streams the driver upgraded during TLS negotiation. Populated by
    # intercept_auth so filter_client_frames uses the correct writer.
    _server_reader: Optional[asyncio.StreamReader] = None
    _server_writer: Optional[asyncio.StreamWriter] = None


# ===========================================================================
# Helpers
# ===========================================================================

# HandshakeV10 layout (bytes we need to touch):
#   [0]         protocol version (0x0a)
#   [1..]       server_version cstring
#   +4          connection_id
#   +8          salt1
#   +1          filler
#   +2  <-- capability_flags_lo  (CLIENT_SSL is here, bit 11)
#   +1          charset
#   +2          status
#   +2  <-- capability_flags_hi


def _strip_caps_for_sandbox(payload: bytes) -> bytes:
    """Return the HandshakeV10 payload with sandbox-facing caps rewritten.

    Cleared flags:
      * CLIENT_SSL         - sandbox<->proxy hop is a local UNIX socket
                             (TLS would just fail; clients otherwise try
                             to upgrade and error).
      * CLIENT_LOCAL_FILES - defence-in-depth against LOAD DATA LOCAL
                             INFILE (already blocked at SQL parse).

    Everything else is preserved so the client's auth-plugin selection
    still matches what our upstream negotiation expects."""
    try:
        server_version_end = payload.index(b"\x00", 1)
    except ValueError:
        return payload  # malformed - forward unchanged, upstream will reject
    lo_off = server_version_end + 1 + 4 + 8 + 1
    if lo_off + 2 > len(payload):
        return payload
    lo = int.from_bytes(payload[lo_off:lo_off + 2], "little")
    lo &= ~(CLIENT_SSL & 0xFFFF)
    lo &= ~(_CLIENT_LOCAL_FILES & 0xFFFF)
    return payload[:lo_off] + lo.to_bytes(2, "little") + payload[lo_off + 2:]


def _extract_response_user(payload: bytes) -> str:
    """Pull the `user` cstring out of a HandshakeResponse41 payload."""
    try:
        off = 32   # caps(4) + max_packet(4) + charset(1) + reserved(23)
        end = payload.index(b"\x00", off)
        return payload[off:end].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_response_caps(payload: bytes) -> int:
    """Read the 4-byte little-endian capability flags the client sent in its
    HandshakeResponse41. Used to mirror the client's response-format choices
    (notably CLIENT_DEPRECATE_EOF) so packet framing agrees end-to-end."""
    if len(payload) < 4:
        return 0
    return int.from_bytes(payload[:4], "little")


def _write_ok(writer: asyncio.StreamWriter, seq_id: int = 2) -> None:
    # Minimal OK packet: 0x00 affected_rows(lenenc=0) last_insert_id(lenenc=0)
    # status_flags(2) warnings(2)
    ok = bytes([_PKT_OK, 0x00, 0x00]) + b"\x02\x00\x00\x00"
    writer.write(build_packet(seq_id, ok))


def _write_error(writer: asyncio.StreamWriter, errno: int, sqlstate: str, msg: str,
                 seq_id: int = 2) -> None:
    body = (
        bytes([_PKT_ERR])
        + errno.to_bytes(2, "little")
        + b"#" + sqlstate.encode("ascii")[:5].ljust(5, b" ")
        + msg.encode("utf-8", errors="replace")
    )
    writer.write(build_packet(seq_id, body))


def _resolve_upstream_tls(cfg: Dict, server_caps: int) -> Tuple[bool, Optional[ssl.SSLContext]]:
    """Decide whether to negotiate TLS to the upstream MySQL server.

    Fail-closed policy (parity with the Postgres driver):
      - Explicit opt-out: `upstream_ssl_mode == "disable"` OR
        `upstream_ssl is False`. Only these two disable TLS.
      - Any other config (including omitted fields) demands TLS. If the
        server does not advertise CLIENT_SSL, `intercept_auth` will raise
        rather than silently downgrade.
    """
    mode = (cfg.get("upstream_ssl_mode") or "").strip().lower()
    if mode == "disable" or cfg.get("upstream_ssl") is False:
        return False, None
    return True, build_ssl_context(cfg)


async def _wrap_writer_tls(
    writer: asyncio.StreamWriter,
    ssl_ctx: ssl.SSLContext,
    server_hostname: str,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Upgrade an existing asyncio stream to TLS in-place (mid-stream STARTTLS).

    Requires Python 3.11+ (start_tls on the transport). Reads from the new
    reader continue where the plaintext read left off."""
    transport = writer.transport
    loop = asyncio.get_running_loop()
    new_reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(new_reader, loop=loop)
    new_transport = await loop.start_tls(
        transport, protocol, ssl_ctx,
        server_hostname=server_hostname or None,
        server_side=False,
    )
    new_writer = asyncio.StreamWriter(new_transport, protocol, new_reader, loop)
    return new_reader, new_writer
