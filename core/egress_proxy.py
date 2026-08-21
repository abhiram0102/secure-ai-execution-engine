"""
egress_proxy.py
Host-side HTTP/HTTPS forward proxy for the sandbox.

The sandbox runs with --unshare-net so it has NO host network access.
Its only outbound path is this proxy, reachable via a Unix socket that is
bind-mounted into the sandbox.  A bridge thread in dispatcher.py listens
on 127.0.0.1:8080 inside the sandbox and forwards over that socket.

Security model (no TLS MITM):
  HTTP  -> full check: SSRF guard + domain + protocol + method + route
  HTTPS CONNECT -> SSRF guard + domain + protocol
    (method/route inside the TLS tunnel cannot be inspected without decryption)

Run:
  python3 core/egress_proxy.py --policy config/sandbox_policy.json \\
                                --socket-path /tmp/egress_abc/proxy.sock
"""

import argparse
import asyncio
import logging
import os
import signal
import ssl
import sys
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.policy_loader import PolicyLoader

log = logging.getLogger("egress_proxy")

from core._ssrf_guard import SSRFBlocked, resolve_public_endpoints

# ===========================================================================
# Policy matching helpers
# ===========================================================================

def _domain_matches(hostname: str, pattern: str) -> bool:
    """Exact match or leading wildcard (*.example.com)."""
    pattern  = pattern.lower()
    hostname = hostname.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname == pattern[2:] or hostname.endswith(suffix)
    return hostname == pattern


def _route_matches(path: str, route_pattern: str) -> bool:
    """* matches any path; prefix* = prefix match; else exact or subpath."""
    if route_pattern in ("*", "/*"):
        return True
    if route_pattern.endswith("*"):
        return path.startswith(route_pattern[:-1])
    return path == route_pattern or path.startswith(route_pattern.rstrip("/") + "/")


def check_policy(
    policy_domains: List[Dict],
    hostname: str,
    method: str,
    path: str,
    protocol: str,
) -> Tuple[bool, str]:
    """Return (allowed, reason).  Empty method/path = skip those checks (CONNECT)."""
    hostname_lower = hostname.lower()
    protocol_lower = protocol.lower()
    method_upper   = method.upper()

    for entry in policy_domains:
        if not _domain_matches(hostname_lower, entry.get("domain", "")):
            continue

        allowed_protocols = [p.lower() for p in entry.get("protocols", ["https"])]
        if protocol_lower not in allowed_protocols:
            return False, (
                f"Protocol {protocol_lower!r} not allowed for {hostname!r}. "
                f"Allowed: {allowed_protocols}"
            )

        if method_upper:
            allowed_methods = [m.upper() for m in entry.get("methods", [])]
            if allowed_methods and method_upper not in allowed_methods:
                return False, (
                    f"Method {method_upper!r} not allowed for {hostname!r}. "
                    f"Allowed: {allowed_methods}"
                )

        if path:
            allowed_routes = entry.get("routes", ["*"])
            if not any(_route_matches(path, r) for r in allowed_routes):
                return False, (
                    f"Route {path!r} not allowed for {hostname!r}. "
                    f"Allowed: {allowed_routes}"
                )

        return True, "ok"

    return False, f"Domain {hostname!r} is not in the allowed list"


# ===========================================================================
# HTTP parsing helpers
# ===========================================================================

async def _read_http_request(
    reader: asyncio.StreamReader,
) -> Tuple[str, Dict[str, str], bytes]:
    """Read one HTTP/1.x request. Returns (request_line, headers, body)."""
    request_line = (await reader.readline()).decode("latin-1").strip()
    headers: Dict[str, str] = {}
    while True:
        line = (await reader.readline()).decode("latin-1").strip()
        if not line:
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    content_length = int(headers.get("Content-Length", headers.get("content-length", 0)))
    body = await reader.readexactly(content_length) if content_length > 0 else b""
    return request_line, headers, body


async def _send_403(writer: asyncio.StreamWriter, reason: str) -> None:
    body = f"403 Forbidden: {reason}\r\n".encode()
    writer.write(
        b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    )
    await writer.drain()


async def _relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy bytes from reader to writer until EOF."""
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass


# ===========================================================================
# Proxy class — forward proxy only (no transparent mode)
# ===========================================================================

class EgressProxy:
    """
    HTTP/HTTPS forward proxy listening on a Unix socket.

    Every connection from the sandbox is a forward-proxy request:
      HTTP  -> absolute URL (GET http://host/path) -> full policy check
      HTTPS -> CONNECT tunnel                       -> domain + protocol check
    """

    def __init__(self, policy_domains: List[Dict]) -> None:
        self.policy_domains = policy_domains
        self._ssl_ctx = ssl.create_default_context()   # created once, reused per-connection

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await self._dispatch(reader, writer)
        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
            pass
        except Exception as exc:
            log.debug("Proxy exception: %s", exc, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line, headers, body = await asyncio.wait_for(
                _read_http_request(reader), timeout=10.0
            )
        except Exception as exc:
            log.debug("Failed to read request: %s", exc)
            return

        parts = request_line.split(" ", 2)
        if len(parts) < 2:
            return
        method, url = parts[0], parts[1]

        if method.upper() == "CONNECT":
            await self._handle_connect(url, reader, writer)
        else:
            await self._handle_http(method, url, headers, body, writer)

    async def _handle_http(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: bytes,
        writer: asyncio.StreamWriter,
    ) -> None:
        parsed   = urlparse(url)
        hostname = parsed.hostname or headers.get("host", "").split(":")[0]
        path     = parsed.path or "/"
        protocol = parsed.scheme or "http"
        port     = parsed.port or (443 if protocol == "https" else 80)

        allowed, reason = check_policy(
            self.policy_domains, hostname, method, path, protocol
        )
        self._log(allowed, method, protocol, hostname, path)
        if not allowed:
            await _send_403(writer, reason)
            return

        try:
            endpoints = await resolve_public_endpoints(hostname, port)
        except SSRFBlocked as blocked:
            await _send_403(writer, str(blocked))
            return

        origin_r = origin_w = None
        for _family, ip, prt in endpoints:
            try:
                if protocol == "https":
                    origin_r, origin_w = await asyncio.open_connection(
                        ip, prt,
                        ssl=self._ssl_ctx,
                        server_hostname=hostname,
                    )
                else:
                    origin_r, origin_w = await asyncio.open_connection(ip, prt)
                break
            except Exception:
                continue

        if origin_w is None:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return

        try:
            path_qs = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
            req = f"{method} {path_qs} HTTP/1.1\r\n"
            for k, v in headers.items():
                if k.lower() in ("proxy-connection", "proxy-authorization"):
                    continue
                req += f"{k}: {v}\r\n"
            req += "\r\n"
            origin_w.write(req.encode("latin-1") + body)
            await origin_w.drain()
            await asyncio.gather(_relay(origin_r, writer), return_exceptions=True)
        finally:
            try:
                origin_w.close()
                await origin_w.wait_closed()
            except Exception:
                pass

    async def _handle_connect(
        self,
        target: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """HTTPS CONNECT tunnel — domain + protocol enforced; content opaque."""
        hostname, _, port_str = target.rpartition(":")
        port = int(port_str) if port_str.isdigit() else 443
        protocol = "https" if port != 80 else "http"

        allowed, reason = check_policy(
            self.policy_domains, hostname, "", "", protocol
        )
        self._log(allowed, "CONNECT", protocol, hostname, "/")
        if not allowed:
            await _send_403(writer, reason)
            return

        try:
            endpoints = await resolve_public_endpoints(hostname, port)
        except SSRFBlocked as blocked:
            await _send_403(writer, str(blocked))
            return

        origin_r = origin_w = None
        for _family, ip, prt in endpoints:
            try:
                origin_r, origin_w = await asyncio.open_connection(ip, prt)
                break
            except Exception:
                continue

        if origin_w is None:
            await _send_403(writer, f"Cannot connect to {hostname}:{port}")
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        try:
            await asyncio.gather(
                _relay(reader, origin_w),
                _relay(origin_r, writer),
                return_exceptions=True,
            )
        finally:
            try:
                origin_w.close()
                await origin_w.wait_closed()
            except Exception:
                pass

    @staticmethod
    def _log(allowed: bool, method: str, protocol: str, host: str, path: str) -> None:
        status = "ALLOW" if allowed else "DENY "
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        log.info("[%s] %s  %-7s  %s://%s%s", ts, status, method, protocol, host, path)


# ===========================================================================
# Entry point — Unix socket only
# ===========================================================================

async def run_proxy(policy_path: str, socket_path: str) -> None:
    loader = PolicyLoader(policy_path)
    policy = loader.load()

    net = policy.get("network", {})
    if not net.get("enabled", False):
        log.info("Network disabled in policy — egress proxy not started.")
        return

    domains = net.get("allowed_domains", [])
    proxy   = EgressProxy(domains)

    # Ensure socket dir exists and remove stale socket
    parent = os.path.dirname(socket_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    if os.path.exists(socket_path):
        os.remove(socket_path)

    server = await asyncio.start_unix_server(proxy.handle, path=socket_path)
    os.chmod(socket_path, 0o666)
    log.info("Egress proxy listening on Unix socket %s", socket_path)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _shutdown(*_):
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT,  _shutdown)
        loop.add_signal_handler(signal.SIGTERM, _shutdown)
    except NotImplementedError:
        signal.signal(signal.SIGTERM, lambda *_: loop.call_soon_threadsafe(_shutdown))
        signal.signal(signal.SIGINT,  lambda *_: loop.call_soon_threadsafe(_shutdown))

    async with server:
        await asyncio.wait(
            [
                asyncio.create_task(stop_event.wait()),
                asyncio.create_task(server.serve_forever()),
            ],
            return_when=asyncio.FIRST_COMPLETED,
        )
        server.close()
        await server.wait_closed()
        log.info("Egress proxy shut down cleanly.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bubble-Wrap egress proxy")
    parser.add_argument("--policy",      default="config/sandbox_policy.json")
    parser.add_argument("--socket-path", required=True,
                        help="Unix socket path to listen on")
    parser.add_argument("--log-level",   default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    )
    asyncio.run(run_proxy(args.policy, args.socket_path))


if __name__ == "__main__":
    main()
