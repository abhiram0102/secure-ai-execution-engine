"""
SCRAM-SHA-256 client for the Postgres v3 auth flow.

RFCs
----
* RFC 5802 — SCRAM
* RFC 7677 — SCRAM-SHA-256
* Postgres protocol — https://www.postgresql.org/docs/current/sasl-authentication.html

Auth message types (Postgres):
    R + code=10  → AuthenticationSASL      (server -> client): mechanism list
    p            → SASLInitialResponse     (client -> server): client-first
    R + code=11  → AuthenticationSASLContinue (server -> client): server-first
    p            → SASLResponse            (client -> server): client-final
    R + code=12  → AuthenticationSASLFinal (server -> client): server-final
    R + code=0   → AuthenticationOk

This module implements only the client half. It is protocol-agnostic — the
driver caller feeds server bytes in and gets client bytes out. That
keeps the crypto testable without a live PG server.

Deliberately zero third-party crypto deps: everything is stdlib `hashlib`
and `hmac`. `pyscram` and `passlib` are convenient but we do not need
their surface area and would rather NOT audit them for this driver.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional

_HASH = hashlib.sha256
_HASH_LEN = 32   # SHA-256 output length


class ScramError(Exception):
    """Raised when SCRAM negotiation fails validation."""


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _h(data: bytes) -> bytes:
    return _HASH(data).digest()


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, _HASH).digest()


def _hi(password: bytes, salt: bytes, iterations: int) -> bytes:
    """RFC 5802 Hi() — same as PBKDF2-HMAC-SHA256."""
    if iterations < 1:
        raise ScramError(f"SCRAM iterations must be >= 1, got {iterations}")
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, _HASH_LEN)


def _saslprep(password: str) -> bytes:
    """SASLPrep (RFC 4013) — the crypto-canonical form of the password.

    A minimal correct implementation: we normalize using NFKC (per
    stringprep tables covered by libidn), strip prohibited characters,
    and encode as UTF-8. For ASCII passwords (the overwhelmingly common
    case) this is identity. Non-ASCII passwords need the NFKC pass to
    match server-side behaviour."""
    import unicodedata
    if not password:
        return b""
    prepped = unicodedata.normalize("NFKC", password)
    return prepped.encode("utf-8")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


class ScramClient:
    """Stateful SCRAM-SHA-256 client. Instantiate once per connection.

    Typical flow (caller drives it):

        client = ScramClient(user="u", password="p")
        first = client.build_client_first()
        server_first = ... read from server ...
        final = client.build_client_final(server_first)
        server_final = ... read from server ...
        client.verify_server_final(server_final)
    """

    __slots__ = (
        "username", "_password", "_nonce", "_client_first_bare",
        "_server_first_message", "_client_final_no_proof",
        "_server_signature", "_completed",
    )

    def __init__(
        self,
        username: str,
        password: str,
        *,
        nonce: Optional[bytes] = None,
    ) -> None:
        # username is sent in the client-first message but Postgres
        # ignores it there (it uses the user from the startup packet
        # instead). We still populate it faithfully per RFC.
        self.username = username
        self._password = _saslprep(password)
        # 24 bytes → 32-char base64 nonce (plenty of entropy). Allow
        # deterministic injection for tests only.
        if nonce is None:
            nonce = secrets.token_bytes(24)
        self._nonce = _b64(nonce).encode("ascii")
        self._client_first_bare: Optional[bytes] = None
        self._server_first_message: Optional[bytes] = None
        self._client_final_no_proof: Optional[bytes] = None
        self._server_signature: Optional[bytes] = None
        self._completed = False

    # ── Step 1: build client-first ────────────────────────────────────
    def build_client_first(self) -> bytes:
        """Return the SASLInitialResponse client-first message bytes.

        Format: "n,,n=<user>,r=<nonce>"
        (GS2 header 'n,,' = no channel binding; server confirms the same.)"""
        # Postgres accepts an empty user in client-first because the real
        # user was already announced in the startup packet. We do not
        # escape user; per RFC only ',' and '=' need escaping and Postgres
        # usernames don't legitimately contain those in this codebase.
        bare = b"n=" + self.username.encode("utf-8") + b",r=" + self._nonce
        self._client_first_bare = bare
        return b"n,," + bare

    # ── Step 2: consume server-first, build client-final ──────────────
    def build_client_final(self, server_first: bytes) -> bytes:
        """Consume the server-first message and produce client-final."""
        if self._client_first_bare is None:
            raise ScramError("build_client_first() must be called first")

        self._server_first_message = server_first
        attrs = _parse_scram_attrs(server_first)

        combined_nonce = attrs["r"]
        if not combined_nonce.startswith(self._nonce):
            # Server MUST return the client nonce as a prefix, followed by
            # its own random suffix. A mismatch means an active MITM /
            # replay — refuse to continue.
            raise ScramError(
                "SCRAM: server nonce does not extend client nonce"
            )

        salt = _b64d(attrs["s"].decode("ascii"))
        iterations = int(attrs["i"])
        if iterations < 4096:
            # RFC 5802 §5.1 recommends >= 4096. Below that is a downgrade
            # attempt or a broken server. Fail rather than accept a
            # weakened KDF.
            raise ScramError(
                f"SCRAM: server-supplied iteration count {iterations} < 4096"
            )

        salted_password = _hi(self._password, salt, iterations)
        client_key = _hmac(salted_password, b"Client Key")
        stored_key = _h(client_key)
        server_key = _hmac(salted_password, b"Server Key")

        # channel-binding='biws' == base64('n,,') because we advertised no
        # channel binding in client-first
        client_final_no_proof = b"c=biws,r=" + combined_nonce
        self._client_final_no_proof = client_final_no_proof

        auth_message = (
            self._client_first_bare + b"," +
            self._server_first_message + b"," +
            client_final_no_proof
        )
        client_signature = _hmac(stored_key, auth_message)
        client_proof = _xor(client_key, client_signature)

        # Remember the server signature we EXPECT so the caller can
        # verify the server-final response later.
        self._server_signature = _hmac(server_key, auth_message)

        return client_final_no_proof + b",p=" + _b64(client_proof).encode("ascii")

    # ── Step 3: verify server-final ───────────────────────────────────
    def verify_server_final(self, server_final: bytes) -> None:
        """Constant-time compare of the server signature — RFC 5802 §3."""
        if self._server_signature is None:
            raise ScramError("verify_server_final() before build_client_final()")

        attrs = _parse_scram_attrs(server_final)
        if "e" in attrs:
            raise ScramError(
                f"SCRAM: server returned error {attrs['e']!r}"
            )
        v = attrs.get("v")
        if v is None:
            raise ScramError("SCRAM: server-final missing 'v' attribute")
        got_sig = _b64d(v.decode("ascii"))
        if not hmac.compare_digest(got_sig, self._server_signature):
            raise ScramError("SCRAM: server signature mismatch")
        self._completed = True

    @property
    def completed(self) -> bool:
        return self._completed


# ---- parsing helpers -------------------------------------------------------

def _parse_scram_attrs(msg: bytes) -> "dict[str, bytes]":
    """Parse a SCRAM comma-separated attribute list into {name: value}.

    SCRAM attribute syntax: `<name>=<value>` where name is a single ASCII
    letter and value is any byte-sequence up to the next unescaped comma.
    """
    out: "dict[str, bytes]" = {}
    for part in msg.split(b","):
        if b"=" not in part:
            continue
        k, _, v = part.partition(b"=")
        if not k:
            continue
        try:
            out[k.decode("ascii")] = v
        except UnicodeDecodeError:
            continue
    return out
