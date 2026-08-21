"""
Shared wire-protocol limits for DB proxy drivers.

Every driver frames a client packet as ``<header> + payload``. Because the
sandbox controls the payload length in the header, an unbounded
``readexactly(payload_len)`` is a trivial memory-DoS primitive: a 32-bit
length of ``0xFFFFFFFC`` would ask the proxy to allocate ~4 GiB before it
ever reaches the SQL firewall.

The limits below are used by every driver's frame reader and are the
first check performed on each incoming client packet.
"""
from __future__ import annotations

# Maximum acceptable client payload length in bytes. Matches the SQL
# firewall's per-query cap so no single packet can even hold an oversized
# query. Deliberately smaller than kernel default socket buffers so a
# malicious sandbox client cannot spend a full syscall's worth of read
# budget on one frame.
MAX_CLIENT_PACKET_BYTES = 128 * 1024   # 128 KiB — SQL cap is 100 KiB + slack

# Server -> client frames are trusted (real DB origin). We still bound
# them to prevent a compromised or lying upstream from OOM'ing the proxy.
MAX_SERVER_PACKET_BYTES = 16 * 1024 * 1024   # 16 MiB — enough for row sets


class OversizedPacketError(Exception):
    """Raised when a wire frame declares a length above the driver cap."""

    def __init__(self, direction: str, declared: int, limit: int) -> None:
        super().__init__(
            f"{direction} packet declared length {declared} exceeds "
            f"limit {limit}"
        )
        self.direction = direction
        self.declared = declared
        self.limit = limit
