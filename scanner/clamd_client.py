"""
Aegis Node — ClamAV Daemon TCP Client.
Connects to clamd on TCP port 3310 using the INSTREAM protocol.
Falls back gracefully when daemon is unavailable (local dev without Docker).

Protocol reference: https://linux.die.net/man/8/clamd
"""

import logging
import socket
import struct
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ─── Default connection settings ─────────────────────────────────────────────
_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 3310
_CONNECT_TIMEOUT = 0.5       # seconds (fast failure when daemon is offline)
_CHUNK_SIZE = 4096           # bytes per INSTREAM chunk
_MAX_RESPONSE_BYTES = 1024

# Cache offline status for 5 seconds to avoid repeated socket timeouts when daemon is down
_OFFLINE_CACHE_TTL = 5.0
_last_failed_check: float = 0.0


@dataclass
class ClamAVResult:
    available: bool          # False when daemon is not reachable
    infected: bool
    virus_name: str | None
    raw_response: str
    error: str | None


def _clamd_instream(path: str, host: str, port: int) -> ClamAVResult:
    """
    Stream file bytes to clamd using the INSTREAM protocol.
    Each chunk is prefixed with a 4-byte big-endian unsigned int length.
    A zero-length chunk signals end of stream.
    """
    global _last_failed_check  # noqa: PLW0603

    now = time.time()
    if now - _last_failed_check < _OFFLINE_CACHE_TTL:
        return ClamAVResult(
            available=False,
            infected=False,
            virus_name=None,
            raw_response="",
            error="ClamAV daemon offline (cached)",
        )

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(_CONNECT_TIMEOUT)
            sock.connect((host, port))
            sock.sendall(b"zINSTREAM\0")

            with open(path, "rb") as fh:
                while chunk := fh.read(_CHUNK_SIZE):
                    sock.sendall(struct.pack("!I", len(chunk)) + chunk)

            # Send EOF chunk
            sock.sendall(struct.pack("!I", 0))

            response = sock.recv(_MAX_RESPONSE_BYTES).decode("utf-8", errors="replace").strip().rstrip("\0")

    except (TimeoutError, ConnectionRefusedError, OSError) as exc:
        _last_failed_check = time.time()
        logger.warning("ClamAV daemon unavailable at %s:%d — %s", host, port, exc)
        return ClamAVResult(
            available=False,
            infected=False,
            virus_name=None,
            raw_response="",
            error=str(exc),
        )

    # Response format: "stream: OK" or "stream: <VirusName> FOUND"
    if "FOUND" in response:
        parts = response.split(":")
        virus = parts[-1].strip().replace(" FOUND", "").strip() if len(parts) > 1 else "Unknown"
        return ClamAVResult(available=True, infected=True, virus_name=virus, raw_response=response, error=None)

    if "OK" in response:
        return ClamAVResult(available=True, infected=False, virus_name=None, raw_response=response, error=None)

    # Unexpected response
    return ClamAVResult(available=True, infected=False, virus_name=None, raw_response=response, error=f"Unexpected: {response}")


def ping(host: str = _DEFAULT_HOST, port: int = _DEFAULT_PORT) -> bool:
    """Returns True if clamd is reachable and responds to PING."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(_CONNECT_TIMEOUT)
            sock.connect((host, port))
            sock.sendall(b"zPING\0")
            response = sock.recv(64).decode("utf-8", errors="replace").strip().rstrip("\0")
            return response == "PONG"
    except OSError:
        return False


def scan_file(path: str, host: str = _DEFAULT_HOST, port: int = _DEFAULT_PORT) -> ClamAVResult:
    """
    Primary entry point — stream file to clamd and return the scan result.
    If clamd is unreachable, returns ClamAVResult(available=False, infected=False).
    """
    return _clamd_instream(path, host, port)
