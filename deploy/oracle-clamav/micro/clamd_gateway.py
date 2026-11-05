"""
Aegis scan gateway for the Oracle Always Free micro VM (0.5 GB RAM): Python standard
library only, so it adds a few MB instead of a container stack. Caddy terminates HTTPS
in front of it; it listens on 127.0.0.1 only and talks to clamd over its Unix socket.

  GET  /healthz          no auth; {"status": "ok"} only
  GET  /api/v1/version   bearer token; clamd VERSION
  POST /api/v1/scan      bearer token; multipart field FILES; same JSON shape as
                         clamav-rest, so Aegis' ClamAVRestProvider needs no change

clamd unreachable, still loading or erroring -> 503 {"success": false}: never "clean".
It never logs the token, file names or contents. Every upload is streamed to a private
temporary file, sent to clamd in chunks and deleted.
"""

import cgi
import hmac
import json
import os
import socket
import struct
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("SCAN_GATEWAY_TOKEN", "")
SOCKET = os.environ.get("CLAMD_SOCKET", "/run/clamd.scan/clamd.sock")
MAX_BYTES = int(os.environ.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024
TIMEOUT = float(os.environ.get("CLAMD_TIMEOUT_SECONDS", "120"))
SLOTS = threading.BoundedSemaphore(int(os.environ.get("MAX_CONCURRENT_SCANS", "1")))
CHUNK = 64 * 1024

if len(TOKEN) < 32:
    raise SystemExit("SCAN_GATEWAY_TOKEN must be set and at least 32 characters long")


def _clamd(command: bytes, stream=None) -> str:
    """One clamd request over the Unix socket; INSTREAM when a file object is given."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        s.connect(SOCKET)
        s.sendall(command)
        if stream is not None:
            while True:
                block = stream.read(CHUNK)
                if not block:
                    break
                s.sendall(struct.pack("!L", len(block)) + block)
            s.sendall(struct.pack("!L", 0))
        reply = b""
        while not reply.endswith(b"\0"):
            part = s.recv(4096)
            if not part:
                break
            reply += part
    return reply.rstrip(b"\0").decode("utf-8", "replace").strip()


class Handler(BaseHTTPRequestHandler):
    server_version = "aegis-gateway"
    sys_version = ""

    def log_message(self, fmt, *args):  # method, path and status only
        print(f"{self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}", flush=True)

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        supplied = header[7:] if header.lower().startswith("bearer ") else ""
        if hmac.compare_digest(supplied.encode(), TOKEN.encode()):
            return True
        self._json(401, {"success": False, "message": "unauthorized"})
        return False

    def do_GET(self):
        if self.path == "/healthz":
            return self._json(200, {"status": "ok"})
        if self.path == "/api/v1/version":
            if not self._authorized():
                return None
            try:
                version = _clamd(b"zVERSION\0")
            except OSError:
                return self._json(503, {"success": False, "message": "clamd unavailable"})
            return self._json(200, {"success": True, "data": {"version": version}})
        return self._json(404, {"success": False, "message": "not found"})

    def do_POST(self):
        if self.path != "/api/v1/scan":
            return self._json(404, {"success": False, "message": "not found"})
        if not self._authorized():
            return None
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return self._json(400, {"success": False, "message": "empty request"})
        if length > MAX_BYTES + 64 * 1024:
            return self._json(413, {"success": False, "message": "file too large"})
        if not SLOTS.acquire(timeout=5):
            return self._json(503, {"success": False, "message": "scanner busy"})
        try:
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                    environ={"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(length),
                                             "CONTENT_TYPE": self.headers.get("Content-Type", "")})
            item = form["FILES"] if "FILES" in form else None
            if item is None or not getattr(item, "file", None):
                return self._json(400, {"success": False, "message": "multipart field FILES required"})
            with tempfile.TemporaryFile() as tmp:
                size = 0
                while True:
                    block = item.file.read(CHUNK)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_BYTES:
                        return self._json(413, {"success": False, "message": "file too large"})
                    tmp.write(block)
                tmp.seek(0)
                try:
                    reply = _clamd(b"zINSTREAM\0", tmp)
                except OSError:
                    return self._json(503, {"success": False, "message": "clamd unavailable"})
            # "stream: OK" | "stream: <Signature> FOUND" | "... ERROR"
            if reply.endswith(" FOUND"):
                virus = reply.split(":", 1)[1].rsplit(" FOUND", 1)[0].strip()
                return self._json(200, {"success": True, "data": {"result": [
                    {"name": "upload.bin", "is_infected": True, "viruses": [virus]}]}})
            if reply.endswith(" OK"):
                return self._json(200, {"success": True, "data": {"result": [
                    {"name": "upload.bin", "is_infected": False, "viruses": []}]}})
            return self._json(503, {"success": False, "message": "clamd error"})
        finally:
            SLOTS.release()


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
