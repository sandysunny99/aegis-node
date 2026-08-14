"""
Aegis Node — File Service.
Handles safe file storage, SHA-256 hashing, MIME detection, format routing, and sanitized artifact storage.

Security rules enforced here:
  - Original filename is sanitized (path separators stripped) before storage.
  - File is saved under a UUID-based name to prevent path traversal.
  - SHA-256 hash computed before file is processed or stored in DB.
  - Sanitized artifacts are isolated in data/sanitized/ under UUID filenames.
  - Never executes uploaded content.
"""

import hashlib
import mimetypes
import re
import uuid
from pathlib import Path

from config import settings

# ─── Data directories ─────────────────────────────────────────────────────────
# Project root resolution (handles both local dev under /backend and Docker container under /app)
_CURR_DIR = Path(__file__).resolve().parent  # .../services
_PROJECT_ROOT = _CURR_DIR.parent.parent if _CURR_DIR.parent.name == "backend" else _CURR_DIR.parent


def _ensure_dir(d: Path) -> Path:
    """Ensure directory exists with graceful fallback to /tmp/data if permission denied."""
    try:
        d.mkdir(parents=True, exist_ok=True)
        return d
    except (PermissionError, OSError):
        fallback = Path("/tmp") / "data" / d.name
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


_SAMPLES_DIR = _ensure_dir(_PROJECT_ROOT / "data" / "samples")
_QUARANTINE_DIR = _ensure_dir(_PROJECT_ROOT / "data" / "quarantine")
_SANITIZED_DIR = _ensure_dir(_PROJECT_ROOT / "data" / "sanitized")

# Reserved Windows device names
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


def _sanitize_filename(name: str) -> str:
    """
    Strip path separators, null bytes, Unicode bidi control characters,
    and Windows device names from the original filename.
    """
    # Strip null bytes & path separators
    name = re.sub(r'[\\\/\0]', '_', name)
    # Strip Unicode bidi control characters (\u202a-\u202e, \u2066-\u2069)
    name = re.sub(r'[\u202a-\u202e\u2066-\u2069]', '', name)
    # Strip leading/trailing dots and spaces
    name = name.strip('. ')

    # Check for Windows reserved names (e.g. CON.csv -> _CON.csv)
    stem = Path(name).stem.upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        name = f"_{name}"

    return name[:255] if name else "unnamed"


def _detect_mime(file_path: Path) -> str:
    """
    Detect MIME type from file content using python-magic (A-017/A-023).
    Falls back to extension-based detection if python-magic is unavailable.
    """
    try:
        import magic  # python-magic (not magic stdlib)
        return magic.from_file(str(file_path), mime=True)
    except (ImportError, Exception):
        pass
    mime, _ = mimetypes.guess_type(str(file_path))
    return mime or "application/octet-stream"


def _detect_format(filename: str) -> str:
    """Return normalised format label based on file extension."""
    ext = Path(filename).suffix.lower()
    _map = {
        ".csv": "csv",
        ".parquet": "parquet",
        ".json": "json",
        ".jsonl": "jsonl",
        ".xlsx": "xlsx",
        ".txt": "txt",
    }
    return _map.get(ext, "unknown")


# A-008: Complete binary magic byte block list (PE/MZ, ELF, all Mach-O variants)
_BINARY_MAGIC: list[bytes] = [
    b"MZ",             # Windows PE/DOS executable
    b"\x7fELF",        # ELF binary (Linux/Unix)
    b"\xfe\xed\xfa",   # Mach-O big-endian 32-bit
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little-endian
    b"\xca\xfe\xba\xbe",  # Mach-O fat/universal binary
]


def validate_magic_bytes(content: bytes, filename: str) -> bool:
    """
    Verify magic byte headers to reject executable binary anomalies (PE/MZ, ELF, MACH-O)
    disguised under allowed dataset extensions.
    """
    if not content:
        return True

    # Block all known binary executable headers (A-008)
    if any(content.startswith(m) for m in _BINARY_MAGIC):
        return False

    ext = Path(filename).suffix.lower()
    if ext == ".parquet" and len(content) >= 4:
        # Parquet files must start with PAR1
        return content.startswith(b"PAR1")

    return True


def compute_sha256(path: Path) -> str:
    """Compute SHA-256 of a file in 64 KB chunks (safe for large files)."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class FileService:
    """Encapsulates all file handling operations for dataset uploads & sanitized artifacts."""

    def validate_extension(self, filename: str) -> bool:
        """Return True if the file extension is in the allow-list."""
        ext = Path(filename).suffix.lower()
        return ext in settings.allowed_extensions

    def save_upload(self, original_filename: str, content: bytes) -> dict:
        """
        Save raw file bytes to data/samples/ under a UUID filename.

        Returns a dict with:
          original_filename, stored_filename, file_size_bytes,
          sha256_hash, mime_type, file_format, file_path
        """
        safe_orig = _sanitize_filename(original_filename)
        ext = Path(safe_orig).suffix.lower()
        stored_name = f"{uuid.uuid4().hex}{ext}"
        dest_path = _SAMPLES_DIR / stored_name

        dest_path.write_bytes(content)

        sha256 = compute_sha256(dest_path)
        mime = _detect_mime(dest_path)
        fmt = _detect_format(safe_orig)

        return {
            "original_filename": safe_orig,
            "stored_filename": stored_name,
            "file_size_bytes": len(content),
            "sha256_hash": sha256,
            "mime_type": mime,
            "file_format": fmt,
            "file_path": str(dest_path),
        }

    def save_sanitized(self, original_stored_filename: str, content: bytes) -> tuple[str, str, Path]:
        """
        Save sanitized content bytes to data/sanitized/ under a UUID filename.
        Returns (stored_sanitized_filename, sha256_hash, full_dest_path).
        """
        ext = Path(original_stored_filename).suffix.lower()
        sanitized_name = f"{uuid.uuid4().hex}_sanitized{ext}"
        dest_path = _SANITIZED_DIR / sanitized_name

        dest_path.write_bytes(content)
        sha256 = compute_sha256(dest_path)
        return sanitized_name, sha256, dest_path

    def quarantine(self, stored_filename: str) -> str:
        """Move a file from samples/ to quarantine/. Returns new path."""
        src = _SAMPLES_DIR / stored_filename
        dst = _QUARANTINE_DIR / stored_filename
        if src.exists():
            src.rename(dst)
        return str(dst)

    def get_sample_path(self, stored_filename: str) -> Path:
        """Return the full path of a stored sample. Enforces directory boundary."""
        p = (_SAMPLES_DIR / Path(stored_filename).name).resolve()
        if not str(p).startswith(str(_SAMPLES_DIR.resolve())):
            raise ValueError("Path traversal attempt detected")
        return p

    def get_existing_source_path(self, stored_filename: str) -> Path:
        """
        Return the existing file path for stored_filename, checking samples/ first then quarantine/.
        Enforces directory boundary.
        """
        safe_name = Path(stored_filename).name
        sample_p = (_SAMPLES_DIR / safe_name).resolve()
        if sample_p.exists() and str(sample_p).startswith(str(_SAMPLES_DIR.resolve())):
            return sample_p

        quarantine_p = (_QUARANTINE_DIR / safe_name).resolve()
        if quarantine_p.exists() and str(quarantine_p).startswith(str(_QUARANTINE_DIR.resolve())):
            return quarantine_p

        raise FileNotFoundError(f"Source file {stored_filename} not found in samples or quarantine.")

    def get_sanitized_path(self, stored_sanitized_filename: str) -> Path:
        """Return the full path of a sanitized sample. Enforces directory boundary."""
        p = (_SANITIZED_DIR / Path(stored_sanitized_filename).name).resolve()
        if not str(p).startswith(str(_SANITIZED_DIR.resolve())):
            raise ValueError("Path traversal attempt detected")
        return p

    def sample_exists(self, stored_filename: str) -> bool:
        try:
            self.get_existing_source_path(stored_filename)
            return True
        except (FileNotFoundError, ValueError):
            return False

    def sanitized_exists(self, stored_sanitized_filename: str) -> bool:
        try:
            return self.get_sanitized_path(stored_sanitized_filename).exists()
        except ValueError:
            return False


file_service = FileService()
