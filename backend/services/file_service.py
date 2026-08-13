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

# ─── Allowed file extensions (case-insensitive) ───────────────────────────────
_ALLOWED_EXTENSIONS = {".csv", ".parquet", ".json", ".jsonl"}

# ─── Data directories ─────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent.parent   # aegis-node/
_SAMPLES_DIR = _PROJECT_ROOT / "data" / "samples"
_QUARANTINE_DIR = _PROJECT_ROOT / "data" / "quarantine"
_SANITIZED_DIR = _PROJECT_ROOT / "data" / "sanitized"

# Ensure directories exist
_SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
_QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
_SANITIZED_DIR.mkdir(parents=True, exist_ok=True)


def _sanitize_filename(name: str) -> str:
    """Strip path separators and control characters from the original filename."""
    name = re.sub(r'[\\\/\0]', '_', name)
    return name[:255]   # hard cap


def _detect_mime(file_path: Path) -> str:
    """
    Detect MIME type from file extension only (python-magic requires libmagic).
    Falls back to application/octet-stream for unknown types.
    """
    mime, _ = mimetypes.guess_type(str(file_path))
    return mime or "application/octet-stream"


def _detect_format(filename: str) -> str:
    """Return normalised format label based on file extension."""
    ext = Path(filename).suffix.lower()
    _map = {".csv": "csv", ".parquet": "parquet", ".json": "json", ".jsonl": "jsonl"}
    return _map.get(ext, "unknown")


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
        return ext in _ALLOWED_EXTENSIONS

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
