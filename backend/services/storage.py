import abc
import hashlib
import logging
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from config import settings

logger = logging.getLogger(__name__)

class StorageError(Exception):
    """Base exception for storage failures."""
    pass

class StorageUnavailableError(StorageError):
    pass

class StorageIntegrityError(StorageError):
    pass

class ArtifactStorage(abc.ABC):
    @abc.abstractmethod
    def save_original(self, scan_id: str, filename: str, content: bytes) -> tuple[str, str]:
        """Save the original uploaded artifact. Returns (object_key, sha256)."""
        pass

    @abc.abstractmethod
    def save_sanitized(self, scan_id: str, filename: str, content: bytes) -> tuple[str, str]:
        """Save the sanitized artifact. Returns (object_key, sha256)."""
        pass

    @abc.abstractmethod
    def save_report(self, scan_id: str, content: bytes) -> str:
        """Save the security report JSON. Returns object_key."""
        pass

    @abc.abstractmethod
    def get_object(self, object_key: str) -> bytes:
        """Retrieve an object's contents."""
        pass

    @abc.abstractmethod
    def delete_object(self, object_key: str) -> bool:
        """Delete an object."""
        pass

    @abc.abstractmethod
    def exists(self, object_key: str) -> bool:
        """Check if an object exists."""
        pass

def _verify_checksum(content: bytes, expected_sha256: str) -> None:
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected_sha256:
        raise StorageIntegrityError(f"SHA-256 mismatch! Expected {expected_sha256}, got {actual}")


class LocalArtifactStorage(ArtifactStorage):
    """Fallback local storage behavior matching pre-R2 file_service.py."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir

    def _get_path(self, object_key: str) -> Path:
        p = (self.base_dir / object_key).resolve()
        if not str(p).startswith(str(self.base_dir.resolve())):
            raise ValueError("Path traversal attempt detected")
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def save_original(self, scan_id: str, filename: str, content: bytes) -> tuple[str, str]:
        safe_name = Path(filename).name
        object_key = f"originals/{scan_id}/{safe_name}"
        p = self._get_path(object_key)
        p.write_bytes(content)
        sha256 = hashlib.sha256(content).hexdigest()
        _verify_checksum(p.read_bytes(), sha256)
        return object_key, sha256

    def save_sanitized(self, scan_id: str, filename: str, content: bytes) -> tuple[str, str]:
        safe_name = Path(filename).name
        object_key = f"sanitized/{scan_id}/{safe_name}"
        p = self._get_path(object_key)
        p.write_bytes(content)
        sha256 = hashlib.sha256(content).hexdigest()
        _verify_checksum(p.read_bytes(), sha256)
        return object_key, sha256

    def save_report(self, scan_id: str, content: bytes) -> str:
        object_key = f"reports/{scan_id}/security-report.json"
        p = self._get_path(object_key)
        p.write_bytes(content)
        return object_key

    def get_object(self, object_key: str) -> bytes:
        p = self._get_path(object_key)
        if not p.exists():
            raise FileNotFoundError(f"Object {object_key} not found")
        return p.read_bytes()

    def delete_object(self, object_key: str) -> bool:
        p = self._get_path(object_key)
        if p.exists():
            p.unlink()
            return True
        return False

    def exists(self, object_key: str) -> bool:
        return self._get_path(object_key).exists()


class R2ArtifactStorage(ArtifactStorage):
    """Cloudflare R2 storage adapter."""

    def __init__(self):
        if not settings.r2_bucket:
            raise ValueError("R2_BUCKET must be configured when R2 is enabled")
        if not settings.r2_endpoint_url:
            raise ValueError("R2_ENDPOINT_URL or R2_ACCOUNT_ID must be configured")

        self.bucket_name = settings.r2_bucket
        self.s3 = boto3.client(
            "s3",
            endpoint_url=settings.r2_endpoint_url,
            aws_access_key_id=settings.r2_access_key_id,
            aws_secret_access_key=settings.r2_secret_access_key,
            region_name=settings.r2_region,
        )

    def _sanitize_key(self, object_key: str) -> str:
        if ".." in object_key or object_key.startswith("/"):
            raise ValueError("Invalid object key (path traversal or absolute path)")
        return object_key

    def _upload(self, object_key: str, content: bytes) -> str:
        safe_key = self._sanitize_key(object_key)
        expected_sha256 = hashlib.sha256(content).hexdigest()

        try:
            self.s3.put_object(
                Bucket=self.bucket_name,
                Key=safe_key,
                Body=content,
                ChecksumSHA256=expected_sha256,
            )
            # Fetch back metadata/headers to verify atomicity & integrity if we strictly want,
            # though put_object with ChecksumSHA256 enforces it server-side.
            # To strictly fulfill "verify expected size/checksum", we can issue a head_object
            head = self.s3.head_object(Bucket=self.bucket_name, Key=safe_key)
            if head["ContentLength"] != len(content):
                raise StorageIntegrityError("Size mismatch after upload")

        except EndpointConnectionError as e:
            logger.error("R2 connection failed: %s", e)
            raise StorageUnavailableError("Could not connect to Cloudflare R2") from e
        except ClientError as e:
            logger.error("R2 upload failed: %s", e)
            raise StorageError(f"R2 upload failed: {e}") from e

        return expected_sha256

    def save_original(self, scan_id: str, filename: str, content: bytes) -> tuple[str, str]:
        safe_name = Path(filename).name
        object_key = f"originals/{scan_id}/{safe_name}"
        sha256 = self._upload(object_key, content)
        return object_key, sha256

    def save_sanitized(self, scan_id: str, filename: str, content: bytes) -> tuple[str, str]:
        safe_name = Path(filename).name
        object_key = f"sanitized/{scan_id}/{safe_name}"
        sha256 = self._upload(object_key, content)
        return object_key, sha256

    def save_report(self, scan_id: str, content: bytes) -> str:
        object_key = f"reports/{scan_id}/security-report.json"
        self._upload(object_key, content)
        return object_key

    def get_object(self, object_key: str) -> bytes:
        safe_key = self._sanitize_key(object_key)
        try:
            resp = self.s3.get_object(Bucket=self.bucket_name, Key=safe_key)
            return resp["Body"].read()
        except self.s3.exceptions.NoSuchKey as e:
            raise FileNotFoundError(f"Object {safe_key} not found in R2") from e
        except ClientError as e:
            logger.error("R2 get_object failed: %s", e)
            raise StorageError(f"Failed to retrieve {safe_key}") from e

    def delete_object(self, object_key: str) -> bool:
        safe_key = self._sanitize_key(object_key)
        try:
            self.s3.delete_object(Bucket=self.bucket_name, Key=safe_key)
            return True
        except ClientError as e:
            logger.error("R2 delete_object failed: %s", e)
            raise StorageError(f"Failed to delete {safe_key}") from e

    def exists(self, object_key: str) -> bool:
        safe_key = self._sanitize_key(object_key)
        try:
            self.s3.head_object(Bucket=self.bucket_name, Key=safe_key)
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404":
                return False
            raise StorageError(f"Failed to check existence of {safe_key}") from e

def get_storage_backend() -> ArtifactStorage:
    if settings.r2_enabled:
        return R2ArtifactStorage()

    # Resolve the data directory exactly as file_service.py did
    curr_dir = Path(__file__).resolve().parent
    root = curr_dir.parent.parent if curr_dir.parent.name == "backend" else curr_dir.parent
    data_dir = root / "data"

    # Try creating it to ensure permissions, fallback to /tmp/data if failed
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        return LocalArtifactStorage(data_dir)
    except (PermissionError, OSError):
        fallback = Path("/tmp/data")
        fallback.mkdir(parents=True, exist_ok=True)
        return LocalArtifactStorage(fallback)

storage_backend = get_storage_backend()
