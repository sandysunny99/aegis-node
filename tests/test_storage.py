import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from services.storage import (
    LocalArtifactStorage,
    R2ArtifactStorage,
    StorageIntegrityError,
    StorageUnavailableError,
    get_data_directory,
    get_storage_backend,
)


@pytest.fixture
def temp_local_storage(tmp_path):
    return LocalArtifactStorage(tmp_path)


def test_data_directory_uses_configured_path(tmp_path, monkeypatch):
    data_dir = tmp_path / "persistent-data"
    monkeypatch.setattr("services.storage.settings.data_dir", data_dir)

    assert get_data_directory() == data_dir
    assert data_dir.is_dir()


def test_local_storage_lifecycle(temp_local_storage):
    content = b"test payload"
    scan_id = "test-scan-123"
    filename = "evil.exe"

    # 1. Save original
    obj_key, sha256 = temp_local_storage.save_original(scan_id, filename, content)
    assert obj_key == "originals/test-scan-123/evil.exe"
    assert sha256 == hashlib.sha256(content).hexdigest()

    # 2. Exists & Retrieve
    assert temp_local_storage.exists(obj_key) is True
    assert temp_local_storage.get_object(obj_key) == content

    # 3. Save report
    rep_key = temp_local_storage.save_report(scan_id, b'{"status": "malicious"}')
    assert rep_key == "reports/test-scan-123/security-report.json"
    assert temp_local_storage.exists(rep_key) is True

    # 4. Delete
    assert temp_local_storage.delete_object(obj_key) is True
    assert temp_local_storage.exists(obj_key) is False

def test_local_storage_backend_uses_configured_data_dir(monkeypatch, tmp_path):
    from config import settings

    monkeypatch.setattr(settings, "r2_enabled", False)
    monkeypatch.setattr(settings, "data_dir", tmp_path)

    storage = get_storage_backend()

    assert isinstance(storage, LocalArtifactStorage)
    assert storage.base_dir == tmp_path


def test_relative_data_dir_resolves_from_repository_root(tmp_path):
    from config import _ROOT_ENV, Settings

    configured_path = Path("relative-artifacts")
    settings = Settings(_env_file=None, data_dir=configured_path)

    assert settings.data_dir == (_ROOT_ENV.parent / configured_path).resolve()


@pytest.mark.asyncio
async def test_file_service_uses_configured_data_dir_for_all_local_artifacts(
    monkeypatch, tmp_path
):
    import services.file_service as file_service_module
    from config import settings

    assert file_service_module._BASE_DATA_DIR == settings.data_dir

    data_dir = tmp_path / "configured-data"
    samples_dir = data_dir / "samples"
    quarantine_dir = data_dir / "quarantine"
    sanitized_dir = data_dir / "sanitized"
    for directory in (samples_dir, quarantine_dir, sanitized_dir):
        directory.mkdir(parents=True)

    storage = LocalArtifactStorage(data_dir)
    monkeypatch.setattr(file_service_module, "_SAMPLES_DIR", samples_dir)
    monkeypatch.setattr(file_service_module, "_QUARANTINE_DIR", quarantine_dir)
    monkeypatch.setattr(file_service_module, "_SANITIZED_DIR", sanitized_dir)
    monkeypatch.setattr(file_service_module, "storage_backend", storage)
    monkeypatch.setattr(settings, "r2_enabled", False)

    class Upload:
        def __init__(self, content):
            self.content = content

        async def read(self, size=-1):
            chunk, self.content = self.content[:size], self.content[size:]
            return chunk

    original = b"id,name\n1,harmless\n"
    service = file_service_module.FileService()
    uploaded = await service.save_upload_stream(Upload(original), "sample.csv")
    staged_path = Path(uploaded["file_path"])
    assert staged_path.parent == samples_dir
    assert staged_path.read_bytes() == original
    assert storage.get_object(uploaded["object_key"]) == original
    assert storage._get_path(uploaded["object_key"]).is_relative_to(data_dir)

    sanitized = b"id,name\n1,clean\n"
    sanitized_result = service.save_sanitized(uploaded["stored_filename"], sanitized)
    sanitized_path = Path(sanitized_result["file_path"])
    assert sanitized_path.parent == sanitized_dir
    assert sanitized_path.read_bytes() == sanitized
    assert storage.get_object(sanitized_result["object_key"]) == sanitized
    assert storage._get_path(sanitized_result["object_key"]).is_relative_to(data_dir)

    quarantined_path = Path(service.quarantine(uploaded["stored_filename"]))
    assert quarantined_path.parent == quarantine_dir
    assert quarantined_path.read_bytes() == original
    assert service.get_existing_source_path(uploaded["stored_filename"]) == quarantined_path


def test_configured_data_directory_permission_error_is_not_hidden(
    monkeypatch, tmp_path
):
    from services import file_service as file_service_module

    blocked_dir = tmp_path / "unwritable"
    original_mkdir = Path.mkdir

    def fail_for_configured_path(path, *args, **kwargs):
        if path == blocked_dir:
            raise PermissionError("permission denied")
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fail_for_configured_path)

    with pytest.raises(PermissionError, match="permission denied"):
        file_service_module._ensure_dir(blocked_dir)

    assert not blocked_dir.exists()


def test_local_storage_path_traversal(temp_local_storage):
    with pytest.raises(ValueError, match="Path traversal attempt detected"):
        temp_local_storage.get_object("../../../etc/passwd")

@pytest.fixture
def mock_r2_storage():
    with patch("backend.services.storage.boto3.client") as mock_boto:
        with patch("backend.services.storage.settings.r2_bucket", "test-bucket"):
            with patch("backend.services.storage.settings.r2_endpoint_url", "https://test.r2.cloudflarestorage.com"):
                storage = R2ArtifactStorage()
                yield storage, mock_boto.return_value

def test_r2_upload_success(mock_r2_storage):
    storage, mock_s3 = mock_r2_storage
    content = b"r2 payload"

    # Mock head_object to return correct size
    mock_s3.head_object.return_value = {"ContentLength": len(content)}

    obj_key, sha256 = storage.save_sanitized("scan456", "test.txt", content)

    assert obj_key == "sanitized/scan456/test.txt"
    mock_s3.put_object.assert_called_once()
    assert mock_s3.put_object.call_args[1]["ChecksumSHA256"] == sha256

def test_r2_integrity_failure(mock_r2_storage):
    storage, mock_s3 = mock_r2_storage
    content = b"r2 payload"

    # Mock head_object to return wrong size
    mock_s3.head_object.return_value = {"ContentLength": 9999}

    with pytest.raises(StorageIntegrityError, match="Size mismatch"):
        storage.save_original("scan456", "test.txt", content)

def test_r2_connection_failure(mock_r2_storage):
    storage, mock_s3 = mock_r2_storage
    mock_s3.put_object.side_effect = EndpointConnectionError(endpoint_url="https://fail")

    with pytest.raises(StorageUnavailableError):
        storage.save_report("scan123", b"report")

def test_r2_path_traversal(mock_r2_storage):
    storage, _ = mock_r2_storage
    with pytest.raises(ValueError, match="Invalid object key"):
        storage.get_object("../../secrets")

def test_r2_missing_object(mock_r2_storage):
    storage, mock_s3 = mock_r2_storage

    # Setup exception correctly attached to client
    mock_s3.exceptions.NoSuchKey = type('NoSuchKey', (ClientError,), {})
    mock_s3.get_object.side_effect = mock_s3.exceptions.NoSuchKey(
        {"Error": {"Code": "NoSuchKey"}}, "operation"
    )

    with pytest.raises(FileNotFoundError):
        storage.get_object("missing.txt")
