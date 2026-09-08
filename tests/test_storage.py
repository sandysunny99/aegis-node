import os
import pytest
from pathlib import Path
import hashlib
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError, EndpointConnectionError

from backend.services.storage import (
    LocalArtifactStorage,
    R2ArtifactStorage,
    StorageUnavailableError,
    StorageError,
    StorageIntegrityError,
)

@pytest.fixture
def temp_local_storage(tmp_path):
    return LocalArtifactStorage(tmp_path)

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
