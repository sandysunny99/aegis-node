"""
Aegis Node — Test Suite: API Endpoints
Integration tests using FastAPI TestClient.
Mocks ClamAV (offline) and AI (unavailable) to keep tests deterministic.
"""

import io
import sys
from pathlib import Path

import pytest

# Ensure backend is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a FastAPI TestClient for integration testing."""
    from backend.main import app
    return TestClient(app)


@pytest.fixture
def demo_csv():
    """A small malicious CSV for testing."""
    content = (
        "id,name,email,notes\n"
        "1,Alice,alice@example.com,clean row\n"
        "2,Bob,' OR '1'='1' --,SQL injection\n"
        "3,Charlie,charlie@test.com,=cmd|' /C calc'!A0\n"
        "4,Dave,dave@test.com,<script>alert(1)</script>\n"
    )
    return io.BytesIO(content.encode("utf-8"))


@pytest.fixture
def clean_csv():
    """A clean CSV with no threats."""
    content = (
        "id,name,email,department\n"
        "1,Alice Johnson,alice@company.com,Engineering\n"
        "2,Bob Smith,bob@company.com,Marketing\n"
        "3,Charlie Brown,charlie@company.com,Sales\n"
    )
    return io.BytesIO(content.encode("utf-8"))


class TestHealthEndpoint:
    """Test the /health endpoint."""

    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_health_has_required_fields(self, client):
        resp = client.get("/health/diagnostics")
        data = resp.json()
        assert "clamav_running" in data
        assert "ai_configured" in data
        assert "ai_provider" in data
        assert "supported_formats" in data
        assert "max_file_size_mb" in data

    def test_health_supported_formats(self, client):
        resp = client.get("/health/diagnostics")
        data = resp.json()
        formats = data["supported_formats"]
        assert "csv" in formats
        assert "json" in formats


class TestUploadEndpoint:
    """Test the POST /api/v1/datasets/upload endpoint."""

    def test_upload_csv_success(self, client, demo_csv):
        resp = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("test.csv", demo_csv, "text/csv")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "dataset_id" in data
        assert data["original_filename"] == "test.csv"
        assert data["file_format"] == "csv"
        assert data["sha256_hash"]
        assert data["status"] == "uploaded"

    def test_upload_rejects_invalid_extension(self, client):
        resp = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("malware.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")},
        )
        assert resp.status_code == 415

    def test_upload_returns_sha256(self, client, clean_csv):
        resp = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("clean.csv", clean_csv, "text/csv")},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert len(data["sha256_hash"]) == 64  # SHA-256 hex digest


class TestScanEndpoint:
    """Test the POST /api/v1/datasets/{id}/scan endpoint."""

    def test_scan_detects_threats(self, client, demo_csv):
        # Upload first
        up = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("malicious.csv", demo_csv, "text/csv")},
        )
        dataset_id = up.json()["dataset_id"]

        # Scan
        resp = client.post(f"/api/v1/datasets/{dataset_id}/scan")
        assert resp.status_code == 200
        data = resp.json()

        assert data["threats_found_count"] > 0
        assert data["verdict"] in ("suspicious", "malicious")
        assert data["risk_score"] > 0
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) > 0

    def test_scan_clean_file(self, client, clean_csv):
        up = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("clean.csv", clean_csv, "text/csv")},
        )
        dataset_id = up.json()["dataset_id"]

        resp = client.post(f"/api/v1/datasets/{dataset_id}/scan")
        assert resp.status_code == 200
        data = resp.json()
        assert data["threats_found_count"] == 0
        assert data["verdict"] in ("clean", "clean_verified", "clean_with_limitations")
        assert data["risk_score"] == 0.0

    def test_scan_not_found(self, client):
        resp = client.post("/api/v1/datasets/99999/scan")
        assert resp.status_code == 404

    def test_scan_result_has_required_fields(self, client, demo_csv):
        up = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("test2.csv", demo_csv, "text/csv")},
        )
        dataset_id = up.json()["dataset_id"]
        resp = client.post(f"/api/v1/datasets/{dataset_id}/scan")
        data = resp.json()

        required_fields = ["scan_id", "dataset_id", "clamav_status", "threats_found_count",
                           "risk_score", "scan_duration_ms", "verdict", "findings"]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"


class TestRemediationEndpoint:
    """Test the POST /api/v1/datasets/{id}/remediate endpoint."""

    def test_remediation_reduces_threats(self, client, demo_csv):
        # Upload and scan first
        up = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("rem_test.csv", demo_csv, "text/csv")},
        )
        dataset_id = up.json()["dataset_id"]
        client.post(f"/api/v1/datasets/{dataset_id}/scan")

        # Remediate
        resp = client.post(f"/api/v1/datasets/{dataset_id}/remediate")
        assert resp.status_code == 200
        data = resp.json()

        assert "threat_reduction_percent" in data
        assert data["threat_reduction_percent"] >= 0
        assert "changes_count" in data
        assert "sanitized_sha256" in data
        assert data["sanitized_sha256"] != data["original_sha256"]

    def test_remediation_without_scan_rejected(self, client, clean_csv):
        up = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("no_scan.csv", clean_csv, "text/csv")},
        )
        dataset_id = up.json()["dataset_id"]
        # Try remediate without scanning
        resp = client.post(f"/api/v1/datasets/{dataset_id}/remediate")
        assert resp.status_code == 400


class TestSecurityEnhancements:
    """Tests covering security headers, Mach-O checks, and token downloads."""

    def test_security_headers_present_on_response(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert "Content-Security-Policy" in resp.headers
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "no-referrer"

    def test_upload_rejects_macho_64bit_magic_bytes(self, client):
        macho_64 = b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 32
        resp = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("fake_dataset.csv", io.BytesIO(macho_64), "text/csv")},
        )
        assert resp.status_code == 400

    def test_upload_rejects_macho_fat_magic_bytes(self, client):
        macho_fat = b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 32
        resp = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("fake_fat.csv", io.BytesIO(macho_fat), "text/csv")},
        )
        assert resp.status_code == 400

    def test_header_based_sanitized_download(self, client, demo_csv):
        up = client.post(
            "/api/v1/datasets/upload",
            files={"file": ("download_test.csv", demo_csv, "text/csv")},
        )
        dataset_id = up.json()["dataset_id"]
        client.post(f"/api/v1/datasets/{dataset_id}/scan")
        rem = client.post(f"/api/v1/datasets/{dataset_id}/remediate").json()
        token = rem["download_token"]

        # Download using Authorization: Bearer <token>
        resp = client.get(
            f"/api/v1/datasets/{dataset_id}/download-sanitized",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert len(resp.content) > 0

