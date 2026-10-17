"""
B1: an "MZ" byte pair is not an executable. PE evidence needs a plausible DOS header,
a bounded e_lfanew and the PE\\0\\0 signature at that offset.

The synthetic PE header below is a 0x200-byte header with no code; it cannot run.
"""

import io
import struct

import pandas as pd
import pytest
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app

from scanner.content_checker import raw_bytes_scan

client = TestClient(app, raise_server_exceptions=False)
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def synthetic_pe_header(e_lfanew: int = 0x80, signature: bytes = b"PE\x00\x00", size: int = 0x200) -> bytes:
    """DOS header + PE signature + i386 machine field; no sections, no code."""
    dos = bytearray(size)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    if 0 <= e_lfanew <= size - 6:
        dos[e_lfanew:e_lfanew + len(signature)] = signature
        struct.pack_into("<H", dos, e_lfanew + 4, 0x014C)
    return bytes(dos)


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


def _pe_findings(raw: bytes, tmp_path, name="f.csv"):
    f = tmp_path / name
    f.write_bytes(raw)
    return [x for x in raw_bytes_scan(f) if x.rule_id == "MAL-002"]


def _filler(n=600):
    return b"".join(b"%d,Alice,25\n" % i for i in range(n))


# ─── plain data containing MZ is not an executable ───────────────────────────

@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("notes.txt", b"intro\n" + b"x" * 600 + b"\nMZ is a two-letter code\n"),
        ("countries.csv", b"code,name\n" + _filler() + b"MZ,Mozambique\n"),
        ("first.csv", b"MZ,Mozambique\nZA,South Africa\n"),
        ("rows.json", b'[' + b",".join(b'{"id":%d,"cc":"MZ"}' % i for i in range(80)) + b']'),
        ("rows.jsonl", b"\n".join(b'{"id":%d,"cc":"MZ"}' % i for i in range(80))),
        ("random.txt", b"x" * 700 + b"aMZb" * 50),
    ],
    ids=["txt", "csv-country", "csv-first-cell", "json", "jsonl", "repeated"],
)
def test_mz_text_is_not_pe_evidence(tmp_path, name, payload):
    assert [f for f in _pe_findings(payload, tmp_path, name) if f.severity != "low"] == []


def test_parquet_with_mz_values_is_not_pe_evidence(tmp_path):
    buf = io.BytesIO()
    pd.DataFrame({"cc": ["MZ"] * 500, "n": range(500)}).to_parquet(buf, index=False)
    assert [f for f in _pe_findings(buf.getvalue(), tmp_path, "d.parquet") if f.severity != "low"] == []


def test_csv_with_mz_country_code_scans_clean(tmp_path):
    up = client.post("/api/v1/datasets/upload",
                      files={"file": ("cc.csv", b"MZ,Mozambique\n" + _filler(), "text/csv")})
    assert up.status_code == 201, up.text
    scan = client.post(f"/api/v1/datasets/{up.json()['dataset_id']}/scan").json()
    assert "MAL-002" not in [f["rule_id"] for f in scan["findings"]]
    assert scan["verdict"] != "suspicious"


# ─── real PE structure is still detected ─────────────────────────────────────

def test_valid_embedded_pe_is_reported(tmp_path):
    raw = b"id,blob\n" + _filler() + synthetic_pe_header() + b"\n"
    [finding] = _pe_findings(raw, tmp_path)
    assert finding.severity == "high"
    assert "validated" in finding.description.lower()


def test_valid_pe_at_offset_zero_is_reported(tmp_path):
    [finding] = _pe_findings(synthetic_pe_header(), tmp_path, "x.txt")
    assert finding.severity == "high"


def test_valid_pe_upload_is_still_rejected():
    up = client.post("/api/v1/datasets/upload",
                     files={"file": ("x.csv", synthetic_pe_header(), "text/csv")})
    assert up.status_code == 400


@pytest.mark.parametrize(
    "header",
    [
        synthetic_pe_header(e_lfanew=0xFFFFFF00),              # e_lfanew out of bounds
        synthetic_pe_header(e_lfanew=0x10),                    # inside the DOS header itself
        synthetic_pe_header()[:0x50],                          # truncated before the PE signature
        synthetic_pe_header(signature=b"PEXX"),                # fake PE marker
    ],
    ids=["e_lfanew-out-of-bounds", "e_lfanew-inside-dos-header", "truncated", "fake-pe-marker"],
)
def test_malformed_pe_headers_are_not_high_severity(tmp_path, header):
    embedded = b"id,blob\n" + _filler() + header + b"\n"
    assert [f for f in _pe_findings(embedded, tmp_path) if f.severity != "low"] == []
    at_start = [f for f in _pe_findings(header, tmp_path, "y.txt") if f.severity != "low"]
    assert at_start == []


def test_unvalidated_mz_at_file_start_is_only_a_low_marker(tmp_path):
    findings = _pe_findings(b"MZ\x90\x00 this is not an executable" + b" " * 100, tmp_path, "z.txt")
    assert findings and all(f.severity == "low" for f in findings)
    assert all(f.category == "possible_executable_marker" for f in findings)


def test_eicar_in_a_row_is_still_detected(tmp_path):
    f = tmp_path / "e.csv"
    f.write_bytes(b"id,payload\n1," + EICAR + b"\n")
    assert "MAL-001" in [x.rule_id for x in raw_bytes_scan(f)]
