"""
B2: XLSX coverage must say what was actually inspected. Every sheet is read, row
limits are explicit, an over-limit workbook is PARTIAL, and archives that are
malformed or would decompress past the limit are reported as not inspected.
"""

import io
import zipfile

import pytest
from openpyxl import Workbook

from scanner.content_checker import check_file


def _workbook(tmp_path, sheets: dict[str, list[list]], name="w.xlsx"):
    wb = Workbook()
    wb.remove(wb.active)
    for title, rows in sheets.items():
        ws = wb.create_sheet(title)
        for row in rows:
            ws.append(row)
    path = tmp_path / name
    wb.save(path)
    return path


def _rows(n, start=0):
    return [["id", "name"]] + [[i, f"user{i}"] for i in range(start, start + n)]


@pytest.fixture
def small_limit(monkeypatch):
    monkeypatch.setattr("scanner.content_checker._MAX_ROWS", 5)


def _coverage(path):
    res = check_file(str(path))
    return res.coverage_status, res.rows_inspected, res.rows_total, res


@pytest.mark.parametrize(("n", "expected"), [(3, ("FULL", 3, 3)), (5, ("FULL", 5, 5))],
                         ids=["below-limit", "at-limit"])
def test_rows_within_the_limit_are_full(tmp_path, small_limit, n, expected):
    status, inspected, total, _ = _coverage(_workbook(tmp_path, {"S1": _rows(n)}))
    assert (status, inspected, total) == expected


def test_rows_over_the_limit_are_partial_and_say_which_limit(tmp_path, small_limit):
    status, inspected, total, res = _coverage(_workbook(tmp_path, {"S1": _rows(8)}))
    assert (status, inspected, total) == ("PARTIAL", 5, 8)
    assert "PARTIAL_DATASET_SCAN" in res.limitations
    assert any(lim.startswith("INSPECTION_LIMIT:xlsx_rows=5") for lim in res.limitations)


def test_every_sheet_is_inspected(tmp_path):
    path = _workbook(tmp_path, {
        "clean": _rows(3),
        "second": [["id", "formula"], [1, '=CMD("calc.exe")']],
    })
    status, inspected, total, res = _coverage(path)
    assert (status, inspected, total) == ("FULL", 4, 4)
    assert any(f.rule_id.startswith("FORM-") for f in res.findings)
    assert any("second" in f.location for f in res.findings)


def test_suspicious_cell_beyond_the_limit_is_not_claimed_clean(tmp_path, small_limit):
    rows = _rows(6) + [[99, '=CMD("calc.exe")']]
    status, _, total, res = _coverage(_workbook(tmp_path, {"S1": rows}))
    assert status == "PARTIAL" and total == 7
    assert not any(f.rule_id.startswith("FORM-") for f in res.findings)


def test_truncated_workbook_is_not_inspected(tmp_path):
    good = _workbook(tmp_path, {"S1": _rows(20)})
    cut = tmp_path / "cut.xlsx"
    cut.write_bytes(good.read_bytes()[: good.stat().st_size // 2])
    status, inspected, _, res = _coverage(cut)
    assert status == "UNKNOWN" and inspected == 0
    assert "PARSER_LIMITATION" in res.limitations


def test_malformed_archive_is_not_inspected(tmp_path):
    bad = tmp_path / "bad.xlsx"
    bad.write_bytes(b"PK\x03\x04 this is not a workbook" * 10)
    status, _, _, res = _coverage(bad)
    assert status == "UNKNOWN"
    assert "PARSER_LIMITATION" in res.limitations


def test_archive_that_would_decompress_past_the_limit_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("scanner.content_checker._XLSX_MAX_UNCOMPRESSED_BYTES", 1024 * 1024)
    path = _workbook(tmp_path, {"S1": _rows(3)})
    buf = io.BytesIO(path.read_bytes())
    with zipfile.ZipFile(buf, "a", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/media/padding.bin", b"\0" * (3 * 1024 * 1024))
    bomb = tmp_path / "bomb.xlsx"
    bomb.write_bytes(buf.getvalue())
    status, inspected, _, res = _coverage(bomb)
    assert status == "UNKNOWN" and inspected == 0
    assert any("XLSX_DECOMPRESSION_LIMIT" in (res.error or "") for _ in [0])
