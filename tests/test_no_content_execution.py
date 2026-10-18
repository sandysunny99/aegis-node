"""
Phase D guard: no code path may execute, evaluate, deserialize or shell out on
uploaded content. This is a static check over the scanner and backend source, so a
future change that adds such a call fails here and has to be reviewed explicitly.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNED = [ROOT / "scanner", ROOT / "backend" / "routers", ROOT / "backend" / "services", ROOT / "backend" / "utils"]

FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTRS = {
    ("pickle", "load"), ("pickle", "loads"), ("marshal", "loads"), ("os", "system"),
    ("os", "popen"), ("importlib", "import_module"),
}
FORBIDDEN_MODULES = {"subprocess", "pickle", "marshal", "shelve", "dill", "cloudpickle"}

# Reviewed exceptions as (file, call). Empty: re.compile / yara.compile are attribute
# calls and are not matched by the bare-name check.
ALLOWED: set[tuple[str, str]] = set()


def _python_files():
    for base in SCANNED:
        yield from base.rglob("*.py")


def test_no_dangerous_calls_or_imports():
    problems = []
    for path in _python_files():
        rel = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in FORBIDDEN_CALLS and (rel, fn.id) not in ALLOWED:
                    problems.append(f"{rel}:{node.lineno} calls {fn.id}()")
                if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                        and (fn.value.id, fn.attr) in FORBIDDEN_ATTRS):
                    problems.append(f"{rel}:{node.lineno} calls {fn.value.id}.{fn.attr}()")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                        problems.append(f"{rel}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in FORBIDDEN_MODULES:
                    problems.append(f"{rel}:{node.lineno} imports from {node.module}")
    assert problems == [], "\n".join(problems)


def test_xlsx_formulas_are_read_not_evaluated():
    """openpyxl never evaluates formulas; make sure no formula engine is imported."""
    source = (ROOT / "scanner" / "content_checker.py").read_text(encoding="utf-8")
    for engine in ("formulas", "pycel", "xlcalculator", "win32com"):
        assert f"import {engine}" not in source
