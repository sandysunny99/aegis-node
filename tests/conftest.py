"""Aegis Node Test Suite — conftest.py"""
import sys
from pathlib import Path

# Ensure both backend and root (scanner/) are importable
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent))
