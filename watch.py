#!/usr/bin/env python3
"""Vigil 命令行入口，真正的实现都在 vigil 包里。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vigil.app import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
