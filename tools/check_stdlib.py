#!/usr/bin/env python3
"""检查项目是否只用了标准库——"零第三方依赖"是 README 的承诺，不能悄悄破。

用法：
    python tools/check_stdlib.py

退出码：0 = 只用了标准库；1 = 引入了第三方依赖（会列出文件和包名）。
"""
from __future__ import annotations

import ast
import pathlib
import sys

LOCAL = {"vigil", "tests", "tools", "watch"}


def imported_roots(tree: ast.AST) -> list[str]:
    roots: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.append(node.module.split(".")[0])
    return roots


def main() -> int:
    stdlib = set(sys.stdlib_module_names)
    bad: list[str] = []
    for path in sorted(pathlib.Path(".").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            print(f"{path}: 语法错误 {exc}")
            return 1
        for name in imported_roots(tree):
            if name not in stdlib and name not in LOCAL:
                bad.append(f"{path}: {name}")

    if bad:
        print("引入了第三方依赖：")
        print("\n".join(bad))
        return 1
    print("依赖检查通过：只用标准库")
    return 0


if __name__ == "__main__":
    sys.exit(main())
