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

# 这些目录里的 .py 不是项目代码：虚拟环境、缓存、构建产物、预览输出。
# 不排除 .venv 的话，本地建过虚拟环境再跑这个脚本就会把 site-packages 当成
# "项目引入了第三方依赖"，CI 绿、本地红，非常误导。
SKIP_DIRS = frozenset({
    "__pycache__", ".git", ".hg", ".svn",
    ".venv", "venv", "env", ".tox", ".nox",
    ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "node_modules", "build", "dist", "preview",
})


def imported_roots(tree: ast.AST) -> list[str]:
    roots: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.extend(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.append(node.module.split(".")[0])
    return roots


def find_violations(root: pathlib.Path) -> list[str]:
    """返回形如 ``path: 包名`` 的违规列表；空列表表示只用了标准库。"""
    stdlib = set(sys.stdlib_module_names)
    bad: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if SKIP_DIRS.intersection(path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            bad.append(f"{path}: 语法错误 {exc}")
            continue
        for name in imported_roots(tree):
            if name not in stdlib and name not in LOCAL:
                bad.append(f"{path}: {name}")
    return bad


def main() -> int:
    bad = find_violations(pathlib.Path("."))
    if bad:
        print("依赖检查未通过：")
        print("\n".join(bad))
        return 1
    print("依赖检查通过：只用标准库")
    return 0


if __name__ == "__main__":
    sys.exit(main())
