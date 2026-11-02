#!/usr/bin/env python3
"""验证翻译链路：按线上的真实顺序逐个探测每个源，告诉你哪个能用。

用法：
    python tools/check_translate.py              # 用内置样例
    python tools/check_translate.py "你的英文"    # 翻自己给的文本

退出码：0 = 至少一个源可用；1 = 全部不可用。

走的是 vigil.translate 的真实代码路径，所以这里的结论就等于线上的行为。
"""
from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vigil.translate import build_translator  # noqa: E402

# 样例里故意带上 CVE 编号，顺便验证翻译会不会把它弄丢
SAMPLE = ("CVE-2026-11111: Ivanti Connect Secure Authentication Bypass Vulnerability. "
          "A remote attacker can access restricted resources. It can be chained with "
          "CVE-2026-104935.")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,8}", re.I)

HINTS = {
    "blocked": "网络层被阻断。GitHub runner 上一般是源站按 IP 拒绝；会自动降级到下一个源。",
    "dns": "域名解析失败，多半也是网络限制。",
    "timeout": "连接超时。数据中心 IP 请求 Google 经常这样，会自动降级。",
    "429": "被限流或当日配额用尽。MyMemory 匿名额度约 5000 字符/天，"
           "给 TRANSLATE_EMAIL 配个邮箱可以提到 5 万。",
    "403": "被拒绝。可能是接口策略变了，或文本超过单次上限（MyMemory 是 500 字符）。",
    "shape": "能连上但返回格式变了，说明接口参数或结构被改过。",
}


def classify(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return str(exc.code) if str(exc.code) in HINTS else "blocked"
    if isinstance(exc, urllib.error.URLError):
        reason = str(getattr(exc, "reason", exc)).lower()
        if "timed out" in reason or "timeout" in reason:
            return "timeout"
        if "name or service" in reason or "getaddrinfo" in reason:
            return "dns"
        return "blocked"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ValueError):
        return "shape"
    return "blocked"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="按线上顺序探测翻译源")
    parser.add_argument("text", nargs="*", help="要翻译的英文；省略则用内置样例")
    args = parser.parse_args(argv)

    samples = [" ".join(args.text)] if args.text else [SAMPLE]
    text = samples[0]

    translator = build_translator()
    if translator is None:
        print("TRANSLATE 被设成了 0，翻译功能是关闭的。")
        return 1

    print("翻译链路（按使用顺序）\n")
    working: list[str] = []
    for provider in translator.providers:
        print(f"--- {provider.name} ---")
        print(f"接口：{provider.endpoint}")
        started = time.time()
        try:
            translated = provider.translate(text, None)
        except Exception as exc:  # noqa: BLE001 - 诊断脚本，要如实打印任何异常
            elapsed = time.time() - started
            print(f"❌ 失败：{type(exc).__name__}: {str(exc)[:120]}（{elapsed:.1f}s）")
            print(f"   建议：{HINTS[classify(exc)]}")
        else:
            elapsed = time.time() - started
            working.append(provider.name)
            print(f"✅ 成功，{elapsed:.2f}s")
            print(f"译文：{translated[:120]}")
            missing = {cve.upper() for cve in CVE_RE.findall(text)} - {
                cve.upper() for cve in CVE_RE.findall(translated)}
            if CVE_RE.search(text):
                print(f"CVE 编号保留：{'是' if not missing else '否 → ' + '、'.join(sorted(missing))}")
        print()

    if not working:
        print("结论：所有翻译源都不可用，条目会以英文原文发出。")
        return 1
    if len(working) == len(translator.providers):
        print(f"结论：{len(working)} 个源全部可用，线上会用 {working[0]}。")
    else:
        print(f"结论：可用的是 {'、'.join(working)}；线上会自动跳过不可用的源。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
