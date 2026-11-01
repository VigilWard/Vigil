#!/usr/bin/env python3
"""验证 Google 免费翻译接口（translate_a/single）在当前网络下能不能用。

用法：
    python tools/check_google.py              # 用内置的两段样例（标题 + 摘要）
    python tools/check_google.py "你的英文"    # 翻自己给的文本

退出码：0 = 可用；1 = 不可用（网络不通 / 被限流 / 返回格式变了）。

走的是 vigil.translate.Translator 的真实代码路径，所以它通了就等于线上能翻。
"""
from __future__ import annotations

import argparse
import sys
import time
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vigil.translate import Translator  # noqa: E402

SAMPLES = [
    ("标题", "Ivanti Connect Secure Authentication Bypass Vulnerability"),
    ("摘要",
     "Ivanti Connect Secure contains an authentication bypass that allows a remote "
     "attacker to access restricted resources. This vulnerability can be chained with "
     "CVE-2026-104935 and CVE-2026-111357."),
]

HINTS = {
    "blocked": "网络层被阻断。换网络（手机热点 / 公司 VPN / 海外机器）后重试；"
               "或直接在 GitHub Actions 里跑（mode 选 probe）。",
    "dns": "域名解析失败。多半也是网络限制，换网络后重试。",
    "timeout": "连接超时。可能被墙，也可能代理没放行；换网络重试。",
    "429": "被限流。隔几分钟再试；短时间内频繁调用会被临时封 IP。",
    "403": "被拒绝。可能是 UA 或接口策略变了，换 User-Agent 或改用镜像。",
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
    if isinstance(exc, (TimeoutError,)):
        return "timeout"
    if isinstance(exc, ValueError):
        return "shape"
    return "blocked"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="检查 Google 免费翻译接口是否可用")
    parser.add_argument("text", nargs="*", help="要翻译的英文；省略则用内置样例")
    args = parser.parse_args(argv)

    samples = [("自定义", " ".join(args.text))] if args.text else SAMPLES
    translator = Translator()
    failures = 0

    print(f"接口：{translator.endpoint}")
    print()

    for label, text in samples:
        print(f"--- {label} ---")
        print(f"原文：{text[:100]}{'…' if len(text) > 100 else ''}")
        started = time.time()
        try:
            translated = translator.translate_text(text)
        except Exception as exc:  # noqa: BLE001 - 诊断脚本，要如实打印任何异常
            elapsed = time.time() - started
            key = classify(exc)
            print(f"❌ 失败：{type(exc).__name__}: {str(exc)[:120]}（{elapsed:.1f}s）")
            print(f"   建议：{HINTS[key]}")
            failures += 1
            continue

        elapsed = time.time() - started
        print(f"✅ 成功，{elapsed:.2f}s")
        print(f"译文：{translated}")
        if "CVE-" in text:
            missing = [word for word in text.split()
                       if word.startswith("CVE-") and word not in translated]
            print(f"CVE 编号保留：{'是' if not missing else '否 → ' + '、'.join(missing)}")
        print()

    if failures:
        print(f"结论：{failures} 个样例失败，这个接口在当前网络下不可用。")
        return 1

    print("结论：接口可用，线上翻译能正常工作。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
