"""测试共用的小工具，避免每个测试文件各写一份 FakeResponse / http_error。"""
from __future__ import annotations

import io
import urllib.error
from typing import Any


class FakeResponse:
    """够用的 urlopen 响应替身：read/headers/上下文管理。"""

    def __init__(self, body: bytes, headers: dict[str, str] | None = None, status: int = 200):
        self._body = io.BytesIO(body)
        self.headers = headers or {}
        self.status = status

    def read(self, size=None):
        return self._body.read(size)

    def getheaders(self):
        return list(self.headers.items())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(code: int, headers: Any = None) -> urllib.error.HTTPError:
    # 第 4 个参数官方类型是 email.message.Message，dict 在运行期一样能用
    return urllib.error.HTTPError("https://a.test/x", code, "err",
                                  headers or {}, io.BytesIO(b""))  # type: ignore[arg-type]
