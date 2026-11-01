"""HTTP 抓取：安全重定向、条件请求、限流重试、字节上限、编码嗅探。"""
from __future__ import annotations

import gzip
import http.client
import io
import re
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import (
    HTTP_RETRIES,
    HTTP_TIMEOUT,
    MAX_DOWNLOAD,
    MAX_INFLATE,
    RETRY_AFTER_CAP,
    RETRY_BACKOFF,
    RETRY_MAX_WAIT,
    RETRY_STATUS,
    USER_AGENT,
    BudgetExceeded,
    DecodeError,
    FetchError,
    NotModified,
)

ACCEPT = (
    "application/atom+xml, application/rss+xml, application/xml;q=0.9, "
    "text/xml;q=0.9, application/json;q=0.8, text/html;q=0.7, */*;q=0.5"
)

# 这些编码"永远不会解码失败"，一旦谎标就会静默产出乱码，必须放到最后
_LOSSY_SINGLE_BYTE = {"iso-8859-1", "latin-1", "latin1", "cp1252", "windows-1252"}


@dataclass(slots=True)
class Response:
    text: str
    etag: str = ""
    last_modified: str = ""


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    try:
        port = parts.port
    except ValueError as exc:  # 非法端口
        raise FetchError(f"地址端口非法：{url}") from exc
    return scheme, (parts.hostname or "").lower(), port or (443 if scheme == "https" else 80)


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """阻止 HTTPS 降级；跨源跳转时丢掉自定义请求头（可能含 token）。

    只放行 GET 的跨源跳转：源站把 http 跳到 https、或跳到 canonical 域名是常态，
    但 POST（飞书 webhook）绝不允许跨源，避免把消息正文发给第三方。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            old_origin = _origin(req.full_url)
            new_origin = _origin(newurl)
        except FetchError as exc:
            raise urllib.error.HTTPError(newurl, code, str(exc), headers, fp) from exc

        if old_origin[0] == "https" and new_origin[0] != "https":
            raise urllib.error.HTTPError(newurl, code, "拒绝 HTTPS 降级重定向", headers, fp)
        if old_origin != new_origin and req.get_method().upper() != "GET":
            raise urllib.error.HTTPError(newurl, code, "拒绝跨域的非 GET 重定向", headers, fp)

        new_request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_request is not None and old_origin != new_origin:
            for name in list(new_request.headers):
                if name.lower() not in ("user-agent", "accept", "accept-encoding"):
                    del new_request.headers[name]
        return new_request


_OPENER = urllib.request.build_opener(SafeRedirectHandler())


def open_url(request: urllib.request.Request, timeout: float):
    return _OPENER.open(request, timeout=timeout)


def budget_left(deadline: float | None) -> float | None:
    """整轮还剩多少秒；没有 deadline 时返回 None。耗尽则抛 BudgetExceeded。

    注意它返回的是**真实剩余预算**，不带上限。以前这里被当成"可等待时间"用，
    但调用方又传了一个 cap 进来，结果 Retry-After 一超过 cap 就被误判成
    "本轮没预算了"——预算判断必须看真实剩余值。
    """
    if deadline is None:
        return None
    left = deadline - time.monotonic()
    if left <= 0:
        raise BudgetExceeded("整轮时间预算已耗尽")
    return left


def request_timeout(deadline: float | None, cap: float = HTTP_TIMEOUT) -> float:
    """单次请求的超时：不超过 cap，也不超过剩余预算。"""
    left = budget_left(deadline)
    return cap if left is None else min(cap, left)


def decode_bytes(raw: bytes, declared: str | None = None) -> str:
    """按 BOM > XML 声明 > HTTP 头 > 常见编码 的顺序解码。"""
    candidates: list[str] = []
    if raw.startswith(b"\xef\xbb\xbf"):
        candidates.append("utf-8-sig")
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        candidates.append("utf-16")

    xml = re.match(rb"\s*<\?xml[^>]*encoding=[\"']([A-Za-z0-9._-]+)", raw[:200], re.I)
    if xml:
        candidates.append(xml.group(1).decode("ascii", "ignore"))

    charset = (declared or "").strip().strip("'\"").lower()
    if charset in _LOSSY_SINGLE_BYTE and any(byte > 127 for byte in raw[:4096]):
        # 头里写 latin-1 但正文有高位字节，八成是谎标，先按 UTF-8/GB18030 试
        charset = ""
    if charset:
        candidates.append(charset)

    candidates.extend(["utf-8", "gb18030", "big5", "shift_jis", "latin-1"])

    for encoding in dict.fromkeys(candidates):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    raise FetchError("响应字符集无法识别")


def read_limited(stream, limit: int, deadline: float | None) -> bytes:
    """按块读取并强制字节上限，避免被超大响应拖死。"""
    chunks: list[bytes] = []
    total = 0
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            raise BudgetExceeded("读取响应超过整轮时间预算")
        chunk = stream.read(min(65536, limit - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise FetchError(f"响应超过 {limit} 字节上限")
        chunks.append(chunk)
    return b"".join(chunks)


def _inflate_limited(raw: bytes, deadline: float | None) -> bytes:
    """分块解压，解压后同样受 MAX_INFLATE 约束（deflate 炸弹防线）。"""
    engine = zlib.decompressobj(zlib.MAX_WBITS)
    out: list[bytes] = []
    total = 0
    pending = raw
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            raise BudgetExceeded("解压响应超过整轮时间预算")
        chunk = engine.decompress(pending, min(65536, MAX_INFLATE - total + 1))
        pending = engine.unconsumed_tail
        if chunk:
            total += len(chunk)
            if total > MAX_INFLATE:
                raise FetchError(f"解压后超过 {MAX_INFLATE} 字节上限")
            out.append(chunk)
        if pending:
            continue          # 输入还没吃完，接着解
        if engine.eof:
            break
        if not chunk:
            break             # 既没有剩余输入也没有新输出，说明流本身就到这了
        # 输入吃完了但输出被 max_length 截住，用空输入继续榨
    return b"".join(out)


def _decompress(raw: bytes, encoding: str, deadline: float | None) -> bytes:
    encoding = (encoding or "").lower().strip()
    if encoding == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                return read_limited(stream, MAX_INFLATE, deadline)
        except (OSError, EOFError) as exc:
            # 传输被截断是可重试的，所以用 DecodeError 而不是 FetchError
            raise DecodeError(f"gzip 解压失败：{exc}") from exc
    if encoding == "deflate":
        try:
            return _inflate_limited(raw, deadline)
        except zlib.error as exc:
            raise DecodeError(f"deflate 解压失败：{exc}") from exc
    return raw


def retry_after(headers) -> float | None:
    """解析 Retry-After（只支持秒数形式）。"""
    value = headers.get("Retry-After") if headers else None
    if not value:
        return None
    try:
        return max(0.0, float(str(value).strip()))
    except ValueError:
        return None


def fetch(
    url: str,
    *,
    etag: str = "",
    last_modified: str = "",
    headers: dict[str, str] | None = None,
    timeout: float | None = None,
    deadline: float | None = None,
) -> Response:
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": ACCEPT,
        "Accept-Encoding": "gzip",
    }
    if etag:
        request_headers["If-None-Match"] = etag
    if last_modified:
        request_headers["If-Modified-Since"] = last_modified
    if headers:
        request_headers.update(headers)

    last_error = "未知错误"
    for attempt in range(HTTP_RETRIES):
        wait: float | None = None
        try:
            slot = request_timeout(deadline, timeout or HTTP_TIMEOUT)
            try:
                request = urllib.request.Request(url, headers=request_headers)
            except ValueError as exc:
                # 非法 URL / 非法头，重试没有意义
                raise FetchError(f"请求无法构造：{exc}") from exc
            with open_url(request, timeout=slot) as response:
                if getattr(response, "status", 200) == 304:
                    raise NotModified()
                raw = read_limited(response, MAX_DOWNLOAD, deadline)
                raw = _decompress(raw, response.headers.get("Content-Encoding", ""), deadline)
                try:
                    declared = response.headers.get_content_charset()
                except AttributeError:  # 测试里的假响应
                    declared = None
                return Response(
                    decode_bytes(raw, declared),
                    response.headers.get("ETag", "") or "",
                    response.headers.get("Last-Modified", "") or "",
                )
        except NotModified:
            raise
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                raise NotModified() from exc
            last_error = f"HTTP {exc.code}"
            if exc.code not in RETRY_STATUS:
                raise FetchError(last_error) from exc
            wait = retry_after(exc.headers)
        except BudgetExceeded:
            raise
        except ValueError as exc:
            # http.client 在写请求头时才抛的 ValueError，同样不该重试
            raise FetchError(f"请求不合法：{exc}") from exc
        except (urllib.error.URLError, TimeoutError, OSError,
                http.client.HTTPException, EOFError, zlib.error, DecodeError) as exc:
            # DecodeError = 响应体被截断，换一次连接大概率就好了
            last_error = str(getattr(exc, "reason", exc)) or exc.__class__.__name__

        if attempt + 1 >= HTTP_RETRIES:
            break
        if wait is not None:
            if wait > RETRY_AFTER_CAP:
                # 源站要求等太久，与其占着预算干等，不如本轮放弃、下一轮再说
                raise FetchError(
                    f"源站要求 {wait:.0f}s 后重试，超过单次等待上限 {RETRY_AFTER_CAP:.0f}s"
                )
            delay = wait
        else:
            delay = min(RETRY_BACKOFF * (2 ** attempt), RETRY_MAX_WAIT)
        try:
            left = budget_left(deadline)
        except BudgetExceeded:
            break
        if left is not None and delay > left:
            if wait is not None:
                raise FetchError(f"源站要求 {delay:.0f}s 后重试，本轮只剩 {left:.0f}s")
            break
        time.sleep(delay)

    raise FetchError(f"重试 {HTTP_RETRIES} 次仍失败（{last_error}）")
