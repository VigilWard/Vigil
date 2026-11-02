"""HTTP 抓取：安全重定向、条件请求、限流重试、字节上限、编码嗅探。"""
from __future__ import annotations

import gzip
import http.client
import io
import ipaddress
import os
import re
import socket
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
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
# UTF-8 的各种写法；声明成这些时优先按 UTF-8 处理
_UTF8_ALIASES = frozenset({"utf-8", "utf8", "utf_8", "utf-8-sig", "utf8mb4"})


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


def allow_private_hosts() -> bool:
    """是否允许抓取本机/私网地址。

    默认拒绝：配置里写内网地址通常意味着误配，而且能让恶意配置去读
    云厂商元数据接口。确实要抓内网源时显式设 `VIGIL_ALLOW_PRIVATE_HOSTS=1`。
    """
    return os.environ.get("VIGIL_ALLOW_PRIVATE_HOSTS", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def is_blocked_host(host: str) -> bool:
    """判断主机名是否是本机/私网/链路本地地址。

    只做字面 IP 和常见本地域名判断；不做 DNS 解析，避免在重定向处理器里
    引入不可控的阻塞。真正的 DNS rebinding 仍需网络层 egress 策略兜底。
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host in {"localhost", "localhost.localdomain", "metadata.google.internal", "metadata.goog"}:
        return True
    if host.endswith((".localhost", ".local", ".internal")):
        return True
    if "%" in host:  # IPv6 zone id，常见于链路本地地址
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # urllib 最终会走 getaddrinfo，而 inet_aton 接受 127.1、2130706433、
        # 0x7f000001 这类 IPv4 简写；不补这一步，SSRF 防护会被简写绕过。
        try:
            address = ipaddress.ip_address(socket.inet_aton(host))
        except (OSError, UnicodeError):
            return False
    return not address.is_global


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """阻止 HTTPS 降级；跨主机跳转时丢掉自定义请求头（可能含 token）。

    只放行 GET 的跨源跳转：源站把 http 跳到 https、或跳到 canonical 域名是常态，
    但 POST（飞书 webhook）绝不允许跨源，避免把消息正文发给第三方。

    请求头按**主机名**判断是否保留：同一主机从 http 升级到 https 是常见的
    canonical 跳转，不该把 Authorization 一起丢掉（以前按 scheme+port 比较，
    升级后端口从 80 变 443，鉴权头被误删，源站直接 401）。
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            old_origin = _origin(req.full_url)
            new_origin = _origin(newurl)
        except FetchError as exc:
            raise urllib.error.HTTPError(newurl, code, str(exc), headers, fp) from exc

        if new_origin[0] not in ("http", "https") or is_blocked_host(new_origin[1]):
            raise urllib.error.HTTPError(
                newurl, code, "拒绝重定向到非 HTTP(S) 或非公网地址", headers, fp
            )
        if old_origin[0] == "https" and new_origin[0] != "https":
            raise urllib.error.HTTPError(newurl, code, "拒绝 HTTPS 降级重定向", headers, fp)
        # POST 比 GET 更严格：只要 scheme/host/port 任一变化就拒绝。
        if old_origin != new_origin and req.get_method().upper() != "GET":
            raise urllib.error.HTTPError(newurl, code, "拒绝跨域的非 GET 重定向", headers, fp)

        new_request = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_request is not None and new_origin[1] != old_origin[1]:
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


def _forgiving_utf8(raw: bytes) -> str | None:
    """整篇基本是合法 UTF-8、只有零星坏字节时，用替换字符解码。

    如果直接让 gb18030 接手，一个坏字节就能把整篇中文解释成另一套编码的乱码，
    而且不报任何错。这里用"坏字节占比"判断：只有极少数替换符时仍按 UTF-8 解。
    """
    text = raw.decode("utf-8", "replace")
    bad = text.count("\ufffd")
    if bad <= 3 or bad * 1000 <= len(raw):
        return text
    return None


def decode_bytes(raw: bytes, declared: str | None = None) -> str:
    """按 BOM > 声明编码 > UTF-8 > 常见编码 的顺序解码。

    关键取舍：
      1. BOM 和明确的非 UTF-8 声明优先，避免把 GBK 正文误当 UTF-8；
      2. 声明 UTF-8 但只有个别坏字节时，用替换解码，而不是整篇退回 gb18030；
      3. 没有可用声明时先试 UTF-8，再试中文/日文传统编码，最后 latin-1 兜底。
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")

    xml = re.match(rb"\s*<\?xml[^>]*encoding=[\"']([A-Za-z0-9._-]+)", raw[:200], re.I)
    xml_encoding = xml.group(1).decode("ascii", "ignore").lower() if xml else ""
    charset = (declared or "").strip().strip("'\"").lower()

    high_bytes = any(byte > 127 for byte in raw[:4096])
    declared_encodings: list[str] = []
    for encoding in (xml_encoding, charset):
        if not encoding:
            continue
        # 头里写 latin-1 但正文有高位字节，八成是谎标：这种编码"永远能解码成功"，
        # 直接信它会静默产出乱码，所以跳过，交给后面的 UTF-8/GB18030 判断。
        if encoding in _LOSSY_SINGLE_BYTE and high_bytes:
            continue
        if encoding not in declared_encodings:
            declared_encodings.append(encoding)

    if declared_encodings:
        # XML 声明比 HTTP 头更可信，所以列表第一项是主声明。
        if declared_encodings[0] in _UTF8_ALIASES:
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                text = _forgiving_utf8(raw)
                if text is not None:
                    return text
            # 声明 UTF-8 但坏字节太多，继续试其它声明（例如头里的 gbk）。
            remaining = declared_encodings[1:]
        else:
            remaining = declared_encodings
        for encoding in remaining:
            try:
                return raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue

    # 没有 NUL 才可能是 UTF-8；UTF-16/32 的字节流里全是 NUL，不能走这条路。
    if b"\x00" not in raw[:1024]:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
        text = _forgiving_utf8(raw)
        if text is not None:
            return text

    for encoding in ("gb18030", "big5", "shift_jis"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    # latin-1 能解码任意字节，是最后的兜底；放在循环外，避免"永远成功"
    # 让循环里的失败分支看起来像死代码。
    return raw.decode("latin-1")


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
    if not engine.eof:
        # gzip 截断会抛 EOFError，deflate 不会：它只是安静地返回半截内容。
        # 不在这里判定，半截 XML/JSON 会被当成"解析失败"，重试也不会发生。
        raise DecodeError("deflate 流不完整（传输可能被截断）")
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
    """解析 Retry-After：秒数或 HTTP-date 两种形式（RFC 9110）。

    只认秒数会让 `Retry-After: Wed, 21 Oct 2026 07:28:00 GMT` 被当成"没有提示"，
    退化成指数退避去撞限流。HTTP-date 按与当前时间的差值折算成秒。
    """
    value = headers.get("Retry-After") if headers else None
    if not value:
        return None
    text = str(value).strip()
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    try:
        return max(0.0, when.timestamp() - time.time())
    except (OverflowError, OSError, ValueError):
        return None


def _http_error_text(exc: urllib.error.HTTPError) -> str:
    """把 HTTPError 压成一行可读信息。

    只写 `HTTP 302` 会把重定向处理器给出的原因（"拒绝重定向到非公网地址"）
    丢掉，线上日志里根本看不出是被安全策略拦了还是源站真的返回 302。
    """
    reason = str(getattr(exc, "reason", "") or "").strip()
    return f"HTTP {exc.code}：{reason}" if reason else f"HTTP {exc.code}"


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

    # 初始地址也要过 SSRF 检查：以前只检查重定向，配置里写内网/元数据地址
    # 会被直接抓取并可能随消息外带。内网源用 VIGIL_ALLOW_PRIVATE_HOSTS=1 放行。
    if not allow_private_hosts():
        _, host, _ = _origin(url)
        if is_blocked_host(host):
            raise FetchError(f"拒绝访问本机或私网地址：{host or url}")

    last_error = "未知错误"
    attempts = 0
    for attempt in range(HTTP_RETRIES):
        attempts += 1
        wait: float | None = None
        try:
            slot = request_timeout(deadline, timeout or HTTP_TIMEOUT)
            try:
                request = urllib.request.Request(url, headers=request_headers)
            except ValueError as exc:
                # 非法 URL / 非法头，重试没有意义
                raise FetchError(f"请求无法构造：{exc}") from exc
            with open_url(request, timeout=slot) as response:
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
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                raise NotModified() from exc
            last_error = _http_error_text(exc)
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
        # 预算耗尽必须原样抛出：调用方会把它记成"本轮跳过"，
        # 而不是"抓取失败"。以前在这里 break 成 FetchError，既会谎报重试次数，
        # 又会让一个只是没排上队的源累积 fail 计数、触发假告警。
        left = budget_left(deadline)
        if left is not None and delay > left:
            if wait is not None:
                raise FetchError(f"源站要求 {delay:.0f}s 后重试，本轮只剩 {left:.0f}s")
            # 退避都等不起：这一轮并没有真正检查完这个源，按"预算跳过"处理，
            # 而不是记成抓取失败（否则会累积 fail 计数、触发假告警）。
            raise BudgetExceeded(f"重试需等待 {delay:.1f}s，本轮只剩 {left:.1f}s")
        time.sleep(delay)

    raise FetchError(f"已尝试 {attempts} 次仍失败（{last_error}）")
