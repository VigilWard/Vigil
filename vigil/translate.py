"""把英文标题和摘要翻成中文。

用 Google 的免密钥接口 `translate_a/single`，不需要任何 key 或账号。
它是非公开接口，随时可能失效；所以：任何失败都退化成原文，绝不阻塞推送。
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request

from . import net
from .models import MAX_RESPONSE, Item, log

DEFAULT_ENDPOINT = "https://translate.googleapis.com/translate_a/single"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

REQUEST_TIMEOUT = 6.0     # 单次请求上限，避免网络不通时拖死整轮
MAX_CHARS = 1200          # 单次 GET 的文本上限，超了按句子拆段
MAX_REQUESTS = 100        # 每轮最多请求数（一条标题+摘要算 2 次）
FAILURE_LIMIT = 2         # 连续失败几次就放弃本轮
MIN_INTERVAL = 0.3        # 两次请求的最小间隔，降低被限流的概率


def parse_translation(raw: str) -> str:
    """解析 Google 的嵌套数组：[[["译文","原文",null,null,10]], ...]。

    长文本会被切成多段，每段是数组的第一个元素，拼起来才是完整译文。
    """
    data = json.loads(raw)
    if not isinstance(data, list) or not data or not isinstance(data[0], list):
        raise ValueError("返回结构不是预期的嵌套数组")
    parts = []
    for segment in data[0]:
        if isinstance(segment, list) and segment and isinstance(segment[0], str):
            parts.append(segment[0])
    return "".join(parts).strip()


def split_text(text: str, limit: int = MAX_CHARS) -> list[str]:
    """按句子切分，保证每段都能塞进一个 GET 请求。

    没有句末标点的长文本（CVE 描述里很常见）也必须切开——否则 URL 会超长，
    服务端直接返回 414，而调用方只会看到一次莫名其妙的失败。
    """
    if len(text) <= limit:
        return [text]
    chunks, current = [], ""
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        for piece in _hard_split(sentence, limit):
            if current and len(current) + len(piece) + 1 > limit:
                chunks.append(current)
                current = piece
            else:
                current = f"{current} {piece}".strip()
    if current:
        chunks.append(current)
    return chunks


def _hard_split(text: str, limit: int) -> list[str]:
    """单句超长时按字符硬切（limit 一定 > 0）。"""
    if len(text) <= limit:
        return [text]
    return [text[index:index + limit] for index in range(0, len(text), limit)]


class Translator:
    """Google 免费翻译。一条文本一个请求，没有批量接口。"""

    def __init__(self, endpoint: str = DEFAULT_ENDPOINT, deadline: float | None = None):
        self.endpoint = endpoint
        self.deadline = deadline
        self.requests = 0
        self.failures = 0
        self._last_call = 0.0

    def _throttle(self) -> None:
        gap = time.monotonic() - self._last_call
        if gap < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - gap)

    def _request(self, text: str) -> str:
        query = urllib.parse.urlencode(
            {"client": "gtx", "sl": "en", "tl": "zh-CN", "dt": "t", "q": text},
            quote_via=urllib.parse.quote,
        )
        request = urllib.request.Request(
            f"{self.endpoint}?{query}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        self._throttle()
        self.requests += 1
        self._last_call = time.monotonic()
        timeout = net.request_timeout(self.deadline, REQUEST_TIMEOUT)
        with net.open_url(request, timeout=timeout) as response:
            raw = net.read_limited(response, MAX_RESPONSE, self.deadline)
        return parse_translation(raw.decode("utf-8"))

    def translate_text(self, text: str) -> str:
        """翻一段文本；超长自动拆段后拼接。"""
        text = (text or "").strip()
        if not text:
            return ""
        # 拆段是按句末标点+空格切的，拼回去也要补回空格，否则英文句子会粘在一起
        return " ".join(self._request(chunk) for chunk in split_text(text)).strip()

    def translate(self, items: list[Item]) -> int:
        """原地填充 title_zh / summary_zh，返回翻好的条数。"""
        done = 0
        for item in items:
            if self.requests >= MAX_REQUESTS:
                log(f"⚠ 翻译请求已达上限（{MAX_REQUESTS} 次），本轮剩下的条目保持原文")
                break
            if self.failures >= FAILURE_LIMIT:
                break
            try:
                if not item.title_zh:
                    item.title_zh = self.translate_text(item.title)
                if item.summary and not item.summary_zh:
                    item.summary_zh = self.translate_text(item.summary)
            except Exception as exc:  # 网络、限流、解析失败都退化
                self.failures += 1
                log(f"⚠ 翻译失败：{exc}")
                if self.failures >= FAILURE_LIMIT:
                    log("⚠ 翻译接口连续失败，本轮不再尝试（条目会用英文原文发出）")
                continue
            done += 1
        return done


def build_translator(deadline: float | None = None) -> Translator | None:
    """默认开启；设 TRANSLATE=0 可关闭，端点也可覆盖（例如走镜像或代理）。"""
    if os.environ.get("TRANSLATE", "1").strip().lower() in ("0", "off", "false", "no"):
        return None
    endpoint = (os.environ.get("TRANSLATE_ENDPOINT") or "").strip() or DEFAULT_ENDPOINT
    return Translator(endpoint, deadline)
