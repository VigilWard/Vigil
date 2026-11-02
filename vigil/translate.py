"""把英文标题和摘要翻成中文，带多源自动降级。

为什么要有多个源：Google 的免密钥接口 `translate_a/single` 是非公开的，
从数据中心 IP（GitHub Actions 的 runner 就在 Azure 机房）请求时经常被 429 或直接
挡掉。一旦它挂了，整条消息就静默变成英文——没有任何报错，很难发现。

所以这里按顺序尝试多个源，前一个连续失败就自动换下一个：

    google   质量最好，但最容易被挡
    baidu    可选，配了 APPID/KEY 才启用，机房 IP 也能用
    mymemory 社区翻译记忆库，无需 key，单次上限 500 字符

全部失败时退化成原文，绝不阻塞推送。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.parse
import urllib.request

from . import net
from .models import MAX_RESPONSE, BudgetExceeded, Item, log

DEFAULT_ENDPOINT = "https://translate.googleapis.com/translate_a/single"
MYMEMORY_ENDPOINT = "https://api.mymemory.translated.net/get"
BAIDU_ENDPOINT = "https://fanyi-api.baidu.com/api/trans/vip/translate"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

REQUEST_TIMEOUT = 6.0     # 单次请求上限，避免网络不通时拖死整轮
# 单次 GET 的文本上限。MyMemory 硬限制 500 字符，超过直接返回 403，
# 所以这里取 450，两个源都塞得下。
MAX_CHARS = 450
MAX_REQUESTS = 100        # 每轮最多请求数（一条标题+摘要算 2 次）
FAILURE_LIMIT = 2         # 连续几条翻不出来就放弃本轮
PROVIDER_STRIKES = 2      # 单个源连续失败几次就本轮停用
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


def parse_mymemory(raw: str) -> str:
    """解析 MyMemory 的 {responseStatus, responseData:{translatedText}}。

    配额用尽时它返回 HTTP 200 + responseStatus 429，所以必须看业务码，
    不能只看 HTTP 状态。
    """
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("返回结构不是对象")
    status = data.get("responseStatus")
    detail = data.get("responseDetails") or ""
    text = ((data.get("responseData") or {}).get("translatedText") or "").strip()
    if status != 200 or not text:
        raise ValueError(f"status={status} {detail}".strip())
    return text


def parse_baidu(raw: str) -> str:
    """解析百度通用翻译的 {trans_result:[{src,dst}], error_code?}。

    出错时它同样返回 HTTP 200，靠 error_code 区分（54001 签名错、54003 限流、
    54004 余额不足），所以必须查 error_code。
    """
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("返回结构不是对象")
    if "error_code" in data:
        raise ValueError(f"百度返回 {data['error_code']}：{data.get('error_msg', '')}")
    rows = data.get("trans_result")
    if not isinstance(rows, list) or not rows:
        raise ValueError("百度返回里没有 trans_result")
    text = "".join(
        row.get("dst", "") for row in rows if isinstance(row, dict)
    ).strip()
    if not text:
        raise ValueError("百度返回空译文")
    return text


def split_text(text: str, limit: int = MAX_CHARS) -> list[str]:
    """按句子切分，保证每段都能塞进一个 GET 请求。

    没有句末标点的长文本（CVE 描述里很常见）也必须切开——否则 URL 会超长，
    服务端直接返回 414 或 403，而调用方只会看到一次莫名其妙的失败。
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


class Provider:
    """一个翻译源：负责拼请求、解析响应。失败时抛异常，由上层切换到下一个源。"""

    name = "?"
    # 两次请求之间的最小间隔（秒）。各家的 QPS 限制不一样，必须分开算，
    # 否则一个慢源会被另一个快源的节流"带跑"，直接撞限流。
    min_interval = MIN_INTERVAL
    # 单次请求超时。正常响应的源用默认值；经常挂的源单独调小，
    # 免得每轮都白等满一个超时。
    timeout = REQUEST_TIMEOUT

    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    def _fetch(self, url: str, deadline: float | None,
               data: bytes | None = None) -> str:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
        request = urllib.request.Request(
            url, data=data, headers=headers, method="POST" if data else "GET",
        )
        timeout = net.request_timeout(deadline, self.timeout)
        with net.open_url(request, timeout=timeout) as response:
            raw = net.read_limited(response, MAX_RESPONSE, deadline)
        return raw.decode("utf-8", "replace")

    def translate(self, text: str, deadline: float | None) -> str:
        raise NotImplementedError


class GoogleProvider(Provider):
    """Google 的免密钥接口。质量最好，也最容易被数据中心 IP 挡。

    超时刻意只给 3 秒：它正常时 0.5–1 秒就返回，而不通时每轮要被撞两次，
    6 秒的默认值会白等 12 秒。缩到 3 秒能把"质量优先"的代价压到可接受范围。
    """

    name = "google"
    timeout = 3.0

    def translate(self, text: str, deadline: float | None) -> str:
        query = urllib.parse.urlencode(
            {"client": "gtx", "sl": "en", "tl": "zh-CN", "dt": "t", "q": text},
            quote_via=urllib.parse.quote,
        )
        return parse_translation(self._fetch(f"{self.endpoint}?{query}", deadline))


class MyMemoryProvider(Provider):
    """MyMemory：社区翻译记忆库，无需 key。

    匿名配额按 IP 算（约 5000 字符/天），带上 `de=邮箱` 可以提到 5 万。
    """

    name = "mymemory"

    def __init__(self, endpoint: str, email: str = ""):
        super().__init__(endpoint)
        self.email = email

    def translate(self, text: str, deadline: float | None) -> str:
        params = {"q": text, "langpair": "en|zh-CN"}
        if self.email:
            params["de"] = self.email
        query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        return parse_mymemory(self._fetch(f"{self.endpoint}?{query}", deadline))


class BaiduProvider(Provider):
    """百度通用翻译。需要 APPID + 密钥，签名是 md5(appid + 原文 + salt + 密钥)。

    中文质量比免费源好，而且不会像 Google 那样被机房 IP 挡；缺点是文本会
    发往百度（隐私提醒见 README）。

    标准版 QPS = 1，实测间隔 1.05 秒偶尔还会撞 54003，1.2 秒才稳定，
    所以这里留 1.2。实名认证升级到高级版后 QPS 会放宽，可以把这里调小。
    """

    name = "baidu"
    min_interval = 1.2

    def __init__(self, endpoint: str, appid: str, key: str):
        super().__init__(endpoint)
        self.appid = appid
        self.key = key

    def translate(self, text: str, deadline: float | None) -> str:
        salt = str(int(time.time() * 1000))
        sign = hashlib.md5(
            f"{self.appid}{text}{salt}{self.key}".encode()
        ).hexdigest()
        payload = urllib.parse.urlencode({
            "q": text, "from": "en", "to": "zh",
            "appid": self.appid, "salt": salt, "sign": sign,
        }).encode()
        return parse_baidu(self._fetch(self.endpoint, deadline, data=payload))


class Translator:
    """按顺序尝试多个翻译源，前一个连续失败就自动换下一个。"""

    def __init__(self, providers: list[Provider] | None = None, deadline: float | None = None):
        self.providers = providers if providers is not None else [GoogleProvider(DEFAULT_ENDPOINT)]
        self.deadline = deadline
        self.requests = 0
        self.failures = 0
        self._strikes: dict[str, int] = {}
        self._current = ""
        self._last_call: dict[str, float] = {}

    def _throttle(self, provider: Provider) -> None:
        """按每个源自己的最小间隔等待。QPS 限制是各算各的。"""
        gap = time.monotonic() - self._last_call.get(provider.name, 0.0)
        if gap < provider.min_interval:
            time.sleep(provider.min_interval - gap)
        self._last_call[provider.name] = time.monotonic()

    def _one(self, text: str) -> str:
        """翻一段；按 providers 顺序试，全挂才抛异常。"""
        errors: list[str] = []
        for provider in self.providers:
            if self._strikes.get(provider.name, 0) >= PROVIDER_STRIKES:
                continue
            if self.deadline is not None and time.monotonic() >= self.deadline:
                raise BudgetExceeded("翻译时间预算已耗尽")
            self._throttle(provider)
            self.requests += 1
            try:
                result = provider.translate(text, self.deadline)
            except BudgetExceeded:
                # 时间预算耗尽不是翻译源故障，不能算 strike，也不能换源重试。
                raise
            except Exception as exc:  # noqa: BLE001 - 换下一个源，不让单点故障中断
                strikes = self._strikes.get(provider.name, 0) + 1
                self._strikes[provider.name] = strikes
                errors.append(f"{provider.name}: {exc}")
                if strikes >= PROVIDER_STRIKES:
                    log(f"⚠ 翻译源 {provider.name} 连续失败 {strikes} 次，本轮停用")
                else:
                    log(f"⚠ 翻译源 {provider.name} 失败：{exc}")
                continue
            self._strikes[provider.name] = 0
            if self._current != provider.name:
                # 只在真的切换时打一行，避免每条都刷屏
                log(f"   翻译源：{provider.name}")
                self._current = provider.name
            return result
        raise RuntimeError("；".join(errors) or "没有可用的翻译源")

    def translate_text(self, text: str) -> str:
        """翻一段文本；超长自动拆段后拼接。"""
        text = (text or "").strip()
        if not text:
            return ""
        # 拆段是按句末标点+空格切的，拼回去也要补回空格，否则英文句子会粘在一起
        return " ".join(self._one(chunk) for chunk in split_text(text)).strip()

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
            except BudgetExceeded:
                log("⚠ 翻译超出本轮时间预算，停止翻译（条目会用原文发出）")
                break
            except Exception as exc:  # noqa: BLE001 - 所有源都挂了，退化成原文
                self.failures += 1
                log(f"⚠ 翻译失败：{exc}")
                if self.failures >= FAILURE_LIMIT:
                    log("⚠ 所有翻译源都不可用，本轮不再尝试（条目会用英文原文发出）")
                continue
            done += 1
        return done


def build_translator(deadline: float | None = None) -> Translator | None:
    """默认开启；设 TRANSLATE=0 可关闭。

    顺序：Google（质量最好）→ 百度（配了 key 才有，稳、不会被机房 IP 挡）→ MyMemory。
    Google 排第一是因为它译文最准，代价是经常被限流——所以它的超时缩到 3 秒，
    不通时每轮只白等 6 秒左右，然后自动落到百度。

    可选环境变量：
        BAIDU_APPID / BAIDU_KEY   百度通用翻译的凭据，放 GitHub Secrets
        TRANSLATE_ENDPOINT        覆盖 Google 的地址（镜像或代理）
        TRANSLATE_EMAIL           传给 MyMemory 的 `de` 参数，配额 5 千 → 5 万字符/天
    """
    if os.environ.get("TRANSLATE", "1").strip().lower() in ("0", "off", "false", "no"):
        return None

    google_endpoint = (os.environ.get("TRANSLATE_ENDPOINT") or "").strip() or DEFAULT_ENDPOINT
    email = (os.environ.get("TRANSLATE_EMAIL") or "").strip()
    appid = (os.environ.get("BAIDU_APPID") or "").strip()
    baidu_key = (os.environ.get("BAIDU_KEY") or "").strip()

    providers: list[Provider] = [GoogleProvider(google_endpoint)]
    if appid and baidu_key:
        providers.append(BaiduProvider(BAIDU_ENDPOINT, appid, baidu_key))
    providers.append(MyMemoryProvider(MYMEMORY_ENDPOINT, email))
    return Translator(providers, deadline)
