"""共享类型、常量、异常与日志。

所有可调参数集中在这里，便于一处修改全局生效。
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "config.json"
STATE_FILE = BASE_DIR / "state.json"

# 消息里的时间一律用东八区，不依赖 runner 的 TZ
CST = timezone(timedelta(hours=8))

# ---------------------------------------------------------------- 网络
USER_AGENT = "Vigil/4.0 (personal security feed watcher)"
HTTP_TIMEOUT = 20.0
HTTP_RETRIES = 3
RETRY_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
RETRY_BACKOFF = 1.2
RETRY_MAX_WAIT = 8.0
# 源站明确给了 Retry-After 时最多等这么久；超过就本轮放弃，而不是提前重试去撞墙
RETRY_AFTER_CAP = 30.0
MAX_DOWNLOAD = 16 << 20          # 单个响应体上限（解压前）
MAX_INFLATE = 16 << 20           # 解压后上限，防压缩炸弹
MAX_RESPONSE = 1 << 18           # 飞书响应体上限

# 飞书自定义机器人限流：单机器人 100 次/分钟、5 次/秒。
# 一条公告一条消息，连续发很容易在一秒内打出 6 个请求，所以消息之间留一点间隔。
PUSH_INTERVAL = 0.25

# ---------------------------------------------------------------- 时间预算
# workflow 的 timeout-minutes 是 12，这里留足余量
FETCH_BUDGET = 300.0
RUN_BUDGET = 520.0

# ---------------------------------------------------------------- 健康检查
FAIL_ALERT = 3                   # 连续失败多少轮发告警
SKIP_ALERT = 3                   # 连续被预算跳过多少轮发告警
EMPTY_ALERT = 3                  # 连续多少轮解析不出任何条目
ALERT_REPEAT = 6 * 3600          # 持续故障的重复提醒间隔

# ---------------------------------------------------------------- 状态
SEEN_RETENTION = 90 * 86400      # 已送达记录保留天数
SEEN_REFRESH = 86400             # seen_at 粗粒度刷新间隔，避免每轮都改状态
MAX_SEEN = 20000                 # seen 条目硬上限
PENDING_TTL = 7 * 86400          # 待送达队列最长保留时间
MAX_PENDING = 300                # 待送达队列硬上限
# 公开仓库连续 60 天没有提交会被停掉定时任务；即使没有新条目也每周留一次心跳提交
HEARTBEAT = 7 * 86400
# 时间戳的合理上限（2100-01-01）。超过一律当成"无日期"，避免手工改坏的
# state 里出现 1e400 / 10**400 这类值后进入排序、JSON 和消息头。
MAX_TIMESTAMP = 4102444800

# ---------------------------------------------------------------- 渲染
MAX_TEXT_BYTES = 18000           # 纯文本消息的正文预算（飞书请求体上限 20KB）
MAX_CARD_BODY_BYTES = 14000      # 卡片正文预算：JSON 外壳和转义还要占几 KB
# 一条公告一条消息。飞书自定义机器人限流 5 次/秒、100 次/分钟，
# 30 条 × 0.25s 间隔 ≈ 8 秒，即使同时推 2 个群也还在限额内。
MAX_MESSAGES = 30                # 单轮单目标最多发几条消息
MAX_ITEMS = 12                   # 每个源默认展示条数
MAX_ITEMS_CAP = 50               # limit 上限
MAX_WINDOW_HOURS = 24 * 90
MAX_TITLE_CHARS = 240
MAX_SUMMARY_CHARS = 300
MAX_LINK_CHARS = 600
MAX_UID_CHARS = 512
# 源名会进卡片分组标题、状态告警和 state；限制长度，避免一个超长名字
# 把告警正文撑爆（_send_alerts 按 18KB 分块，但单条告警仍应保持短小）。
MAX_NAME_CHARS = 80
# 单个源的原始文本上限，超过就截断。摘要最终只展示 300 字，没必要为
# 几十万字的 HTML 做十几次正则替换——那是白烧 CPU，也是拒绝服务的入口。
MAX_CLEAN_CHARS = 20000
# 单个源一次最多解析多少条，防止超大 feed 撑爆内存和 state。
# 必须大于 CISA KEV 目录的规模（已超 1000 条），否则每轮都会触发截断告警。
MAX_NODES = 2000


class VigilError(Exception):
    """所有"预期内、可读"错误的基类。"""


class ConfigError(VigilError):
    """配置文件不合法。"""


class StateError(VigilError):
    """state.json 不合法或版本不兼容。"""


class FetchError(VigilError):
    """网络抓取失败。"""


class DecodeError(FetchError):
    """响应体解压失败（多半是传输被截断）。

    单独一个类型是为了让 fetch() 知道"这个错误值得重试"——而"响应超过上限"
    这类确定性失败仍然是 FetchError，重试没有意义。
    """


class ParseError(VigilError):
    """源内容无法解析。"""


class PushError(VigilError):
    """推送到飞书失败。"""


class BudgetExceeded(VigilError):
    """整轮时间预算耗尽。"""


class NotModified(VigilError):
    """服务端返回 304。"""


def sanitize_text(value: str) -> str:
    """清掉无法编码成 UTF-8 的孤立代理项（lone surrogate）。

    JSON 的 ``\\ud800`` 这类转义是合法 JSON，``json.loads`` 会原样产出
    一个孤立代理项；它会让 ``str.encode("utf-8")`` 抛 UnicodeEncodeError，
    进而打挂指纹计算、state 写入和飞书请求体编码。这里统一替换成 ``?``，
    保证进入 Item / Source / state 的文本一定可编码。
    """
    if not isinstance(value, str):
        value = str(value)
    if not value:
        return value
    return value.encode("utf-8", "replace").decode("utf-8")


@dataclass(slots=True)
class Source:
    """一个配置里的数据源。

    身份（key）只由 url + kind + match 决定：改名字、改 limit、改 headers
    都不会让已有基线失效。
    """

    name: str
    url: str
    kind: str = "rss"
    match: str = ""
    limit: int = 0
    exploited: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    mapping: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # 配置和 state 都可能被手工编辑；所有进入身份的文本先保证可编码。
        self.name = sanitize_text(self.name)
        self.url = sanitize_text(self.url)
        self.kind = sanitize_text(self.kind)
        self.match = sanitize_text(self.match)
        self.headers = {
            sanitize_text(key): sanitize_text(value) for key, value in self.headers.items()
        }
        self.mapping = {
            sanitize_text(key): sanitize_text(value) for key, value in self.mapping.items()
        }

    @property
    def key(self) -> str:
        # kind 归一化（枚举值，大小写无意义），match 只去空白。
        # match **不能** 做 casefold/lower：`\D` 和 `\d` 会被折叠成同一个字符串，
        # 两个语义相反的正则就会撞成同一个源身份，配置直接被判"重复"。
        raw = f"{self.url}\x00{self.kind.strip().lower()}\x00{self.match.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


@dataclass(slots=True)
class Item:
    """一条公告。"""

    source_key: str
    source_name: str
    uid: str
    title: str
    link: str = ""
    published: int = 0
    summary: str = ""
    cves: tuple[str, ...] = ()
    exploited: bool = False
    ransomware: bool = False   # CISA KEV 的"已知勒索团伙利用"标记
    severity: int = 0          # 0-4：未知/低/中/高/严重
    cvss: float = 0.0          # CVSS 基础分，取不到为 0
    title_zh: str = ""         # 中文标题（翻译失败时为空，渲染回落原文）
    summary_zh: str = ""       # 中文摘要
    also: tuple[str, ...] = ()       # 合并时记录"另见哪些源"
    # 合并时被吸收掉的条目 key，用于一并确认送达。
    # 只在内存里用（merge() 产出 → compose() 消费），刻意不写进 state：
    # 每次 merge 都会重算，持久化只会让 state 变大且引入过期 key。
    merged: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # 这是最后一道防线：无论 Item 来自解析器、state 还是测试，
        # 都不允许把孤立代理项带进指纹、JSON 或飞书请求体。
        self.source_key = sanitize_text(self.source_key)
        self.source_name = sanitize_text(self.source_name)
        self.uid = sanitize_text(self.uid)
        self.title = sanitize_text(self.title)
        self.link = sanitize_text(self.link)
        self.summary = sanitize_text(self.summary)
        # 字符串是"一个元素"而不是字符序列；直接构造时传 "CVE-..." 不能被拆成单字。
        if isinstance(self.cves, str):
            self.cves = (self.cves,)
        if isinstance(self.also, str):
            self.also = (self.also,)
        if isinstance(self.merged, str):
            self.merged = (self.merged,)
        self.cves = tuple(sanitize_text(cve) for cve in self.cves)
        self.title_zh = sanitize_text(self.title_zh)
        self.summary_zh = sanitize_text(self.summary_zh)
        self.also = tuple(sanitize_text(name) for name in self.also)
        self.merged = tuple(sanitize_text(key) for key in self.merged)
        # 直接构造的 Item 也做一次范围兜底，避免把非法值写进 state。
        # OverflowError 必须单独接住：float("inf") / 10**400 这类值转 int 会抛它，
        # 而它不属于 ValueError，漏掉就会让整轮在构造阶段 traceback。
        try:
            self.published = int(self.published)
        except (TypeError, ValueError, OverflowError):
            self.published = 0
        if not 0 <= self.published < MAX_TIMESTAMP:
            self.published = 0
        # bool 是 int 的子类，True 不能当成等级 1。
        if isinstance(self.severity, bool) or self.severity not in (0, 1, 2, 3, 4):
            self.severity = 0
        try:
            self.cvss = float(self.cvss)
        except (TypeError, ValueError, OverflowError):
            self.cvss = 0.0
        if not math.isfinite(self.cvss) or not 0 <= self.cvss <= 10:
            self.cvss = 0.0

    @property
    def key(self) -> str:
        return f"{self.source_key}:{self.uid}"

    @property
    def fingerprint(self) -> str:
        """内容指纹。标题/链接/编号/在野利用/等级任一变化都算新版本。

        刻意**不含摘要**：不少源会在摘要里塞浏览量、更新时间、缓存标记这类每次都变的
        字段，把它算进去会让同一条公告每轮都被当成新版本，无限重推。
        """
        payload = "\x1f".join(
            (
                self.title,
                self.link,
                ",".join(self.cves),
                "1" if self.exploited else "0",
                "1" if self.ransomware else "0",
                str(self.severity),
                f"{self.cvss:.1f}",
            )
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "source_key": self.source_key,
            "source_name": self.source_name,
            "uid": self.uid,
            "title": self.title,
            "link": self.link,
            "published": self.published,
            "summary": self.summary,
            "cves": list(self.cves),
            "exploited": self.exploited,
            "ransomware": self.ransomware,
            "severity": self.severity,
            "cvss": self.cvss,
            "title_zh": self.title_zh,
            "summary_zh": self.summary_zh,
            "also": list(self.also),
        }

    @classmethod
    def from_dict(cls, data: dict) -> Item:
        if not isinstance(data, dict):
            raise StateError("state 中的条目必须是对象")
        try:
            # 类型必须严格校验：state 可能被手工编辑过，
            # bool("false") 是 True、str(None) 是 "None" 这类静默转换会把脏数据发到群里。
            for name in ("source_key", "source_name", "uid", "title"):
                if not isinstance(data.get(name), str):
                    raise ValueError(f"{name} 必须是字符串")
            for name in ("link", "summary", "title_zh", "summary_zh"):
                if not isinstance(data.get(name, ""), str):
                    raise ValueError(f"{name} 必须是字符串")
            for name in ("exploited", "ransomware"):
                if type(data.get(name, False)) is not bool:
                    raise ValueError(f"{name} 必须是布尔值")
            published = int(data.get("published", 0) or 0)
            raw_severity = data.get("severity", 0)
            if isinstance(raw_severity, bool):
                raise ValueError("severity 不能是布尔值")
            severity = int(raw_severity or 0)
            cvss = float(data.get("cvss", 0) or 0)
            raw_cves = data.get("cves", ())
            raw_also = data.get("also", ())
            if not isinstance(raw_cves, (list, tuple)):
                raise ValueError("cves 必须是数组")
            if not isinstance(raw_also, (list, tuple)):
                raise ValueError("also 必须是数组")
            if not all(isinstance(x, str) for x in raw_cves):
                raise ValueError("cves 的每一项都必须是字符串")
            if not all(isinstance(x, str) for x in raw_also):
                raise ValueError("also 的每一项都必须是字符串")
            if not 0 <= published < MAX_TIMESTAMP:
                raise ValueError(f"published 超出合理范围：{published}")
            if severity not in (0, 1, 2, 3, 4):
                raise ValueError(f"severity 超出 0~4：{severity}")
            if not math.isfinite(cvss) or not 0 <= cvss <= 10:
                raise ValueError(f"cvss 超出 0~10：{cvss}")
            return cls(
                source_key=data["source_key"],
                source_name=data["source_name"],
                uid=data["uid"],
                title=data["title"],
                link=data.get("link", ""),
                published=published,
                summary=data.get("summary", ""),
                cves=tuple(raw_cves),
                exploited=data.get("exploited", False),
                ransomware=data.get("ransomware", False),
                severity=severity,
                cvss=cvss,
                title_zh=data.get("title_zh", ""),
                summary_zh=data.get("summary_zh", ""),
                also=tuple(raw_also),
            )
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise StateError(f"state 中的条目字段无效：{exc}") from exc


@dataclass(slots=True)
class Config:
    sources: list[Source]
    window_hours: int = 48
    max_items: int = MAX_ITEMS


@dataclass(slots=True)
class PushTarget:
    webhook: str
    secret: str = ""

    def __post_init__(self) -> None:
        # Secret 从 JSON 对象里读出来时经常带尾随换行；签名必须用干净的值。
        self.webhook = sanitize_text(self.webhook).strip()
        self.secret = sanitize_text(self.secret).strip()

    @property
    def tid(self) -> str:
        return hashlib.sha256(self.webhook.encode("utf-8")).hexdigest()[:12]


@dataclass(slots=True)
class Failure:
    """一个源的异常记录，用于渲染消息头与退出码判断。"""

    name: str
    key: str
    detail: str = ""


@dataclass(slots=True)
class Report:
    items: list[Item] = field(default_factory=list)
    failures: list[Failure] = field(default_factory=list)
    skipped: list[Failure] = field(default_factory=list)


def log(*args: object) -> None:
    """带时间戳写到 stdout；日志里不出现任何密钥或条目内容。"""
    try:
        stamp = datetime.now(CST).strftime("%H:%M:%S")
        print(f"[{stamp}]", *args, file=sys.stdout, flush=True)
    except Exception:  # pragma: no cover - 极端情况下日志失败不应影响主流程
        pass


def dump_json(data: object, *, indent: int | None = None) -> str:
    text = json.dumps(data, ensure_ascii=False, indent=indent, sort_keys=True)
    # 兜底：即使有漏网的孤立代理项，也不能让 state 写入在 encode 时崩掉。
    return text.encode("utf-8", "replace").decode("utf-8")


def shorten(text: str, limit: int) -> str:
    """按字符截断，超长时以省略号结尾。

    解析层和渲染层都要用（标题、摘要、链接），实现放在这里避免两份逻辑跑偏。
    """
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit == 1:
        return text[:1]
    return text[: limit - 1] + "…"
