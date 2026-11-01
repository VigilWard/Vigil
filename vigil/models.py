"""共享类型、常量、异常与日志。

所有可调参数集中在这里，便于一处修改全局生效。
"""
from __future__ import annotations

import hashlib
import json
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
# 多页 + 多群时很容易在一秒内打出 6 个请求，所以页与页之间留一点间隔。
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

# ---------------------------------------------------------------- 渲染
MAX_TEXT_BYTES = 18000           # 纯文本消息的正文预算（飞书请求体上限 20KB）
MAX_CARD_BODY_BYTES = 14000      # 卡片正文预算：JSON 外壳和转义还要占几 KB
MAX_PAGES = 3                    # 单轮单目标最多发几页
MAX_ITEMS = 12                   # 每个源默认展示条数
MAX_ITEMS_CAP = 50               # limit 上限
MAX_WINDOW_HOURS = 24 * 90
MAX_TITLE_CHARS = 240
MAX_SUMMARY_CHARS = 300
MAX_LINK_CHARS = 600
MAX_UID_CHARS = 512
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
            return cls(
                source_key=str(data["source_key"]),
                source_name=str(data["source_name"]),
                uid=str(data["uid"]),
                title=str(data["title"]),
                link=str(data.get("link", "")),
                published=int(data.get("published", 0) or 0),
                summary=str(data.get("summary", "")),
                cves=tuple(str(x) for x in data.get("cves", ())),
                exploited=bool(data.get("exploited", False)),
                ransomware=bool(data.get("ransomware", False)),
                severity=int(data.get("severity", 0) or 0),
                cvss=float(data.get("cvss", 0) or 0),
                title_zh=str(data.get("title_zh", "")),
                summary_zh=str(data.get("summary_zh", "")),
                also=tuple(str(x) for x in data.get("also", ())),
            )
        except (KeyError, TypeError, ValueError) as exc:
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
    return json.dumps(data, ensure_ascii=False, indent=indent, sort_keys=True)


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
