"""把条目渲染成飞书消息：一条公告一条消息。

为什么不把多条塞进一张卡片：
  一张卡片里按「源 → 等级」分组，普通漏洞会把高危漏洞夹在中间，扫消息时
  很难一眼挑出来。拆成一条一条之后，每张卡片自己的头部配色、图标和副标题
  都在说"这条有多要紧"，等级再也不会被邻居淹没。

同一份内容有两种输出：
  markup=True   → 卡片用的 lark_md（加粗标题、等级着色）
  markup=False  → 纯文本（--dry-run 在终端里看，或临时切回文本消息）
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from .models import (
    CST,
    MAX_CARD_BODY_BYTES,
    MAX_ITEMS,
    MAX_LINK_CHARS,
    MAX_MESSAGES,
    MAX_SUMMARY_CHARS,
    MAX_TITLE_CHARS,
    Config,
    Failure,
    Item,
    log,
    shorten,
)

CVE_TITLE_PREFIX = re.compile(r"^(?:CVE-\d{4}-\d{4,8}[\s:：]+)+", re.I)
SEVERITY_LABELS = {1: "低", 2: "中", 3: "高", 4: "严重"}
# 卡片头部只能放纯文本，颜色又不能只靠模板色区分（蓝底同时覆盖中/低/未知），
# 所以标题前面再加一个字符标记，扫消息列表时不用点开也能看出等级。
SEVERITY_ICONS = {1: "⚪", 2: "🟡", 3: "🟠", 4: "🔴"}
EXPLOITED_ICON = "🚨"
# 卡片头部标题只用来"认消息"，不承载全文；正文里的【标题原文】才是完整版。
HEADER_TITLE_CHARS = 60

# 飞书的 lark_md 不支持反斜杠转义，官方要求把命中的特殊字符换成 HTML 实体，
# 否则标题里的 * 会把后面的文字吃掉。& 必须一起换，避免二次解析。
_MD_ESCAPES = {
    "&": "&amp;",
    "<": "&#60;",
    ">": "&#62;",
    "~": "&sim;",
    "*": "&#42;",
    "[": "&#91;",
    "]": "&#93;",
    "(": "&#40;",
    ")": "&#41;",
    "#": "&#35;",
    "+": "&#43;",
    "`": "&#96;",
    "$": "&#36;",
    "_": "&#95;",
    "!": "&#33;",
    "\\": "&#92;",
}
_MD_ESCAPE_RE = re.compile("[" + re.escape("".join(_MD_ESCAPES)) + "]")


@dataclass(slots=True)
class Message:
    """一条飞书消息。标题、副标题进卡片头部，正文进卡片 body。"""

    title: str
    subtitle: str
    body: str
    keys: list[str] = field(default_factory=list)
    template: str = "blue"

    def as_text(self) -> str:
        head = f"{self.title} · {self.subtitle}" if self.subtitle else self.title
        return f"{head}\n{self.body}" if self.body else head


def escape_md(text: str) -> str:
    """把动态文本里的 markdown 控制字符换成 HTML 实体（飞书 lark_md 的转义方式）。"""
    return _MD_ESCAPE_RE.sub(lambda match: _MD_ESCAPES[match.group(0)], text)


# 链接里能构造出标记的字符：<> 拼标签，* ~ ` 拼强调，[] 拼 [文本](地址)。
# 这些字符在合法 URL 里本来就不该出现，直接剔除即可。
# 刻意**不**转义 _ & ( ) # + $ !：它们在 URL 里合法且极常见
# （security_advisories、?a=1&b=2），换成实体虽然显示一致，却会让链接没法点。
_LINK_JUNK = re.compile(r"[<>\"'`|*~\[\]]")
# 链接里如果出现 &#60; / &#42; 这类 HTML 实体，飞书 lark_md 会把它解码成
# < / *，等于绕过了上面的字面剔除。只清掉"能还原成 markdown 控制符"的实体，
# 保留 &amp; 和普通查询参数里的 &，避免把合法 URL 改坏。
_HTML_ENTITY = re.compile(
    r"&#(?:x[0-9a-f]+|\d+);"
    r"|&(?:lt|gt|sim|ast|lowbar|lbrack|rbrack|num|plus|grave|dollar|excl|bsol);",
    re.I,
)


def sanitize_link(link: str) -> str:
    """把外部来源的链接压成"不可能构造标记"的形式。"""
    return _HTML_ENTITY.sub("", _LINK_JUNK.sub("", link))


def shorten_bytes(text: str, budget: int) -> str:
    """按 UTF-8 字节截断，不会切出半个汉字。"""
    if budget <= 0:
        return ""
    raw = text.encode("utf-8", "replace")
    if len(raw) <= budget:
        return text
    if budget <= 3:
        return raw[:budget].decode("utf-8", "ignore")
    return raw[: budget - 3].decode("utf-8", "ignore") + "…"


def _inline(text: str) -> str:
    """把字段压成单行。

    解析层的 clean() 已经做过这件事，但 state 里的条目可能被手工改过。
    一个换行就能把「【标题原文】」后面的内容挤到下一行，让整张卡片错位，
    所以渲染前再兜一次。
    """
    return " ".join((text or "").split())


def _display_title(item: Item) -> str:
    """标题去掉开头重复的 CVE 号——编号已经单独占一行，标题里再写一遍只是噪音。"""
    title = shorten(_inline(item.title), MAX_TITLE_CHARS)
    if item.cves:
        stripped = CVE_TITLE_PREFIX.sub("", title).strip()
        if stripped:
            title = stripped
    return title


def render_item(item: Item, *, markup: bool = True) -> str:
    """一条漏洞渲染成字段化的多行文本。字段没有值就整行省略，不留空壳。

    标题和摘要都拆成「翻译 / 原文」两行：有译文时两行都给（译文在上、原文在下），
    没译文时只给原文那一行。标签必须和内容对得上——不能把英文挂在「翻译」下面。
    """
    title = _display_title(item)

    title_zh = shorten(_inline(item.title_zh), MAX_TITLE_CHARS)
    if title_zh and item.cves:
        stripped = CVE_TITLE_PREFIX.sub("", title_zh).strip()
        if stripped:
            title_zh = stripped
    # 译文和原文一样（中文源、或 Google 原样返回）时不算翻译，否则会出现两行一模一样
    translated_title = bool(title_zh) and title_zh != title

    lines = []
    # 来源放第一行：一条公告一条消息之后，卡片标题是公告本身，源名只出现在
    # 副标题里不够显眼；消息被转发或截图出去时也要能一眼看出是哪家源。
    source_name = _inline(item.source_name)
    if source_name:
        lines.append("【来源】" + (escape_md(source_name) if markup else source_name))
    if item.cves:
        cve_text = "、".join(item.cves)
        lines.append("【编号】" + (escape_md(cve_text) if markup else cve_text))
    if item.published:
        # 统一按东八区展示：runner 的本地时区不可控，不能用 datetime.fromtimestamp(ts)
        published = datetime.fromtimestamp(item.published, CST).strftime("%Y-%m-%d %H:%M")
        lines.append("【发布时间】" + published)

    # 加粗只给"主行"：有译文时是译文，没译文时是原文
    if translated_title:
        lines.append("【标题翻译】" + (f"**{escape_md(title_zh)}**" if markup else title_zh))
        lines.append("【标题原文】" + (escape_md(title) if markup else title))
    else:
        lines.append("【标题原文】" + (f"**{escape_md(title)}**" if markup else title))

    if item.severity >= 1:
        label = SEVERITY_LABELS.get(item.severity, "")
        if item.cvss:
            label = f"{label}（CVSS {item.cvss:.1f}）"
        if markup and item.severity >= 3:
            label = f"<font color='red'>{label}</font>"
        elif markup and item.severity == 1:
            label = f"<font color='grey'>{label}</font>"
        lines.append("【等级】" + label)

    # 「在野利用」以前只体现在分组标题【在野利用】里；拆成一条一条之后
    # 分组标题没了，这个信号必须落到每一条自己的正文里，否则会丢信息。
    marks = []
    if item.exploited:
        marks.append("已确认在野利用")
    if item.ransomware:
        marks.append("已知勒索团伙利用")
    if marks:
        value = "、".join(marks)
        if markup:
            value = f"<font color='red'>{value}</font>"
        lines.append("【标记】" + value)

    summary_zh = shorten(_inline(item.summary_zh), MAX_SUMMARY_CHARS)
    summary = shorten(_inline(item.summary), MAX_SUMMARY_CHARS)
    if summary_zh and summary_zh != summary:
        lines.append("【摘要翻译】" + (escape_md(summary_zh) if markup else summary_zh))
    if summary:
        lines.append("【摘要原文】" + (escape_md(summary) if markup else summary))

    if item.link:
        # 链接也来自外部源：不处理的话，一个带 <font> / ** 的 URL 就能往卡片里注入样式。
        # 这里用"剔除危险字符"而不是实体转义，是为了不破坏 URL 里的 _ 和 &。
        link = shorten(sanitize_link(" ".join(item.link.split())), MAX_LINK_CHARS)
        lines.append("【链接】" + link)

    if item.also:
        also = "、".join(item.also)
        lines.append("【另见】" + (escape_md(also) if markup else also))

    return "\n".join(lines)


def select_items(config: Config, items: list[Item]) -> tuple[list[Item], int]:
    """按每个源的 limit 挑出本轮要发的条目，返回 (入选条目, 顺延条数)。

    limit 是"每轮最多发几条"的洪泛闸门：同一源内先按 (等级, 时间) 排好再截断，
    留下的必须是最要紧的那几条，而不是恰好排在前面那几条。被截断的条目不会
    被确认送达，下一轮会重新进入候选，所以只会延后、不会丢。
    """
    sources = {source.key: source for source in config.sources}
    buckets: dict[str, list[Item]] = {}
    for item in items:
        buckets.setdefault(item.source_key, []).append(item)

    selected: list[Item] = []
    deferred = 0
    for source_key, values in buckets.items():
        values.sort(key=lambda item: (-item.severity, -item.published, item.title))
        source = sources.get(source_key)
        # 至少展示 1 条：limit 为 0/负数只可能来自直接构造的 Source，
        # 真按它切片会让这个源永远发不出去。
        limit = max(1, (source.limit or config.max_items) if source else MAX_ITEMS)
        selected.extend(values[:limit])
        deferred += max(0, len(values) - limit)
    return selected, deferred


def _rank(item: Item) -> tuple:
    """越要紧越靠前：在野利用 → 等级 → 时间 → 标题。

    先发重要的不只是"看起来舒服"：真撞上飞书限流或时间预算耗尽时，
    被截掉的是排在后面的普通条目，而不是最需要处理的那条。
    """
    return (not item.exploited, -item.severity, -item.published, item.title)


def _header_title(item: Item) -> str:
    title = shorten(_display_title(item), HEADER_TITLE_CHARS) or "（无标题）"
    icon = EXPLOITED_ICON if item.exploited else SEVERITY_ICONS.get(item.severity, "")
    return f"{icon} {title}" if icon else title


def _subtitle(item: Item, stamp: str, index: int, total: int, overflow: int) -> str:
    parts = [item.source_name, stamp]
    marks = []
    if item.exploited:
        marks.append("在野利用")
    if item.severity >= 1:
        label = SEVERITY_LABELS.get(item.severity, "")
        if item.cvss:
            label = f"{label}（CVSS {item.cvss:.1f}）"
        marks.append(label)
    if marks:
        parts.append(" · ".join(marks))
    if total > 1:
        parts.append(f"第 {index}/{total} 条")
    if overflow:
        parts.append(f"另有 {overflow} 条顺延到下一轮")
    return " · ".join(part for part in parts if part)


def card_template(item: Item) -> str:
    """单条消息的头部配色。

    red 只留给"确认在野利用"，普通严重用 carmine，避免每条都刺眼。
    """
    if item.exploited:
        return "red"
    if item.severity >= 4:
        return "carmine"
    if item.severity == 3:
        return "orange"
    return "blue"


def compose(
    config: Config,
    items: list[Item],
    now: int,
    *,
    failures: list[Failure] | None = None,
    skipped: list[Failure] | None = None,
    markup: bool = True,
    budget: int = MAX_CARD_BODY_BYTES,
    max_messages: int = MAX_MESSAGES,
) -> list[Message]:
    """把条目渲染成一条条消息，一条公告一条。

    返回的每一条都带着自己的 keys（含被跨源合并掉的条目），调用方逐条发送、
    逐条确认；没发出去的自然留在队列里，下一轮补发。
    """
    failures = failures or []
    skipped = skipped or []

    notes = []
    for failure in failures:
        name = escape_md(failure.name) if markup else failure.name
        notes.append(f"⚠ 抓取失败：{name}")
    for failure in skipped:
        name = escape_md(failure.name) if markup else failure.name
        notes.append(f"⚠ 本轮未检查：{name}")

    selected, deferred = select_items(config, items)
    selected.sort(key=_rank)
    # 一次刷几十条既会撞飞书限流（5 次/秒），也会把群刷屏；
    # 超出上限的留在队列里，下一轮优先发（排序保证先发要紧的）。
    overflow = deferred + max(0, len(selected) - max_messages)
    selected = selected[:max_messages]

    stamp = f"{datetime.fromtimestamp(now, CST):%m-%d %H:%M}"
    if not selected:
        if not notes:
            return []
        # 只有源异常、没有条目时也发一条状态消息，别把提示吞掉
        return [Message("Vigil · 源状态提示", stamp, "\n".join(notes))]

    total = len(selected)
    messages: list[Message] = []
    for index, item in enumerate(selected, 1):
        body = render_item(item, markup=markup)
        if index == 1 and notes:
            # 源异常提示搭第一条的车：不额外占一条消息，也不会因为后面某条
            # 推送失败而丢掉（第一条失败时整轮都不会确认，下一轮会重发）
            body = "\n".join(notes) + "\n\n" + body
        if len(body.encode("utf-8", "replace")) > budget:
            log("⚠ 单条公告超过消息预算，已截断")
            body = shorten_bytes(body, budget)
        messages.append(Message(
            _header_title(item),
            _subtitle(item, stamp, index, total, overflow if index == total else 0),
            body.rstrip("\n"),
            [item.key, *item.merged],
            card_template(item),
        ))
    return messages
