"""把条目渲染成飞书消息体，并按字节预算分页。

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
    MAX_PAGES,
    Config,
    Failure,
    Item,
    log,
    shorten,
)

CVE_TITLE_PREFIX = re.compile(r"^(?:CVE-\d{4}-\d{4,8}[\s:：]+)+", re.I)
SEVERITY_LABELS = {1: "低", 2: "中", 3: "高", 4: "严重"}

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
class Page:
    """一页消息。标题、副标题进卡片头部，正文进卡片 body。"""

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


def sanitize_link(link: str) -> str:
    """把外部来源的链接压成"不可能构造标记"的形式。"""
    return _LINK_JUNK.sub("", link)


def shorten_bytes(text: str, budget: int) -> str:
    """按 UTF-8 字节截断，不会切出半个汉字。"""
    if budget <= 0:
        return ""
    raw = text.encode("utf-8")
    if len(raw) <= budget:
        return text
    if budget <= 3:
        return raw[:budget].decode("utf-8", "ignore")
    return raw[: budget - 3].decode("utf-8", "ignore") + "…"


def render_item(item: Item, *, markup: bool = True) -> str:
    """一条漏洞渲染成字段化的多行文本。字段没有值就整行省略，不留空壳。

    有译文时【标题】用中文，并把英文原标题放进【原文】，方便核对和搜索。
    """
    title = item.title
    if item.cves:
        stripped = CVE_TITLE_PREFIX.sub("", title).strip()
        if stripped:
            title = stripped

    title_zh = item.title_zh.strip()
    if title_zh and item.cves:
        stripped = CVE_TITLE_PREFIX.sub("", title_zh).strip()
        if stripped:
            title_zh = stripped
    display = title_zh or title

    lines = []
    if item.cves:
        lines.append("【编号】" + "、".join(item.cves))

    if markup:
        # 不加空格：其它字段（【编号】【摘要】【链接】）都是紧贴内容，
        # 【标题】多一个空格会让 --dry-run 的排版和线上卡片对不上
        lines.append("【标题】**" + escape_md(display) + "**")
    else:
        lines.append("【标题】" + display)

    if title_zh and title_zh != title:
        lines.append("【原文】" + (escape_md(title) if markup else title))

    if item.severity >= 1:
        label = SEVERITY_LABELS.get(item.severity, "")
        if item.cvss:
            label = f"{label}（CVSS {item.cvss:.1f}）"
        if markup and item.severity >= 3:
            label = f"<font color='red'>{label}</font>"
        elif markup and item.severity == 1:
            label = f"<font color='grey'>{label}</font>"
        lines.append("【等级】" + label)

    if item.ransomware:
        value = "已知勒索团伙利用"
        if markup:
            value = f"<font color='red'>{value}</font>"
        lines.append("【标记】" + value)

    summary = item.summary_zh.strip() or item.summary
    if summary:
        summary = escape_md(summary) if markup else summary
        lines.append("【摘要】" + summary)

    if item.link:
        # 链接也来自外部源：不处理的话，一个带 <font> / ** 的 URL 就能往卡片里注入样式。
        # 这里用"剔除危险字符"而不是实体转义，是为了不破坏 URL 里的 _ 和 &。
        link = shorten(sanitize_link(" ".join(item.link.split())), MAX_LINK_CHARS)
        lines.append("【链接】" + link)

    if item.also:
        also = "、".join(item.also)
        lines.append("【另见】" + (escape_md(also) if markup else also))

    return "\n".join(lines)


def build_sections(config: Config, items: list[Item]):
    """按「在野利用 / 新披露」→ 源 → 严重度、时间 分组。"""
    order = {source.key: index for index, source in enumerate(config.sources)}
    sources = {source.key: source for source in config.sources}

    buckets: dict[tuple[bool, str], list[Item]] = {}
    for item in items:
        buckets.setdefault((item.exploited, item.source_key), []).append(item)

    sections = []
    for exploited, label in ((True, "在野利用"), (False, "新披露")):
        groups = []
        keys = sorted({key[1] for key in buckets if key[0] == exploited},
                      key=lambda key: order.get(key, 999))
        for skey in keys:
            values = sorted(
                buckets[(exploited, skey)],
                key=lambda item: (-item.severity, -item.published, item.title),
            )
            source = sources.get(skey)
            limit = (source.limit or config.max_items) if source else MAX_ITEMS
            shown = values[:limit]
            # 源被从 config 里删掉时（条目还在队列里）用条目自带的源名兜底。
            # 注意取 values[0] 而不是 shown[0]：limit 理论上可能小于 1，
            # 那时 shown 是空列表，shown[0] 会直接 IndexError。
            name = source.name if source else values[0].source_name
            groups.append((name, shown, len(values) - len(shown)))
        if groups:
            sections.append((label, groups))
    return sections


def paginate(blocks: list[tuple[str, list[str]]], budget: int, max_pages: int):
    """把消息块塞进不超过 budget 字节的若干页。

    返回 ([(正文, keys)], overflow)。超出的块不会被确认送达，下一轮会重发。
    overflow 只统计**条目**，分组标题这类没有 keys 的块不计入，
    否则消息里会写「另有 N 条」而用户根本找不到那 N 条。
    """
    if max_pages < 1:
        return [], sum(len(keys) for _, keys in blocks)

    pages: list[tuple[str, list[str]]] = []
    current = ""
    keys: list[str] = []
    overflow = 0

    for text, block_keys in blocks:
        text = text.replace("\r", "")
        if not text:
            continue
        while True:
            if not current:
                # 页首不留空行
                text = text.lstrip("\n")
                if not text:
                    break
            sep = 1 if current else 0
            room = budget - len(current.encode("utf-8")) - sep
            if len(text.encode("utf-8")) <= room:
                current = f"{current}\n{text}" if current else text
                keys.extend(block_keys)
                break
            if current:
                if len(pages) + 1 >= max_pages:
                    # 最后一页也装不下了：剩下的条目留给下一轮，只数条目
                    overflow += len(block_keys)
                    break
                pages.append((current, keys))
                current, keys = "", []
                continue
            # 整页只放一个块还放不下：截断后仍然发出，避免死循环
            piece = shorten_bytes(text, max(0, room))
            if not piece:
                overflow += len(block_keys)
                break
            log("⚠ 单条内容超过单页预算，已截断")
            current = piece
            keys.extend(block_keys)
            break

    if current and len(pages) < max_pages:
        # 用 current 而不是 keys 判空：只有"源异常提示"这类没有条目 key 的块
        # 时也要成页，否则整页内容会被静默丢掉
        pages.append((current, keys))
    return pages, overflow


def card_template(items: list[Item]) -> str:
    """卡片头部配色。

    red 只留给"确认在野利用"，普通严重用 carmine，避免每条都刺眼。
    """
    if any(item.exploited for item in items):
        return "red"
    top = max((item.severity for item in items), default=0)
    if top >= 4:
        return "carmine"
    if top == 3:
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
) -> list[Page]:
    failures = failures or []
    skipped = skipped or []

    blocks: list[tuple[str, list[str]]] = []
    for failure in failures:
        name = escape_md(failure.name) if markup else failure.name
        blocks.append((f"⚠ 抓取失败：{name}\n", []))
    for failure in skipped:
        name = escape_md(failure.name) if markup else failure.name
        blocks.append((f"⚠ 本轮未检查：{name}\n", []))

    for label, groups in build_sections(config, items):
        blocks.append((f"【{label}】", []))
        for name, values, hidden in groups:
            # 源名来自配置，和条目一样要转义，否则名字里的 * 会把整行吃掉
            shown_name = escape_md(name) if markup else name
            blocks.append((f"{shown_name}（{len(values) + hidden}条）", []))
            for item in values:
                # 条目自带结尾空行：块与块之间自然隔开，源标题紧跟第一个条目
                blocks.append((render_item(item, markup=markup) + "\n", [item.key, *item.merged]))
            if hidden > 0:
                blocks.append((f"…另有{hidden}条未列出，将顺延到后续轮次\n", []))

    title = f"Vigil · {datetime.fromtimestamp(now, CST):%m-%d %H:%M}"
    exploited = sum(1 for item in items if item.exploited)
    # 没有条目、只有源异常提示时不能说"0 条待送达"，那会让人以为消息是空的
    subtitle = f"{len(items)} 条待送达" if items else "源状态提示"
    if exploited:
        subtitle += f" · 含 {exploited} 条在野利用"

    by_key = {item.key: item for item in items}
    raw_pages, overflow = paginate(blocks, budget, MAX_PAGES)
    total = len(raw_pages)
    pages = []
    for index, (body, keys) in enumerate(raw_pages, 1):
        page_subtitle = subtitle
        if total > 1:
            page_subtitle += f" · 第 {index}/{total} 页"
        if overflow and index == total:
            page_subtitle += f" · 另有 {overflow} 条顺延到下一轮"
        page_items = [by_key[key] for key in keys if key in by_key]
        pages.append(Page(title, page_subtitle, body.rstrip("\n"), keys,
                          card_template(page_items)))
    return pages
