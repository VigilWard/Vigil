"""把若干条目编排成若干条消息：跨源合并、排序、限额、副标题与头部配色。

为什么不把多条塞进一张卡片：
  一张卡片里按「源 → 等级」分组，普通漏洞会把高危漏洞夹在中间，扫消息时
  很难一眼挑出来。拆成一条一条之后，每张卡片自己的头部配色和图标
  都在说"这条有多要紧"，等级再也不会被邻居淹没。

单条条目的字段排版与转义在 render.py；这里只决定"发哪几条、怎么编号、
什么颜色、超预算怎么截断"。
"""
from __future__ import annotations

import unicodedata

from .models import (
    MAX_CARD_BODY_BYTES,
    MAX_ITEMS,
    MAX_MESSAGES,
    Config,
    Failure,
    Item,
    Message,
    log,
    shorten,
    shorten_bytes,
)
from .render import escape_md, render_item, titles_of

# 卡片头部只能放纯文本，颜色又不能只靠模板色区分（蓝底同时覆盖中/低/未知），
# 所以标题前面再加一个字符标记，扫消息列表时不用点开也能看出等级。
SEVERITY_ICONS = {1: "⚪", 2: "🟡", 3: "🟠", 4: "🔴"}
EXPLOITED_ICON = "🚨"
# 卡片头部标题只用来"认消息"，不承载全文；正文里的【标题原文】才是完整版。
HEADER_TITLE_CHARS = 60
# 副标题在飞书客户端里**只能显示一行**（官方文档：超出一行用 ... 省略）。PC 卡片宽、
# 手机卡片窄，同一条副标题在手机上会被切掉尾巴，曾经把排在最后的「第 3/30 条」
# 切成「第 3/…」。两条对策同时生效：
#   1) 序号永远排在最前面：之后无论怎么截，被吃掉的都只是源名；
#   2) 整行按 30 个"半角宽度"自己收口：宁可少写几个字，也不让客户端动刀。
# 30 来自实测——手机上一行大约排得下 35 个半角宽度，余量用来抵消字号设置和
# 卡片边距的差异。因此副标题不再放"本轮推送时间"和"等级文字"：前者就是消息自身
# 的发送时间（每 10 分钟一轮，翻消息时飞书会显示），后者已经由标题前的图标、
# 头部配色和正文【等级】表达。
SUBTITLE_COLUMNS = 30
SUBTITLE_SEPARATOR = " · "


def _char_width(char: str) -> int:
    """一个字符占几个"半角宽度"：汉字、全角标点和 emoji 算 2，其余算 1。"""
    return 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1


def display_width(text: str) -> int:
    """按"半角宽度"估算一行能排下多少字符。

    飞书没有公开副标题的像素宽度，这里只用来做保守收口：
    宁可我们自己提前少写，也不要让客户端把「第 3/30 条」截成「第 3/…」。
    `·`（分隔符）和 `…`（省略号）属于 East Asian Ambiguous，中文界面下往往占满
    一个汉字宽，这里按 1 计——SUBTITLE_COLUMNS 相对手机实际容量留的余量足以吸收
    这点误差（一条副标题里最多一个 `·` 加一个 `…`，最多多算 2 列）。
    """
    return sum(_char_width(char) for char in text)


def shorten_display(text: str, budget: int) -> str:
    """按显示宽度截断，超长时以 … 结尾（不会切出半个字）。"""
    if display_width(text) <= budget:
        return text
    if budget < 2:
        # 连「一个字 + 省略号」都放不下：宁可留空，也不要留一个孤零零的「…」
        return ""
    kept = []
    used = 0
    for char in text:
        width = _char_width(char)
        if used + width > budget - 1:   # 留 1 个宽度给省略号
            break
        kept.append(char)
        used += width
    trimmed = "".join(kept).rstrip()
    # 前导空白也可能把预算吃光，此时同样不要留下孤零零的省略号
    return f"{trimmed}…" if trimmed else ""


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
        # 稳定排序：等级、时间都相同时保持队列顺序（新条目按源里的先后入队），
        # 不要再用标题做 tie-break——无日期的源（NGINX）会被按字母序挑走。
        values.sort(key=lambda item: (-item.severity, -item.published))
        source = sources.get(source_key)
        # 至少展示 1 条：limit 为 0/负数只可能来自直接构造的 Source，
        # 真按它切片会让这个源永远发不出去。
        limit = max(1, (source.limit or config.max_items) if source else MAX_ITEMS)
        selected.extend(values[:limit])
        deferred += max(0, len(values) - limit)
    return selected, deferred


def _rank(item: Item) -> tuple:
    """越要紧越靠前：在野利用 → 等级 → 时间。

    先发重要的不只是"看起来舒服"：真撞上飞书限流或时间预算耗尽时，
    被截掉的是排在后面的普通条目，而不是最需要处理的那条。
    同分时保持 select_items 给出的队列顺序（稳定排序）。
    """
    return (not item.exploited, -item.severity, -item.published)


def _header_title(item: Item) -> str:
    """卡片头部标题：有译文就用译文，没有（或与原文相同）时回落原文。

    头部是扫消息时唯一会看的地方，中文比英文原文更快认出来；完整原文仍在
    正文【标题原文】里，不靠这里承载。
    """
    original, translated = titles_of(item)
    title = shorten(translated or original, HEADER_TITLE_CHARS) or "（无标题）"
    icon = EXPLOITED_ICON if item.exploited else SEVERITY_ICONS.get(item.severity, "")
    return f"{icon} {title}" if icon else title


def _subtitle(item: Item, index: int, total: int) -> str:
    """卡片副标题：序号在前，源名在后。

    副标题只有一行，所以序号必须排在最前面：这一行无论被谁截断，都不能把
    「第 3/30 条」切成「第 3/…」。源名再按剩余宽度收一次口，让整行尽量完整
    落在手机的一行里；完整源名在正文【来源】里，截短不会丢信息。
    """
    source = " ".join(item.source_name.split())
    if total <= 1:
        return shorten_display(source, SUBTITLE_COLUMNS)
    counter = f"第 {index}/{total} 条"
    if not source:
        return counter
    room = SUBTITLE_COLUMNS - display_width(counter) - display_width(SUBTITLE_SEPARATOR)
    shortened = shorten_display(source, room)
    return f"{counter}{SUBTITLE_SEPARATOR}{shortened}" if shortened else counter


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


def merge(items: list[Item], config: Config) -> list[Item]:
    """同一个 CVE 被不同源同时报到时合并成一条。

    只合并"来自不同源"的条目：同一个源里两条独立公告即使提到同一个 CVE
    也必须各自保留，否则会静默丢消息。

    每个源先选一条代表参与跨源合并，其余同源条目原样保留；这样既能去重，
    又不会把"同一源的两条独立公告"吞掉。代表按
    (在野利用, 严重度, CVSS, 发布时间, 配置顺序) 选，避免配置里靠前的
    低危源覆盖后面源的高危信息。
    """
    order = {source.key: index for index, source in enumerate(config.sources)}
    by_cve: dict[str, list[Item]] = {}
    merged: list[Item] = []

    for item in items:
        if len(item.cves) == 1:
            by_cve.setdefault(item.cves[0], []).append(item)
        else:
            merged.append(item)

    def rank(item: Item) -> tuple:
        return (
            not item.exploited,
            -item.severity,
            -item.cvss,
            -item.published,
            order.get(item.source_key, 999),
            item.key,
        )

    for group in by_cve.values():
        by_source: dict[str, list[Item]] = {}
        for item in group:
            by_source.setdefault(item.source_key, []).append(item)
        if len(by_source) < 2:
            merged.extend(group)
            continue

        # 每个源只拿一条代表去跨源合并；同源其余条目继续单独发。
        representatives = {
            source_key: min(source_items, key=rank)
            for source_key, source_items in by_source.items()
        }
        winner = min(representatives.values(), key=rank)
        others = [
            item for source_key, item in representatives.items()
            if source_key != winner.source_key
        ]
        winner.also = tuple(sorted({item.source_name for item in others}))
        winner.merged = tuple(sorted({item.key for item in others}))
        # 合并后的条目应该反映整组最严重的信号，而不是 winner 自己那一行。
        winner.severity = max(item.severity for item in group)
        winner.cvss = max(item.cvss for item in group)
        winner.exploited = any(item.exploited for item in group)
        winner.ransomware = any(item.ransomware for item in group)
        merged.append(winner)

        # 非代表条目全部保留，避免"同源多条独立公告"被静默吞掉。
        for source_key, source_items in by_source.items():
            representative = representatives[source_key]
            for item in source_items:
                if item is not winner and item is not representative:
                    merged.append(item)

    return merged


def compose(
    config: Config,
    items: list[Item],
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

    if not selected:
        # 没有条目就什么都不发：源异常提示只在有内容时搭车（app._deliver 在
        # 队列为空时直接返回，根本不会调到这里）。单独发"状态卡片"会让一个
        # 抖动的源每 10 分钟刷一张空卡片——README 里明确不这么做。
        return []

    total = len(selected)
    messages: list[Message] = []
    for index, item in enumerate(selected, 1):
        body = render_item(item, markup=markup)
        # 整句提示搭车进正文：源异常跟第一条，顺延跟最后一条，都不额外占消息。
        # 这两类话都太长，塞不进只有一行的副标题，而正文顶部不会被截断。
        tops = []
        if index == 1:
            # 源异常提示搭第一条的车：不额外占一条消息，也不会因为后面某条
            # 推送失败而丢掉（第一条失败时整轮都不会确认，下一轮会重发）
            tops.extend(notes)
        if index == total and overflow:
            tops.append(f"⚠ 另有 {overflow} 条顺延到下一轮")
        if tops:
            body = "\n".join(tops) + "\n\n" + body
        if len(body.encode("utf-8", "replace")) > budget:
            log("⚠ 单条公告超过消息预算，已截断")
            body = shorten_bytes(body, budget)
        messages.append(Message(
            _header_title(item),
            _subtitle(item, index, total),
            body.rstrip("\n"),
            [item.key, *item.merged],
            card_template(item),
        ))
    return messages
