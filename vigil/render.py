"""把单条公告渲染成消息正文。

同一份内容有两种输出：
  markup=True   → 卡片用的 lark_md（加粗标题、等级着色）
  markup=False  → 纯文本（--dry-run 在终端里看）

"若干条目 → 若干消息"（排序、每源 limit、副标题、头部配色）在 digest.py；
这里只负责一条条目的字段排版、转义与链接净化。
"""
from __future__ import annotations

import html.entities
import re
from datetime import datetime

from .models import (
    CST,
    MAX_LINK_CHARS,
    MAX_SUMMARY_CHARS,
    MAX_TITLE_CHARS,
    Item,
    shorten,
)

CVE_TITLE_PREFIX = re.compile(r"^(?:CVE-\d{4}-\d{4,8}[\s:：]+)+", re.I)
# 内核 CVE 团队用 "REJECTED: CVE-…" 作撤稿通知的标题：编号已经作废，正文里必须
# 点名，否则它看起来和一条新漏洞一模一样（还会占掉内核源每轮的展示名额）。
# 必须要求冒号：像 "Rejected packets cause kernel panic" 这种正常公告标题不能
# 因为以 Rejected 开头就被说成"编号已作废"。
REJECTED_TITLE_PREFIX = re.compile(r"^\s*REJECTED\s*[:：]", re.I)
SEVERITY_LABELS = {1: "低", 2: "中", 3: "高", 4: "严重"}
# 【编号】一行最多列这么多 CVE，其余用"等 N 个"收口。批量修复公告（或 JSON 源的
# cve 列表字段）可能塞进成百上千个编号，一行就能把正文预算吃光、把标题和摘要
# 挤到截断之外。只影响展示，不影响指纹与跨源合并。
MAX_CVES_RENDERED = 12

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


def escape_md(text: str) -> str:
    """把动态文本里的 markdown 控制字符换成 HTML 实体（飞书 lark_md 的转义方式）。"""
    return _MD_ESCAPE_RE.sub(lambda match: _MD_ESCAPES[match.group(0)], text)


# 链接里能构造出标记的字符：<> 拼标签，* ` | 拼强调，[] 拼 [文本](地址)。
# 刻意不剔 _ & ( ) # + $ ! ~：它们在 URL 里合法且极常见
# （security_advisories、/~user/、?a=1&b=2）；~ 是 RFC 3986 的 unreserved，
# 删掉会把 /~shmat/ 这类地址直接改坏。
_LINK_JUNK = re.compile(r"[<>\"'`|*\[\]]")
# lark_md 会把 &#60; / &NewLine; 这类实体解码成 < / 换行。所以链接里任何
# "可能被解码"的 & 引用都必须失效。这里刻意不删除引用，而是把开头的 & 换成
# %26：删除会让两侧文本拼成一个新引用（"&#6" + "&x;" + "0;" → "&#60;"），
# 而 %26 在 URL 里解码后仍是 &，链接本身不受影响。
_ENTITY_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{0,31};?")
_NUMERIC_AMP = re.compile(r"&#(?:0*38|[xX]0*26);")
# 无分号的遗留实体名：html.unescape("&lt") 也会给出 "<"，不能漏。
_LEGACY_ENTITIES = frozenset(
    name for name in html.entities.html5 if not name.endswith(";")
)
# 无分号的遗留实体里，只有 lt/gt（含大写）会解码成能构造标记的字符；
# 其余（&copy、&not、&nbsp…）最多变成普通符号。只拦这几个，避免把
# "&notify=2" 这类查询参数也当成引用、把链接改坏。
_DANGEROUS_LEGACY = frozenset(
    name for name in _LEGACY_ENTITIES
    if any(char in "<>[]()*\n\r" for char in html.unescape(f"&{name}"))
)


def _starts_reference(text: str, index: int) -> bool:
    """index 处的 & 是否可能被当成 HTML 字符引用。

    数字引用即使没有分号也会被解码（&#60 → "<"），一律拦；
    命名引用带分号时一律拦；不带分号时只拦"危险遗留名"。
    解码器吃的是最长前缀（"&lt0064" → "<0064"），所以要按前缀判断，
    不能只比整个 token。普通查询分隔符 `?a=1&b=2` 不受影响。
    """
    if text.startswith("#", index + 1):
        return True
    match = _ENTITY_NAME.match(text, index + 1)
    if not match:
        return False
    token = match.group(0)
    if token.endswith(";"):
        return True
    return any(token.startswith(name) for name in _DANGEROUS_LEGACY)


def _neutralize_entities(text: str) -> str:
    """让所有可能被解码成标记的 & 引用失效；只替换、不删除。"""
    out: list[str] = []
    index = 0
    total = len(text)
    while index < total:
        char = text[index]
        if char != "&":
            out.append(char)
            index += 1
            continue
        if text.startswith("&amp;", index):
            # 唯一保留的实体：解码回来就是 &，构造不出标记。
            out.append("&amp;")
            index += 5
            continue
        numeric = _NUMERIC_AMP.match(text, index)
        if numeric:
            out.append("&amp;")
            index = numeric.end()
            continue
        out.append("%26" if _starts_reference(text, index) else "&")
        index += 1
    return "".join(out)


def sanitize_link(link: str) -> str:
    """把外部来源的链接压成"不可能构造标记"的形式。

    顺序不能反：先剔非法字符（删除可能把两侧拼成新引用），再中和 &。
    中和阶段只替换、不删除，因此不会产生新的拼接。
    """
    return _neutralize_entities(_LINK_JUNK.sub("", link))


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


def titles_of(item: Item) -> tuple[str, str]:
    """返回 (原文标题, 译文标题)；没有译文、或译文与原文一模一样时第二项是空串。

    译文也要去掉开头重复的 CVE 号。译文与原文相同是常态（中文源、或翻译接口
    原样返回），此时不能把它当成"有译文"，否则卡片上会出现两行一样的内容。
    digest 里的卡片头部标题也要用这一份规则。
    """
    original = _display_title(item)
    translated = shorten(_inline(item.title_zh), MAX_TITLE_CHARS)
    if translated and item.cves:
        stripped = CVE_TITLE_PREFIX.sub("", translated).strip()
        if stripped:
            translated = stripped
    if translated == original:
        translated = ""
    return original, translated


def _cves_line(item: Item) -> str:
    shown = item.cves[:MAX_CVES_RENDERED]
    text = "、".join(shown)
    if len(item.cves) > len(shown):
        text = f"{text} 等 {len(item.cves)} 个"
    return text


def render_item(item: Item, *, markup: bool = True) -> str:
    """一条漏洞渲染成字段化的多行文本。字段没有值就整行省略，不留空壳。

    标题和摘要都拆成「翻译 / 原文」两行：有译文时两行都给（译文在上、原文在下），
    没译文时只给原文那一行。标签必须和内容对得上——不能把英文挂在「翻译」下面。
    """
    title, title_zh = titles_of(item)
    # 译文与原文相同时 titles_of() 已经折成空串，这里只看有没有译文
    translated_title = bool(title_zh)

    lines = []
    # 来源放第一行：一条公告一条消息之后，卡片标题是公告本身，源名只出现在
    # 副标题里不够显眼；消息被转发或截图出去时也要能一眼看出是哪家源。
    source_name = _inline(item.source_name)
    if source_name:
        lines.append("【来源】" + (escape_md(source_name) if markup else source_name))
    if item.cves:
        cve_text = _cves_line(item)
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

    # 撤稿通知本身没有可利用的信息，唯一要传达的是"这个编号作废了"，
    # 所以紧跟标题、用红色标出：漏看这一行就会继续把它当成一条新漏洞。
    if REJECTED_TITLE_PREFIX.match(title):
        withdrawn = "该编号已作废，不再是有效 CVE"
        if markup:
            withdrawn = f"<font color='red'>{withdrawn}</font>"
        lines.append("【撤销CVE】" + withdrawn)

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
        # 这里用"剔除危险字符 + 中和实体"而不是整体转义，是为了不破坏 URL 里的 _ 和 &。
        link = shorten(sanitize_link(" ".join(item.link.split())), MAX_LINK_CHARS)
        lines.append("【链接】" + link)

    if item.also:
        # 与其它字段一样先压成单行：state 里的条目可能被手工改过。
        also = "、".join(_inline(name) for name in item.also)
        lines.append("【另见】" + (escape_md(also) if markup else also))

    return "\n".join(lines)
