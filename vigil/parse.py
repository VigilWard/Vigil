"""文本清洗、时间解析与各类源解析器。

新增一个源格式时，只需要在这里加一个 `parse_xxx(text, source) -> list[Item]`
并注册到 PARSERS，config 里的 kind 就能直接用了。
"""
from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .models import (
    MAX_CLEAN_CHARS,
    MAX_LINK_CHARS,
    MAX_NODES,
    MAX_SUMMARY_CHARS,
    MAX_TIMESTAMP,
    MAX_TITLE_CHARS,
    MAX_UID_CHARS,
    Item,
    ParseError,
    Source,
    log,
    sanitize_text,
    shorten,
)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,8}", re.I)

# ---------------------------------------------------------------- 文本

# 只认"看起来像标签"的东西：</?名字 属性…>。
#   "Affected versions < 1.2.3"  —— < 后面是空格，不是标签
#   "如果 a<b 且 b>c 则"         —— 属性名里出现中文，不是标签
#   "升级到 <V2.0> 版本"         —— 名字里有点号，不是标签
#   "firmware <b and c> d"       —— 属性没有 =，也不是布尔属性，不是标签
# 以前用 `[^<>]{0,2000}` 兜住一切，上面几种都会被整段吃掉（实测
# "升级到 <V2.0> 版本" → "升级到 版本"）。现在属性必须是 name=value，
# 或者 HTML 规范里的布尔属性（它们本来就允许不带值）。
_BOOLEAN_ATTRS = frozenset({
    "allowfullscreen", "async", "autofocus", "autoplay", "checked", "compact",
    "controls", "declare", "default", "defer", "disabled", "download",
    "formnovalidate", "hidden", "inert", "ismap", "itemscope", "loop",
    "multiple", "muted", "nohref", "nomodule", "noresize", "noshade",
    "novalidate", "nowrap", "open", "playsinline", "readonly", "required",
    "reversed", "selected",
})
# 标签名允许的字符（首字符必须是 ASCII 字母）
_TAG_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:-"
)
_ATTR_NAME = re.compile(r"[A-Za-z_:][-A-Za-z0-9_:.]*")
# 一个标签最多看这么多字符，超过就当正文（防止畸形输入拖慢扫描）
_MAX_TAG_CHARS = 2000
# 注释单独处理：它不是标签，但也不该出现在摘要里。长度有上限，不会回溯爆炸。
_COMMENT = re.compile(r"<!--.{0,2000}?-->", re.S)
# script/style 的**内容**也要去掉：只剥标签会把整段 CSS/JS 留在摘要里，
# 一个几万字的 <style> 块还会把真正的公告挤出 MAX_CLEAN_CHARS（实测整条摘要
# 变成 19993 个字符的 "body{color:red}"）。
_RAW_OPEN = re.compile(r"<(script|style)\b[^<>]{0,2000}>", re.I)
_CLOSE_SCRIPT = re.compile(r"</script\s*>", re.I)
_CLOSE_STYLE = re.compile(r"</style\s*>", re.I)
_IMAGE = re.compile(r"!\[([^\]]{0,200})\]\([^)]{0,500}\)")
_LINK = re.compile(r"\[([^\]]{0,300})\]\([^)]{0,500}\)")
_HEADING = re.compile(r"(?m)^[ \t]{0,3}#{1,6}[ \t]+")
_QUOTE = re.compile(r"(?m)^[ \t]*>[ \t]?")
_BOLD = re.compile(r"\*\*(?!\s)(.{1,500}?)(?<!\s)\*\*")
_UNDER_BOLD = re.compile(r"(?<!\w)__(?!\s)(.{1,500}?)(?<!\s)__(?!\w)")
_CODE = re.compile(r"`([^`\n]{0,300})`")
_RULE = re.compile(r"(?m)^[ \t]*(?:={3,}|-{3,}|\*{3,})[ \t]*$")
# 邮件列表里常见 "Posted by ... on Oct 31 ======" 这种行内分隔线，
# 整行匹配的 _RULE 抓不到，单独再扫一遍（要求整段是独立的符号串）
_RULE_ANY = re.compile(r"(?<!\S)[=\-*]{4,}(?!\S)")
_SPACES = re.compile(r"\s+")
# 邮件列表类 feed 的固定前缀："Posted by Foo Bar on Oct 31 "
_POSTED_BY = re.compile(
    r"^Posted by .{0,80}? on (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+",
    re.I,
)

# 只在本项目内部使用，避免把不可见字符带进消息和 state
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u00ad"), None)


def _drop_spans(text: str, opener: str, closer: str) -> str:
    """线性删掉 opener…closer 之间的内容；遇到第一个未闭合的 opener 就停手。

    不用 `.*?` 正则：未闭合时每个 opener 都要一路扫到文末，整体退化成 O(n²)
    （实测 256KB 的畸形 CDATA 要 20 秒，16MB 能把整轮钉死）。
    """
    parts: list[str] = []
    pos = 0
    while True:
        start = text.find(opener, pos)
        if start < 0:
            break
        end = text.find(closer, start + len(opener))
        if end < 0:
            break
        parts.append(text[pos:start])
        pos = end + len(closer)
    if not parts:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def _strip_raw_blocks(text: str) -> str:
    """去掉 <script>/<style> 及其内容：正文里的 CSS/JS 不属于摘要。"""
    parts: list[str] = []
    pos = 0            # 还没写进 parts 的起点
    cursor = 0         # 下一次查找 opener 的位置
    missing: set[str] = set()
    while True:
        opening = _RAW_OPEN.search(text, cursor)
        if not opening:
            break
        name = opening.group(1).lower()
        if name in missing:
            # 这个类型后面已经没有闭合标签了，跳过即可（原文保留），
            # 避免每个未闭合的 opener 都再向文末搜一遍（那是 O(n²)）。
            cursor = opening.end()
            continue
        closer = _CLOSE_SCRIPT if name == "script" else _CLOSE_STYLE
        closing = closer.search(text, opening.end())
        if not closing:
            # 没有闭合标签：保留这一段。安全公告经常在正文里讨论 "<script>" 标签，
            # 一律删到文末会把后面的内容全吞掉；跳过这个 opener 继续找后面成对的块。
            missing.add(name)
            cursor = opening.end()
            continue
        parts.append(text[pos:opening.start()])
        # 块原来的位置补一个空格：否则 "Critical<script>x</script>Update"
        # 会被拼成 "CriticalUpdate"（旧实现只剥标签，正好留下了空格）。
        parts.append(" ")
        pos = closing.end()
        cursor = closing.end()
    if not parts:
        return text
    parts.append(text[pos:])
    return "".join(parts)


def _valid_attrs(body: str) -> bool:
    """标签名之后、'>' 之前的部分是否合法：属性必须 name=value 或布尔属性。"""
    index, total = 0, len(body)
    while index < total:
        while index < total and body[index].isspace():
            index += 1
        if index >= total:
            return True
        if body[index] == "/":              # 自闭合
            return body[index + 1:].strip() == ""
        match = _ATTR_NAME.match(body, index)
        if not match:
            return False
        name = match.group(0).lower()
        index = match.end()
        while index < total and body[index].isspace():
            index += 1
        if index < total and body[index] == "=":
            index += 1
            while index < total and body[index].isspace():
                index += 1
            if index < total and body[index] in "\"'":
                close = body.find(body[index], index + 1)
                if close < 0:
                    return False
                index = close + 1
            else:
                start = index
                while index < total and not body[index].isspace() \
                        and body[index] not in "\"'<>":
                    index += 1
                if index == start:
                    return False
        elif name not in _BOOLEAN_ATTRS:
            return False
    return True


def _tag_end(text: str, start: int) -> int:
    """从 '<' 起判断是不是标签：是则返回 '>' 之后的下标，否则 -1。"""
    total = len(text)
    index = start + 1
    if index < total and text[index] == "/":
        index += 1
    if index >= total:
        return -1
    head = text[index]
    if not (head.isascii() and head.isalpha()):
        return -1
    limit = min(total, start + _MAX_TAG_CHARS)
    name_end = index + 1
    while name_end < limit and text[name_end] in _TAG_NAME_CHARS:
        name_end += 1
    quote = ""
    cursor = name_end
    while cursor < limit:
        char = text[cursor]
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == ">":
            return cursor + 1 if _valid_attrs(text[name_end:cursor]) else -1
        elif char == "<":
            return -1
        cursor += 1
    return -1


def _strip_tags(text: str) -> str:
    """把标签换成空格；不是标签的 '<' 原样保留。

    手写线性扫描而不是正则：属性语法写成正则会带嵌套量词，
    形如 `<a href=` 重复几千次就能让回溯爆炸（实测 50KB 要 2.6 秒，
    旧版 0.3ms）。这里每个字符最多被访问常数次。
    """
    parts: list[str] = []
    pos = 0
    while True:
        start = text.find("<", pos)
        if start < 0:
            break
        end = _tag_end(text, start)
        if end < 0:
            parts.append(text[pos:start + 1])
            pos = start + 1
            continue
        parts.append(text[pos:start])
        parts.append(" ")
        pos = end
    parts.append(text[pos:])
    return "".join(parts)


def clean(value: str | None) -> str:
    """把 HTML / Markdown 摘要压成一行纯文本。

    刻意保守：只处理成对且紧贴文字的强调标记，`a * b * c`、`snake_case_name`
    这类正文里的普通符号必须原样保留。

    script/style 先整块去掉再截断：摘要最终只留 300 字，一段 CSS 就足以把
    真正的公告挤出 MAX_CLEAN_CHARS，顺序反过来等于白截。
    """
    raw = value or ""
    if not isinstance(raw, str):
        raw = str(raw)
    text = sanitize_text(_strip_raw_blocks(raw)[:MAX_CLEAN_CHARS])
    text = html.unescape(text)
    # 再剥一次 script/style：JSON 源和二次转义源里常见 &lt;style&gt;…&lt;/style&gt;，
    # 只在 unescape 之前剥，等于漏掉一半（CSS 照样占满 300 字）。
    # 这段只有 ≤MAX_CLEAN_CHARS，多一遍线性扫描可以忽略。
    text = _strip_raw_blocks(text)
    text = text.translate(_ZERO_WIDTH)
    # 先统一换行符：邮件列表类源大量用 CRLF，行尾的 \r 会让 ^...$ 类的规则匹配不上
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _COMMENT.sub(" ", text)
    text = _strip_tags(text)
    text = _IMAGE.sub(r"\1", text)
    text = _LINK.sub(r"\1", text)
    text = _HEADING.sub("", text)
    text = _QUOTE.sub("", text)
    text = _BOLD.sub(r"\1", text)
    text = _UNDER_BOLD.sub(r"\1", text)
    text = _CODE.sub(r"\1", text)
    text = _RULE.sub(" ", text)
    text = _RULE_ANY.sub(" ", text)
    text = _SPACES.sub(" ", text).strip()
    return _POSTED_BY.sub("", text)


def _clean_uid(value: str) -> str:
    return shorten(" ".join(str(value or "").split()), MAX_UID_CHARS)


# ---------------------------------------------------------------- 时间

_EXTRA_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d",
    "%Y%m%d",
    "%Y%m%d%H%M%S",
    "%d %b %Y %H:%M:%S",
    "%d %B %Y %H:%M:%S",
)


def _stamp_of(moment: datetime) -> int:
    """datetime → Unix 秒；落在合理区间外一律当成"无日期"。

    以前只有"数字时间戳"那条分支做了范围校验，ISO / HTTP-date / 固定格式
    三个分支会把 9999-12-31、0001-01-01 原样返回。目前靠 Item 兜底，
    但那意味着任何新调用点都会继承脏值。
    """
    try:
        stamp = int(moment.timestamp())
    except (OverflowError, OSError, ValueError):
        return 0
    return stamp if 0 < stamp < MAX_TIMESTAMP else 0


def parse_time(value) -> int:
    """把各种常见时间格式转成 Unix 秒；无法识别或超出合理范围时返回 0（= 无日期）。"""
    if value is None or isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        try:
            stamp = int(value)
        except (ValueError, OverflowError):
            # JSON 里的 NaN / Infinity（Python 的 json 默认接受）会在这里炸；
            # 一个畸形字段不该把整轮抓取打挂
            return 0
        if stamp > 10**11:  # 毫秒
            stamp //= 1000
        return stamp if 0 < stamp < MAX_TIMESTAMP else 0

    text = str(value).strip()
    if not text or text.lower() in ("null", "none", "n/a"):
        return 0
    # 只认 ASCII 十进制数字。`²`.isdigit() 也是 True，但 int('²²…') 会抛
    # ValueError，冒到 collect 的兜底里会把整个源判成"解析器异常"；
    # 全角 '１２３４５６７８９' 则会被 int() 成功转成 123456789（1973 年）。
    if text.isascii() and text.isdigit():
        # 只有 9~13 位才当作 Unix 时间戳；8 位的 20261031 是日期，不能按 1970 年算
        if 9 <= len(text) <= 13:
            return parse_time(int(text))
    else:
        # 只替换结尾那一个字符。str.replace("Z", …) 会把正文里偶然出现的
        # 大写 Z 也一起换掉；而且要同时认小写 z（不少源这么写）。
        normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return _stamp_of(parsed)
        except (ValueError, OverflowError, OSError):
            pass

    try:
        parsed = parsedate_to_datetime(text)
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return _stamp_of(parsed)
    except (TypeError, ValueError, OverflowError):
        pass

    for fmt in _EXTRA_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return _stamp_of(parsed)
        except ValueError:
            continue
    return 0


# ---------------------------------------------------------------- 等级

_SEVERITY_WORDS = {
    "critical": 4,
    "high": 3,
    "important": 3,
    "medium": 2,
    "moderate": 2,
    "low": 1,
    "none": 0,
}
_SEVERITY_LABEL = re.compile(
    r"severity\s*[:：]\s*(critical|high|important|medium|moderate|low|none)", re.I
)
# "score" 必须整词出现（否则 "underscore 8 chars" 会被当成 8 分），
# 分数允许三位数再交给范围校验——以前 \d{1,2} 会把 "score 100" 截成 10 分。
_SCORE_LABEL = re.compile(
    r"\b(?:base\s+)?score\s*[:：=]?\s*(\d{1,3}(?:\.\d)?)(?!\d)(?!\.\d)", re.I
)
_CVSS_VALUE = re.compile(r"cvss[^\d]{0,12}v?\d(?:\.\d)?\s*[:：]\s*(\d{1,2}(?:\.\d)?)", re.I)
_CVSS_VERSION = re.compile(r"cvss\s*[:：]?\s*v?(\d(?:\.\d)?)", re.I)
_CVSS_VECTOR = re.compile(r"CVSS:\d\.\d/[A-Z:/]+", re.I)
_CVSS_CONTEXT = re.compile(r"cvss|score|severity|评分|风险", re.I)
# CVSS 版本号只有这几个；"CVSS 9.8" 里的 9.8 是分数，不能当版本剥掉。
_CVSS_KNOWN_VERSIONS = frozenset({"2.0", "3.0", "3.1", "4.0"})
# 没有小数点的分数（CVSS 10 / CVSS 9）；要求前面是 cvss 且后面不是数字或点。
# 句末的句号不算"点"："(?!\d)(?!\.\d)" 允许 "CVSS 10."，但挡住 "CVSS 3.1"。
_CVSS_INT = re.compile(r"cvss\s*[:：=]?\s*(\d{1,2})(?!\d)(?!\.\d)", re.I)
# 同理：以前 (?![.\d]) 把句末句号也拒了，"CVSS 9.8." 直接解析成 0 分。
_DECIMAL = re.compile(r"(?<![\d.])(\d{1,2}\.\d)(?!\d)(?!\.\d)")


def _level_of(score: float) -> int:
    if score >= 9:
        return 4
    if score >= 7:
        return 3
    if score >= 4:
        return 2
    return 1 if score > 0 else 0


def _strip_cvss_versions(text: str) -> str:
    """只剥掉真正的版本号，保留 "CVSS 9.8" 这类裸分数。"""

    def replace(match: re.Match[str]) -> str:
        return " " if match.group(1) in _CVSS_KNOWN_VERSIONS else match.group(0)

    return _CVSS_VERSION.sub(replace, text)


def cvss_of(text: str) -> float:
    """提取 CVSS 基础分（0~10），取不到返回 0。

    必须限定在 CVSS 语境里找数字，否则 "PHP 8.1.2 Released" 里的版本号 8.1
    会被当成 8.1 分，把一条发布公告标成高危。
    """
    text = text or ""
    for pattern in (_SCORE_LABEL, _CVSS_VALUE):
        match = pattern.search(text)
        if match:
            value = float(match.group(1))
            if 0 <= value <= 10:
                return value
    if not _CVSS_CONTEXT.search(text):
        return 0.0
    # "CVSS 10" / "CVSS 9" 这类整数分数；放在版本剥离之前，
    # 避免 _CVSS_INT 把 "CVSS 3.1" 里的 3 误认成整数分数。
    integer = _CVSS_INT.search(text)
    if integer:
        value = float(integer.group(1))
        # 2/3/4 更可能是 "CVSS 3" 这种版本写法，不当成整数分数。
        if value not in {2.0, 3.0, 4.0} and 0 <= value <= 10:
            return value
    stripped = _strip_cvss_versions(_CVSS_VECTOR.sub(" ", text))
    match = _DECIMAL.search(stripped)
    if match:
        value = float(match.group(1))
        if 0 <= value <= 10:
            return value
    return 0.0


def severity_of(text: str) -> int:
    """严重等级 0-4：先认厂商自己写的等级词，没有再看 CVSS 分数。"""
    text = text or ""
    label = _SEVERITY_LABEL.search(text)
    if label:
        return _SEVERITY_WORDS[label.group(1).lower()]
    return _level_of(cvss_of(text))


# ---------------------------------------------------------------- 构造

def _cves(*texts: str) -> tuple[str, ...]:
    found: set[str] = set()
    for text in texts:
        found.update(match.upper() for match in CVE_PATTERN.findall(text or ""))
    return tuple(sorted(found))


def build_item(
    source: Source,
    *,
    uid: str,
    title: str,
    link: str = "",
    published: int = 0,
    summary: str = "",
    cves: tuple[str, ...] = (),
    exploited: bool | None = None,
    ransomware: bool = False,
    severity: int | None = None,
) -> Item | None:
    """统一做截断与兜底；uid 或标题为空则丢弃该条目。"""
    uid = _clean_uid(uid)
    title = shorten(clean(title), MAX_TITLE_CHARS)
    if not uid or not title:
        return None
    link = shorten(" ".join((link or "").split()), MAX_LINK_CHARS)
    summary = clean(summary)
    if link and summary.endswith(link):
        # 不少源把详情页地址也写进正文，和【链接】重复
        summary = summary[: -len(link)].rstrip(" \u3000;；,，.。")
    summary = shorten(summary, MAX_SUMMARY_CHARS)
    cves = cves or _cves(title, summary)
    text = title + " " + summary
    return Item(
        source_key=source.key,
        source_name=source.name,
        uid=uid,
        title=title,
        link=link,
        published=published,
        summary=summary,
        cves=cves,
        exploited=source.exploited if exploited is None else exploited,
        ransomware=ransomware,
        severity=severity_of(text) if severity is None else severity,
        cvss=cvss_of(text),
    )


def _cap(items: list[Item]) -> list[Item]:
    """按 uid 去重，再对超大 feed 只保留最新的一批。

    去重放在这里是因为所有解析器都经过它：同一个 uid 出现两次时，
    `state.queue` 只会留下后一条，前面的条目会在"共 N 条"里被算进去却永远发不出去。
    """
    unique: list[Item] = []
    seen: set[str] = set()
    for item in items:
        if item.key in seen:
            continue
        seen.add(item.key)
        unique.append(item)
    if len(unique) != len(items):
        log(f"⚠ 存在重复条目（{len(items)} 条 → {len(unique)} 条），已按 uid 去重")
    items = unique
    if len(items) <= MAX_NODES:
        return items
    # 无日期条目按"最新"处理：这里是在决定**丢谁**，把未知日期当成最旧会
    # 直接把它们丢掉（NGINX 整类源都没有日期）。这和 pending_for 的"发送
    # 顺序把无日期排最后"不冲突，那边是排序，这边是保命。
    # 用 MAX_TIMESTAMP + 1 而不是 2**31：后者在 2038 年后会被真实时间戳超过，
    # 排序会悄悄反过来。
    ranked = sorted(items, key=lambda item: item.published or MAX_TIMESTAMP + 1, reverse=True)
    log(f"⚠ 条目过多（{len(items)} 条），只保留最新 {MAX_NODES} 条")
    return ranked[:MAX_NODES]


# ---------------------------------------------------------------- RSS / Atom

# 自定义实体声明：正规订阅源不需要，出现即视为攻击面
_ENTITY_DECL = re.compile(r"<!ENTITY", re.I)


def _has_entity_declaration(payload: str) -> bool:
    """只在真正的标记里找 <!ENTITY。

    CDATA 和注释里的 "<!ENTITY" 只是正文——安全公告完全可能在讨论 XML 实体攻击，
    把这种源永久判成攻击会静默丢掉整条流。真正的实体声明不可能藏在 CDATA 里生效，
    所以先剔除惰性文本再判断是安全的。
    """
    # 绝大多数响应根本没有 <!ENTITY：先做一次 O(n) 全文搜索，命中才去剔除惰性文本。
    # 之前无条件先跑 CDATA/注释剔除，畸形输入（大量未闭合 <![CDATA[）能让一轮卡几十分钟。
    if not _ENTITY_DECL.search(payload):
        return False
    markup = _drop_spans(_drop_spans(payload, "<!--", "-->"), "<![CDATA[", "]]>")
    return bool(_ENTITY_DECL.search(markup))


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1].lower()


def _namespace(tag: str) -> str:
    if tag.startswith("{"):
        return tag[1:].split("}", 1)[0]
    return ""


# 核心元素所在的命名空间：RSS 2.0 没有命名空间，RSS 1.0 和 Atom 各有一个。
# 扩展模块（media:/itunes:/dc:）也带命名空间，同名时必须让核心元素优先——
# WordPress 类源常同时输出 <media:description>（图片说明）和 <description>（正文），
# 只比 localname 会让图片说明抢走摘要。
_CORE_NAMESPACES = frozenset({
    "",
    "http://www.w3.org/2005/Atom",
    "http://purl.org/rss/1.0/",
    "http://my.netscape.com/rdf/simple/0.9/",
})
# content:encoded 是"正文"的正规来源，比 media:/itunes: 这类附件描述更该被选中
_CONTENT_MODULE = "http://purl.org/rss/1.0/modules/content/"
_EXTENSION_RANK = 2


def _namespace_rank(tag: str) -> int:
    namespace = _namespace(tag)
    if namespace in _CORE_NAMESPACES:
        return 0
    if namespace == _CONTENT_MODULE:
        return 1
    return _EXTENSION_RANK


def _first(node: ET.Element, *names: str) -> str:
    """按 names 的优先级取非空子节点文本，命名空间比名字顺序更优先。

    排序键是 (命名空间等级, 名字序号)：核心字段永远赢；没有核心字段时
    content:encoded 赢过 media:description（否则"只有图说 + 正文"的源
    会把图说当摘要）。
    """
    best_key: tuple[int, int] | None = None
    best_text = ""
    for name_index, name in enumerate(names):
        for child in node:
            if _local(child.tag) != name:
                continue
            text = "".join(child.itertext()).strip()
            if not text:
                continue
            key = (_namespace_rank(child.tag), name_index)
            if best_key is None or key < best_key:
                best_key, best_text = key, text
    return best_text


def _atom_link(node: ET.Element) -> str:
    fallback = ""
    for child in node:
        if _local(child.tag) != "link":
            continue
        href = (child.get("href") or "").strip()
        if not href:
            continue
        rel = (child.get("rel") or "alternate").lower().rsplit("/", 1)[-1]
        if rel == "alternate":
            return href
        if not fallback:
            fallback = href
    return fallback


def parse_rss(text: str, source: Source) -> list[Item]:
    payload = text.lstrip("\ufeff").strip()
    if not payload:
        raise ParseError("响应为空")
    # ElementTree 会展开内部实体，深层嵌套可以指数级放大内存（billion laughs）。
    # 正规 feed 不需要自定义实体，看到就直接拒绝，而不是把 runner 撑爆。
    if _has_entity_declaration(payload):
        raise ParseError("响应里包含自定义 XML 实体（<!ENTITY>），已拒绝解析")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        head = clean(payload)[:80]
        if re.search(r"<(?:html|!doctype\s+html)\b", payload[:600], re.I):
            raise ParseError(f"返回的是网页而不是订阅源（可能被 WAF 拦了）：{head[:60]}") from exc
        raise ParseError(f"XML 解析失败：{exc}") from exc

    root_name = _local(root.tag)
    if root_name == "html":
        raise ParseError("返回的是 HTML 页面而不是订阅源（可能被 WAF 拦了）")
    if root_name not in ("rss", "feed", "rdf"):
        raise ParseError(f"无法识别的 XML 根节点 <{root_name}>，可能不是订阅源")

    items: list[Item] = []
    seen: set[str] = set()
    for node in root.iter():
        if _local(node.tag) not in ("item", "entry"):
            continue
        title = _first(node, "title")
        link = _first(node, "link") or _atom_link(node)
        guid = _first(node, "guid", "id")
        uid = guid or link or title
        if not uid:
            continue
        if not link and re.match(r"^https?://", guid):
            link = guid
        if uid in seen:
            continue
        seen.add(uid)
        item = build_item(
            source,
            uid=uid,
            title=title,
            link=link,
            published=parse_time(
                _first(node, "published", "pubdate", "issued", "created", "updated", "modified", "date")
            ),
            summary=_first(node, "summary", "description", "content", "encoded"),
        )
        if item:
            items.append(item)
    # 结构合法但没有条目（比如刚上线的空 feed）不算错误，交给上层判断
    return _cap(items)


# ---------------------------------------------------------------- CISA KEV

def parse_kev(text: str, source: Source) -> list[Item]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"JSON 解析失败：{exc}") from exc

    rows = data.get("vulnerabilities") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ParseError("CISA KEV 缺少 vulnerabilities 数组，目录结构可能已改变")

    items: list[Item] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cveID", "")).strip().upper()
        if not CVE_PATTERN.fullmatch(cve):
            continue
        vendor = str(row.get("vendorProject", "")).strip()
        product = str(row.get("product", "")).strip()
        name = str(row.get("vulnerabilityName", "")).strip() or cve
        prefix = f"{vendor} {product}".strip()
        title = name if not prefix or name.lower().startswith(prefix.lower()) else f"{prefix}：{name}"
        summary = str(row.get("shortDescription", ""))
        ransomware = str(row.get("knownRansomwareCampaignUse", "")).lower() == "known"
        item = build_item(
            source,
            uid=cve,
            title=title,
            link=f"https://nvd.nist.gov/vuln/detail/{cve}",
            published=parse_time(row.get("dateAdded")),
            summary=summary,
            cves=(cve,),
            exploited=True,
            ransomware=ransomware,
        )
        if item:
            items.append(item)
    if rows and not items:
        raise ParseError("CISA KEV 有数据但没有一条带有效 CVE 编号，字段结构可能已改变")
    return _cap(items)


# ---------------------------------------------------------------- 通用 JSON

def _as_text(value) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def dig(obj, path: str):
    """按 a.b.0.c 取值，支持数组下标。"""
    current = obj
    if not path:
        return current
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def parse_json(text: str, source: Source) -> list[Item]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"JSON 解析失败：{exc}") from exc

    mapping = source.mapping

    def field(name: str, default: str) -> str:
        """取映射路径；空字符串视为"没配"，回落到默认字段名。

        `dig(row, "")` 会返回整行对象，直接把整行 JSON dump 成标题——
        配置里少写一个值就变成一堆垃圾标题，所以这里必须先归一化。
        """
        return mapping.get(name, "").strip() or default

    path = mapping.get("path", "").strip()
    rows = dig(data, path)
    if not isinstance(rows, list):
        raise ParseError(f"json.path={path!r} 没指向数组，请检查字段映射")

    title_path = field("title", "title")
    link_path = field("link", "link")
    id_path = field("id", "id")
    summary_path = field("summary", "summary")
    date_path = field("date", "date")
    cve_path = mapping.get("cve", "").strip()

    items: list[Item] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        title = _as_text(dig(row, title_path))
        link = _as_text(dig(row, link_path))
        uid = _as_text(dig(row, id_path)) or link or title
        cve_field = _as_text(dig(row, cve_path)) if cve_path else ""
        summary = _as_text(dig(row, summary_path))
        item = build_item(
            source,
            uid=uid,
            title=title,
            link=link,
            published=parse_time(dig(row, date_path)),
            summary=summary,
            cves=_cves(title, summary, cve_field),
        )
        if item:
            items.append(item)
    if rows and not items:
        raise ParseError("JSON 里有数据但没有一条能映射出标题，请检查字段映射")
    return _cap(items)


# ---------------------------------------------------------------- nginx 公告页

_PARA = re.compile(r"<p\b[^>]{0,200}>(.*?)</p>", re.I | re.S)
_P_CLOSE = re.compile(r"</p\s*>", re.I)
# nginx 的公告块一定带 "Severity:" 行；用不含捕获的线性正则判断，避免 lower() 复制整段
_SEVERITY_WORD = re.compile(r"severity", re.I)
_BR = re.compile(r"<br\s*/?>", re.I)
_LINK_TAG = re.compile(r"<a\b[^>]{0,300}>(.*?)</a>", re.I | re.S)
_A_HREF = re.compile(r"""<a\b[^>]{0,300}?href\s*=\s*["']([^"']{1,600})["']""", re.I)
# 链接文字是这些的时候没有信息量，和后面的【编号】重复
_NOISE = {"advisory", "advisories", "details", "详情", "公告"}


def _list_items(text: str):
    """按 <li …>…</li> 顺序切出块内容。

    刻意不用 `(.*?)</li>` 正则：遇到"大量未闭合 <li>"的页面时，每个 <li> 都要
    一路扫到文末才失败，整体退化成 O(n²)——几十 KB 的错误页就能让一轮跑上几分钟。
    这里用 find 定位，并且一旦后面再没有 </li> 就整体收工，是线性的。
    """
    pos = 0
    while True:
        start = text.find("<li", pos)
        if start < 0:
            return
        after = start + 3
        # 排除 <link>、<line> 这类前缀相同的标签（原正则用 \b 达到同样目的）
        if after < len(text) and text[after] not in " \t\r\n/>":
            pos = after
            continue
        open_end = text.find(">", after)
        if open_end < 0:
            tail = text[start:]
            if "<p" in tail.lower() or CVE_PATTERN.search(tail):
                raise ParseError("NGINX 页面结构不完整（<li> 标签被截断），可能响应被截断")
            return
        close = text.find("</li>", open_end)
        if close < 0:
            tail = text[open_end + 1:]
            if "<p" in tail.lower() or CVE_PATTERN.search(tail):
                raise ParseError("NGINX 页面结构不完整（<li> 未闭合），可能响应被截断")
            return
        yield text[open_end + 1:close]
        pos = close + len("</li>")


def parse_nginx(text: str, source: Source) -> list[Item]:
    items: list[Item] = []
    for block in _list_items(text):
        # 先把搜索范围压到第一个 </p>：单个超长 <li> 里若全是未闭合的 <p>，
        # `.*?</p>` 会从每个 <p> 一路扫到文末，整体 O(n²)
        # （实测 256KB 的畸形页面要 89 秒）。
        close = _P_CLOSE.search(block)
        if not close:
            continue
        para = _PARA.search(block[: close.end()])
        if not para:
            continue
        # "severity" 在整段里判断（线性正则，不受下面的截断影响），否则一条
        # 超长公告会因为 Severity 那行被切掉而整条消失。
        full = para.group(1)
        if not _SEVERITY_WORD.search(full):
            continue
        # 后面的清洗/unwrap 只看前 MAX_CLEAN_CHARS 个字符：摘要本来只留 300 字，
        # 没必要为几十万字的段落白烧 CPU（也能挡住未闭合 <a> 的二次复杂度）。
        raw = full[:MAX_CLEAN_CHARS]
        parts = _BR.split(raw)
        title = clean(parts[0])
        if not title:
            continue
        cves = _cves(raw)
        details = []
        for part in parts[1:]:
            detail = clean(_LINK_TAG.sub(r"\1", part))
            if not detail:
                continue
            if detail.lower() in _NOISE or detail.upper() in cves:
                continue
            if re.match(r"^severity\s*[:：]", detail, re.I):
                continue          # 渲染层已经单独出了【等级】行
            details.append(detail)
        summary = "；".join(details)
        # 优先用公告自己的链接；取不到再退回 cve.org，别把用户锁死在 CVE 页
        href = _A_HREF.search(raw)
        link = href.group(1).strip() if href else ""
        if not link.lower().startswith(("http://", "https://")):
            link = f"https://www.cve.org/CVERecord?id={cves[0]}" if cves else ""
        # 没有 CVE 的公告（例如厂商内部编号）也要推：uid 退回链接，再退回标题。
        # 以前直接 continue，最新的公告只要没写 CVE 就会被静默漏掉。
        uid = cves[0] if cves else (link or title)
        item = build_item(
            source,
            uid=uid,
            title=title,
            link=link,
            summary=summary,
            cves=cves,
            # 等级从原始段落读：Severity 那行已经从摘要里剔掉了
            severity=severity_of(raw),
        )
        if item:
            items.append(item)
    if not items:
        raise ParseError("没有解析出 NGINX 公告（页面结构可能变了）")
    return _cap(items)


PARSERS = {
    "rss": parse_rss,
    "kev": parse_kev,
    "json": parse_json,
    "nginx": parse_nginx,
}
