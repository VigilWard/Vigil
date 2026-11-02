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

# 只认"看起来像标签"的东西：</?字母 …>。
# 不能用 [^>]*：安全公告里到处都是 "affected versions < 1.2.3"，
# 那种 < 不是标签，一旦被当成标签就会把后面的正文整段吃掉。
# 字符类同时排除 < 和 >，遇到未闭合的 < 立刻失败，不会在每个位置上回溯。
_TAG = re.compile(r"</?[A-Za-z][^<>]{0,2000}>")
# 注释单独处理：它不是标签，但也不该出现在摘要里。长度有上限，不会回溯爆炸。
_COMMENT = re.compile(r"<!--.{0,2000}?-->", re.S)
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


def clean(value: str | None) -> str:
    """把 HTML / Markdown 摘要压成一行纯文本。

    刻意保守：只处理成对且紧贴文字的强调标记，`a * b * c`、`snake_case_name`
    这类正文里的普通符号必须原样保留。

    入口先截断：摘要最终只留 300 字，为几十万字的正文跑十几次正则纯属浪费，
    而且给了恶意 feed 一个把 runner 拖死的入口。
    """
    raw = value or ""
    if not isinstance(raw, str):
        raw = str(raw)
    # 先截断再 sanitize，避免对几十万字的正文做一次全量 encode。
    text = sanitize_text(raw[:MAX_CLEAN_CHARS])
    text = html.unescape(text)
    text = text.translate(_ZERO_WIDTH)
    # 先统一换行符：邮件列表类源大量用 CRLF，行尾的 \r 会让 ^...$ 类的规则匹配不上
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _COMMENT.sub(" ", text)
    text = _TAG.sub(" ", text)
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


def parse_time(value) -> int:
    """把各种常见时间格式转成 Unix 秒；无法识别时返回 0（= 无日期）。"""
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
        return stamp if 0 < stamp < 4102444800 else 0

    text = str(value).strip()
    if not text or text.lower() in ("null", "none", "n/a"):
        return 0
    if text.isdigit():
        # 只有 9~13 位才当作 Unix 时间戳；8 位的 20261031 是日期，不能按 1970 年算
        if 9 <= len(text) <= 13:
            return parse_time(int(text))
    else:
        normalized = text.replace("Z", "+00:00") if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp())
        except (ValueError, OverflowError, OSError):
            pass

    try:
        parsed = parsedate_to_datetime(text)
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp())
    except (TypeError, ValueError, OverflowError):
        pass

    for fmt in _EXTRA_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return int(parsed.timestamp())
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
_SCORE_LABEL = re.compile(r"(?:base\s+)?score\s*[:：=]?\s*(\d{1,2}(?:\.\d)?)", re.I)
_CVSS_VALUE = re.compile(r"cvss[^\d]{0,12}v?\d(?:\.\d)?\s*[:：]\s*(\d{1,2}(?:\.\d)?)", re.I)
_CVSS_VERSION = re.compile(r"cvss\s*v?(\d(?:\.\d)?)", re.I)
_CVSS_VECTOR = re.compile(r"CVSS:\d\.\d/[A-Z:/]+", re.I)
_CVSS_CONTEXT = re.compile(r"cvss|score|severity|评分|风险", re.I)
# CVSS 版本号只有这几个；"CVSS 9.8" 里的 9.8 是分数，不能当版本剥掉。
_CVSS_KNOWN_VERSIONS = frozenset({"2.0", "3.0", "3.1", "4.0"})
# 没有小数点的分数（CVSS 10 / CVSS 9）；要求前面是 cvss 且后面不是数字或点。
_CVSS_INT = re.compile(r"cvss\s*[:：=]?\s*(\d{1,2})(?![\d.])", re.I)
_DECIMAL = re.compile(r"(?<![\d.])(\d{1,2}\.\d)(?![.\d])")


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
    """超大 feed 只保留最新的一批，避免一次解析几千条把内存和 state 撑爆。"""
    if len(items) <= MAX_NODES:
        return items
    ranked = sorted(items, key=lambda item: item.published or 2**31, reverse=True)
    log(f"⚠ 条目过多（{len(items)} 条），只保留最新 {MAX_NODES} 条")
    return ranked[:MAX_NODES]


# ---------------------------------------------------------------- RSS / Atom

# 自定义实体声明：正规订阅源不需要，出现即视为攻击面
_ENTITY_DECL = re.compile(r"<!ENTITY", re.I)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1].lower()


def _first(node: ET.Element, *names: str) -> str:
    """按 names 的优先级取第一个非空子节点文本。"""
    for name in names:
        for child in node:
            if _local(child.tag) == name:
                text = "".join(child.itertext()).strip()
                if text:
                    return text
    return ""


def _atom_link(node: ET.Element) -> str:
    fallback = ""
    for child in node:
        if _local(child.tag) != "link":
            continue
        href = (child.get("href") or "").strip()
        if not href:
            continue
        rel = (child.get("rel") or "alternate").lower()
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
    if _ENTITY_DECL.search(payload):
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
    rows = dig(data, mapping.get("path", ""))
    if not isinstance(rows, list):
        raise ParseError(f"json.path={mapping.get('path', '')!r} 没指向数组，请检查字段映射")

    items: list[Item] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        title = _as_text(dig(row, mapping.get("title", "title")))
        link = _as_text(dig(row, mapping.get("link", "link")))
        uid = _as_text(dig(row, mapping.get("id", "id"))) or link or title
        cve_field = _as_text(dig(row, mapping["cve"])) if mapping.get("cve") else ""
        item = build_item(
            source,
            uid=uid,
            title=title,
            link=link,
            published=parse_time(dig(row, mapping.get("date", "date"))),
            summary=_as_text(dig(row, mapping.get("summary", "summary"))),
            cves=_cves(title, _as_text(dig(row, mapping.get("summary", "summary"))), cve_field),
        )
        if item:
            items.append(item)
    if rows and not items:
        raise ParseError("JSON 里有数据但没有一条能映射出标题，请检查字段映射")
    return _cap(items)


# ---------------------------------------------------------------- nginx 公告页

_PARA = re.compile(r"<p\b[^>]{0,200}>(.*?)</p>", re.I | re.S)
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
        para = _PARA.search(block)
        if not para:
            continue
        raw = para.group(1)
        parts = _BR.split(raw)
        title = clean(parts[0])
        if not title or "severity" not in raw.lower():
            continue
        cves = _cves(raw)
        if not cves:
            continue
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
            link = f"https://www.cve.org/CVERecord?id={cves[0]}"
        item = build_item(
            source,
            uid=cves[0],
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
