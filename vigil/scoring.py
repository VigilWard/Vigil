"""从公告正文里读严重等级与 CVSS 分数。

刻意不查 NVD：等级只反映源自己写的内容，取不到就是"未知"（0）。
放在独立模块里，是因为这套启发式和解析器没有关系：RSS / JSON / nginx
三个分支都要用，而 parse.py 已经承担了清洗与四种格式的解析。
"""
from __future__ import annotations

import re

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
# 兜底的裸分数：必须紧跟在 CVSS/评分/风险 后面，最多隔一个连接词。
# 以前用 _DECIMAL 扫全文，会把 "fixed: 6.6"（内核版本）、"Affected: 4.4"
# 这类版本号当成 CVSS 分数，给一条只给向量、没给分数的公告编出中危分。
_CVSS_NEAR = re.compile(
    r"(?:cvss|评分|风险)\s*(?:评分)?\s*(?:(?:of|is|score)\s*)?[:：=]?\s*"
    r"(\d{1,2}\.\d)(?!\d)(?!\.\d)",
    re.I,
)


def _level_of(score: float) -> int:
    if score >= 9:
        return 4
    if score >= 7:
        return 3
    if score >= 4:
        return 2
    return 1 if score > 0 else 0


def _strip_cvss_versions(text: str) -> str:
    """只剥掉真正的版本号，保留 "CVSS 9.8" 这类裸分数。

    版本号换成一个 " cvss " 占位而不是空串：后面的分数还得靠这个语境词才能
    被认出来（"CVSS 3.1 9.8" 剥完是 " cvss  9.8"）。
    """

    def replace(match: re.Match[str]) -> str:
        return " cvss " if match.group(1) in _CVSS_KNOWN_VERSIONS else match.group(0)

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
    stripped = _strip_cvss_versions(_CVSS_VECTOR.sub(" cvss ", text))
    match = _CVSS_NEAR.search(stripped)
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
