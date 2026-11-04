"""严格读取与校验 config.json。

设计原则：宁可启动就报错，也不要带着半个配置跑到线上。
所有错误信息都指出"第几个源、哪个字段"，方便直接改配置。
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from .models import (
    MAX_ITEMS,
    MAX_ITEMS_CAP,
    MAX_NAME_CHARS,
    MAX_WINDOW_HOURS,
    Config,
    ConfigError,
    Source,
    sanitize_text,
)
from .net import allow_private_hosts, is_blocked_host, is_metadata_address
from .parse import PARSERS

ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# 只允许引用这个前缀的环境变量。config.json 是公开提交的，如果允许 ${FEISHU_SECRET}
# 这类写法，一个"新增数据源"的 PR 就能把机器人密钥带进 URL/请求头发到外部。
ENV_PREFIX = "VIGIL_"
# HTTP 头字段名只允许 token 字符（RFC 7230）
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

TOP_KEYS = {"sources", "window_hours", "max_items"}
SOURCE_KEYS = {"name", "url", "kind", "match", "limit", "exploited", "headers", "json"}
MAPPING_KEYS = {"path", "id", "title", "link", "summary", "date", "cve"}

DEFAULT_WINDOW_HOURS = 48


def expand_env(value: str) -> str:
    """把 ${VIGIL_*} 替换成环境变量；缺失时直接报错，避免把字面量发到线上。

    只允许 `VIGIL_` 前缀：配置文件是公开提交的，如果任意变量都能引用，
    一个恶意 PR 就能用 `${FEISHU_SECRET}` 把机器人密钥拼进 URL 或请求头。
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if not name.startswith(ENV_PREFIX):
            raise ConfigError(
                f"环境变量 {name} 不允许在配置里引用：只允许 {ENV_PREFIX}* 前缀，"
                "避免配置读取飞书/百度等工具自身的密钥"
            )
        if name not in os.environ:
            raise ConfigError(f"环境变量 {name} 未设置")
        return os.environ[name]

    return ENV_RE.sub(replace, value)


def _int_field(value, name: str, low: int, high: int) -> int | None:
    """校验可选整数；字段缺席时返回 None，由调用方决定默认值。

    刻意不在这里塞 default 参数：以前 `limit` 用 `default=0` 而合法区间是 1~50，
    "0 表示没配" 这条约定只存在于调用方脑子里，改起来很容易踩。
    """
    if value is None:
        return None
    # bool 是 int 的子类，必须单独排除
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{name} 应为 {low}~{high} 之间的整数")
    return value


def _str_map(value, name: str, allowed: set[str] | None = None) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} 应为对象")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ConfigError(f"{name} 的键和值都必须是字符串")
        if allowed is not None and key not in allowed:
            raise ConfigError(f"{name} 含未知字段 {key!r}")
        result[key] = item
    return result


def _check_url(url: str, where: str) -> None:
    try:
        parts = urlsplit(url)
        # 访问 .port 就会校验端口合法性，非法端口在这里就拦下来
        _ = parts.port
    except ValueError as exc:
        raise ConfigError(f"{where}的 url 无法解析：{exc}") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"{where}的 url 必须是完整的 http/https 地址")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        # 换行/控制字符会让 http.client 在发请求时才抛 ValueError，
        # 也会把日志和卡片排版弄乱；在配置阶段就拒绝。
        raise ConfigError(f"{where}的 url 不能包含换行或控制字符")
    if parts.username is not None or parts.password is not None:
        raise ConfigError(f"{where}的 url 不应包含用户名或密码，请改用 Secrets 和请求头")
    # 元数据地址必须先判：它连逃生门也不放行。放在私网判断之后会出现
    # "请设置 VIGIL_ALLOW_PRIVATE_HOSTS=1"——用户照做后仍然被拒。
    if is_metadata_address(parts.hostname):
        raise ConfigError(
            f"{where}的 url 指向云元数据或链路本地地址，已拒绝"
            "（这类地址不受 VIGIL_ALLOW_PRIVATE_HOSTS 影响）"
        )
    # 启动时就拦住本机/私网地址，而不是等到抓取时才失败（否则每轮都会记一次源失败）。
    if not allow_private_hosts() and is_blocked_host(parts.hostname):
        raise ConfigError(
            f"{where}的 url 指向本机或私网地址，已拒绝；"
            "如果确实要抓内网源，请设置 VIGIL_ALLOW_PRIVATE_HOSTS=1"
        )


def _check_headers(headers: dict[str, str], where: str) -> dict[str, str]:
    """校验自定义请求头。

    urllib 把非法字段名/值留到发请求时才由 http.client 抛 ValueError，
    那会绕过 fetch() 的错误处理直接把整轮打挂。所以在启动时就拦住，
    顺带 strip 掉值两端空白——Secret 粘贴时带尾随换行是常见事故。
    """
    cleaned: dict[str, str] = {}
    for name, value in headers.items():
        name = sanitize_text(name).strip()
        value = sanitize_text(expand_env(value)).strip()
        if not HEADER_NAME_RE.match(name):
            raise ConfigError(f"{where}的 headers 字段名不合法：{name!r}")
        if "\r" in value or "\n" in value:
            raise ConfigError(f"{where}的 headers.{name} 值里不能有换行（检查 Secret 是否带尾随换行）")
        cleaned[name] = value
    return cleaned


def load_config(path: Path | str) -> Config:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ConfigError(f"无法读取配置 {path}：{exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"配置文件不是 UTF-8 编码：{exc}") from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置 JSON 无效：{exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError("配置顶层必须是 JSON 对象")
    unknown = set(raw) - TOP_KEYS
    if unknown:
        raise ConfigError(f"配置含未知字段：{', '.join(sorted(unknown))}")

    entries = raw.get("sources")
    if not isinstance(entries, list) or not entries:
        raise ConfigError("sources 必须是非空数组")

    window = _int_field(raw.get("window_hours"), "window_hours", 1, MAX_WINDOW_HOURS)
    max_items = _int_field(raw.get("max_items"), "max_items", 1, MAX_ITEMS_CAP)
    window = DEFAULT_WINDOW_HOURS if window is None else window
    max_items = MAX_ITEMS if max_items is None else max_items

    sources: list[Source] = []
    names: set[str] = set()
    keys: set[str] = set()

    for index, entry in enumerate(entries, 1):
        where = f"第 {index} 个源"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}必须是对象")
        unknown = set(entry) - SOURCE_KEYS
        if unknown:
            raise ConfigError(f"{where}含未知字段：{', '.join(sorted(unknown))}")

        raw_name = entry.get("name")
        raw_url = entry.get("url")
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ConfigError(f"{where}缺少有效 name")
        if not isinstance(raw_url, str) or not raw_url.strip():
            raise ConfigError(f"{where}缺少有效 url")

        name = sanitize_text(" ".join(raw_name.split()))
        if len(name) > MAX_NAME_CHARS:
            raise ConfigError(f"{where}的 name 过长（最多 {MAX_NAME_CHARS} 个字符）")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name):
            raise ConfigError(f"{where}的 name 不能包含控制字符")
        if name in names:
            raise ConfigError(f"{where}的 name 与前面的源重复：{name}（消息里会分不清）")
        names.add(name)

        url = sanitize_text(expand_env(raw_url.strip())).strip()
        _check_url(url, where)

        kind = entry.get("kind", "rss")
        if not isinstance(kind, str):
            raise ConfigError(f"{where}的 kind 必须是字符串")
        kind = sanitize_text(kind).strip().lower()
        if kind not in PARSERS:
            raise ConfigError(f"{where}的 kind 必须是 {sorted(PARSERS)}")

        match = entry.get("match", "")
        if not isinstance(match, str):
            raise ConfigError(f"{where}的 match 必须是字符串")
        match = sanitize_text(match).strip()
        if match:
            try:
                re.compile(match)
            except re.error as exc:
                raise ConfigError(f"{where}的 match 正则无效：{exc}") from exc

        exploited = entry.get("exploited", False)
        if type(exploited) is not bool:
            raise ConfigError(f"{where}的 exploited 必须是 JSON 布尔值")

        limit = _int_field(entry.get("limit"), f"{where}的 limit", 1, MAX_ITEMS_CAP)
        limit = 0 if limit is None else limit   # 0 = 沿用全局 max_items

        headers = _str_map(entry.get("headers", {}), f"{where}的 headers")
        headers = _check_headers(headers, where)

        if "json" in entry and kind != "json":
            raise ConfigError(f"{where}只有 kind=json 时才能配置 json 映射")
        if kind == "json" and "json" not in entry:
            raise ConfigError(f"{where}使用 kind=json 时必须提供 json 映射")
        mapping = _str_map(entry.get("json", {}), f"{where}的 json", MAPPING_KEYS)
        for key, value in mapping.items():
            # path 可以为空（表示根节点就是数组）；其它字段留空会让 dig(row, "")
            # 返回整行对象，最后把一整段 JSON dump 当成标题推出去。
            if key != "path" and not value.strip():
                raise ConfigError(
                    f"{where}的 json.{key} 不能为空；不写这个键就会使用默认字段名"
                )

        source = Source(name, url, kind, match, limit, exploited, headers, mapping)
        if source.key in keys:
            raise ConfigError(f"{where}与前一个源身份相同（url + kind + match 都一样）：{url}")
        keys.add(source.key)
        sources.append(source)

    return Config(sources, window, max_items)
