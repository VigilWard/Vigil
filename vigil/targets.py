"""读取并校验飞书推送目标。

FEISHU_WEBHOOKS 支持 JSON 数组或逗号/换行分隔的多条 webhook；
FEISHU_WEBHOOK 是单目标的兼容写法。所有校验都在启动时做完：
配置有问题就立刻报错，而不是抓完一轮才发现发不出去。
"""
from __future__ import annotations

import json
import os
import urllib.parse

from .models import ConfigError, PushTarget

FEISHU_HOST_SUFFIXES = (".feishu.cn", ".larksuite.com")


def _is_feishu_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host in ("feishu.cn", "larksuite.com") or host.endswith(FEISHU_HOST_SUFFIXES)


def load_targets() -> list[PushTarget]:
    """读取推送目标。FEISHU_WEBHOOKS 优先，解析出 0 个目标时回落到 FEISHU_WEBHOOK。"""
    shared_secret = os.environ.get("FEISHU_SECRET", "").strip()
    raw = os.environ.get("FEISHU_WEBHOOKS", "").strip()
    single = os.environ.get("FEISHU_WEBHOOK", "").strip()
    allow_any_host = os.environ.get("FEISHU_ALLOW_ANY_HOST", "").strip().lower() in (
        "1", "true", "yes", "on",
    )
    entries: list = []

    if raw:
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ConfigError(f"FEISHU_WEBHOOKS 不是合法 JSON：{exc}") from exc
            if not isinstance(parsed, list):
                raise ConfigError("FEISHU_WEBHOOKS 必须是数组")
            entries = parsed
        else:
            entries = [part.strip() for part in raw.replace("\r", "").replace(",", "\n").split("\n")]

    # 逗号/换行分隔时尾部空项是常态，先剔掉再判断"是不是真的一个目标都没有"
    entries = [entry for entry in entries
               if not (isinstance(entry, str) and not entry.strip())]

    if not entries and single:
        # FEISHU_WEBHOOKS 存在但解析出 0 个目标（例如留了个 "[]" 或 ","）时回落到单目标写法。
        # 以前这里会直接返回空列表，结果一条消息都发不出去，而且不报任何错。
        entries = [single]

    targets: list[PushTarget] = []
    seen: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            # 上面的预过滤已经把空串剔掉了，这里不必再判空
            webhook, secret = entry.strip(), shared_secret
        elif isinstance(entry, dict) and set(entry) <= {"webhook", "secret"}:
            webhook = entry.get("webhook", "")
            secret = entry.get("secret", shared_secret)
            if not isinstance(webhook, str) or not isinstance(secret, str):
                raise ConfigError("FEISHU_WEBHOOKS 的 webhook/secret 必须是字符串")
            webhook = webhook.strip()
            secret = secret.strip()
            if not webhook:
                # 写了对象却没给地址，多半是复制漏了，不该静默跳过
                raise ConfigError("FEISHU_WEBHOOKS 里有对象缺少 webhook")
        else:
            raise ConfigError("FEISHU_WEBHOOKS 的每一项必须是 URL 字符串或 {webhook, secret} 对象")
        try:
            parts = urllib.parse.urlsplit(webhook)
            _ = parts.port
        except ValueError as exc:
            raise ConfigError(f"飞书 webhook 地址无法解析：{exc}") from exc
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise ConfigError("飞书 webhook 必须是不含用户信息的完整 HTTPS 地址")
        if not allow_any_host and not _is_feishu_host(parts.hostname):
            raise ConfigError(
                "飞书 webhook 必须使用 feishu.cn / larksuite.com 域名；"
                "如果确实走代理，请设置 FEISHU_ALLOW_ANY_HOST=1"
            )
        target = PushTarget(webhook, secret)
        if target.tid not in seen:
            targets.append(target)
            seen.add(target.tid)
    return targets
