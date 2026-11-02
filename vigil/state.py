"""基线、内容指纹与待送达队列。

state.json 是整个工具唯一的"记忆"，因此这里的设计目标是：
  1. 幂等——同一轮重复执行不会重复推送；
  2. 不丢——只有确认送达的条目才写进 seen；
  3. 少写——没有实质变化时一个字节都不改，避免每 10 分钟一个 commit。
"""
from __future__ import annotations

import json
import math
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .models import (
    HEARTBEAT,
    MAX_PENDING,
    MAX_SEEN,
    PENDING_TTL,
    SEEN_REFRESH,
    SEEN_RETENTION,
    Item,
    StateError,
    dump_json,
    log,
    sanitize_text,
)

# v2：内容指纹的输入变了（摘要不再计入、NGINX 条目改用原始公告链接）。
# 旧指纹会整体失效，如果不升版本，升级后第一轮会把窗口内的历史条目当成新条目重推一遍。
STATE_VERSION = 2


def _reject_json_constant(value: str) -> None:
    """拒绝 JSON 里的 NaN / Infinity，避免 int()/float 比较抛未捕获异常。"""
    raise ValueError(f"不允许的 JSON 常量：{value}")


def _reject_json_float(value: str) -> float:
    """拒绝溢出成 inf 的浮点字面量（例如 1e400）。

    `json.loads` 只在遇到 `NaN` / `Infinity` 时调用 parse_constant；
    `1e400` 是合法 JSON 数字，但 `float()` 会得到 inf，随后 `int(inf)`
    抛的 OverflowError 会绕过所有"state 不合法"的处理。必须在入口拦住。
    """
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"不允许的非有限数字：{value}")
    return number


def _as_int(value, name: str) -> int:
    """把 state 里的数字字段转成 int，越界时给出可读的 StateError。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise StateError(f"{name} 必须是数字")
    try:
        return int(value)
    except (OverflowError, ValueError) as exc:
        raise StateError(f"{name} 超出可表示范围：{value!r}") from exc


@dataclass(slots=True)
class SourceHealth:
    """单个源的健康状态。"""

    initialized: bool = False
    etag: str = ""
    last_modified: str = ""
    fail: int = 0
    skipped: int = 0
    empty: int = 0
    had_items: bool = False
    last_ok: int = 0
    alert: str = ""
    alert_at: int = 0
    # 目标 tid → 已经收到过的告警类型。多群场景下必须按目标记账：
    # 只记一个全局 alert 会让"A 群收到了、B 群失败"变成 B 群永远收不到这条告警。
    alert_sent: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> SourceHealth:
        if not isinstance(data, dict):
            raise StateError("state.sources 的每一项都必须是对象")
        health = cls()
        for field_name in ("initialized", "had_items"):
            value = data.get(field_name, False)
            if type(value) is not bool:
                raise StateError(f"state.sources.{field_name} 必须是布尔值")
            setattr(health, field_name, value)
        for field_name in ("etag", "last_modified", "alert"):
            value = data.get(field_name, "")
            if not isinstance(value, str):
                raise StateError(f"state.sources.{field_name} 必须是字符串")
            setattr(health, field_name, sanitize_text(value))
        for field_name in ("fail", "skipped", "empty", "last_ok", "alert_at"):
            setattr(health, field_name,
                    _as_int(data.get(field_name, 0), f"state.sources.{field_name}"))
        sent = data.get("alert_sent", {})
        if not isinstance(sent, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in sent.items()
        ):
            raise StateError("state.sources.alert_sent 必须是「目标 ID → 告警类型」的字符串对象")
        health.alert_sent = {
            sanitize_text(key): sanitize_text(value) for key, value in sent.items()
        }
        return health


@dataclass(slots=True)
class Pending:
    """一条等待送达的条目。sent 记录"已经确认收到它的目标"。"""

    item: dict
    fingerprint: str
    since: int
    sent: list[str]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, key: str, data: dict) -> Pending:
        if not isinstance(data, dict) or not isinstance(data.get("item"), dict):
            raise StateError(f"state.pending.{key} 无效")
        sent = data.get("sent", [])
        if not isinstance(sent, list) or not all(isinstance(x, str) for x in sent):
            raise StateError(f"state.pending.{key}.sent 必须是字符串数组")
        item = Item.from_dict(data["item"])
        if item.key != key:
            raise StateError(f"state.pending.{key} 与条目身份不一致")
        return cls(
            item=data["item"],
            fingerprint=sanitize_text(str(data.get("fingerprint") or item.fingerprint)),
            since=_as_int(data.get("since", 0), f"state.pending.{key}.since"),
            sent=list(dict.fromkeys(sanitize_text(value) for value in sent)),
        )


class State:
    def __init__(self) -> None:
        self.sources: dict[str, SourceHealth] = {}
        self.seen: dict[str, str] = {}
        self.seen_at: dict[str, int] = {}
        self.pending: dict[str, Pending] = {}
        self.saved_at: int = 0
        self.heartbeat: int = 0
        self._pruned = False

    # ------------------------------------------------------------ 健康状态
    def health(self, key: str) -> SourceHealth:
        return self.sources.setdefault(key, SourceHealth())

    # ------------------------------------------------------------ 去重
    def is_fresh(self, item: Item) -> bool:
        """内容指纹和上次送达的不一样，就是需要推送的条目。

        已经在待送达队列里、且指纹相同的条目不算新——否则推送失败期间
        每一轮都会把它重新翻译一遍，白白烧掉翻译配额。
        """
        record = self.pending.get(item.key)
        if record is not None and record.fingerprint == item.fingerprint:
            return False
        return self.seen.get(item.key) != item.fingerprint

    def touch(self, key: str, now: int) -> None:
        """条目仍在源里出现，延长保留期。粗粒度刷新，避免每轮都改状态。"""
        if now - self.seen_at.get(key, 0) >= SEEN_REFRESH:
            self.seen_at[key] = now

    def remember(self, item: Item, now: int) -> None:
        self.seen[item.key] = item.fingerprint
        self.seen_at[item.key] = now
        self.pending.pop(item.key, None)

    # ------------------------------------------------------------ 待送达队列
    def queue(self, item: Item, now: int) -> bool:
        """入队；同指纹的记录已存在时什么都不做。

        内容更新（指纹变了）会替换整条记录；只补译文这种"指纹不变"的刷新
        走 refresh()，两者职责分开，避免这里既要判重又要合并字段。
        """
        existing = self.pending.get(item.key)
        if existing and existing.fingerprint == item.fingerprint:
            return False
        self.pending[item.key] = Pending(
            item=item.to_dict(),
            fingerprint=item.fingerprint,
            since=now,
            sent=[],
        )
        return True

    def refresh(self, item: Item) -> None:
        """把条目的新内容（通常是补上的译文）写回待送达队列。"""
        record = self.pending.get(item.key)
        if record is None or record.fingerprint != item.fingerprint:
            return
        record.item = item.to_dict()

    def pending_items(self, source_key: str | None = None) -> list[Item]:
        """待送达条目的副本（按源过滤）。

        返回的是新构造的 Item，改它们不会影响 state——要写回请用 refresh()。
        """
        items = []
        for record in self.pending.values():
            item = Item.from_dict(record.item)
            if source_key is None or item.source_key == source_key:
                items.append(item)
        return items

    def pending_for(self, target_id: str) -> list[Item]:
        items = []
        for record in self.pending.values():
            if target_id in record.sent:
                continue
            items.append(Item.from_dict(record.item))
        # 稳定顺序：新的在前，同时间按 key，保证每轮渲染结果一致
        items.sort(key=lambda item: (-item.published, item.key))
        return items

    def ack(self, keys: list[str], target_id: str, target_ids: set[str], now: int) -> None:
        """确认一页送达：先按目标记账，所有目标都收到后才转正为 seen。"""
        if not target_ids:
            return
        completed: list[Item] = []
        for key in dict.fromkeys(keys):
            record = self.pending.get(key)
            if record is None:
                continue
            if target_id not in record.sent:
                record.sent.append(target_id)
            if target_ids.issubset(set(record.sent)):
                completed.append(Item.from_dict(record.item))
        for item in completed:
            self.remember(item, now)

    # ------------------------------------------------------------ 清理
    def prune(self, now: int) -> tuple[int, int]:
        """裁剪过期的 seen 与 pending，返回 (丢弃的 seen 数, 丢弃的 pending 数)。

        pending 是有意设置上限的：webhook 坏了一周之后不该一口气补推上千条，
        宁可丢掉过期资讯并留下日志。
        """
        dropped_pending = 0
        for key, record in list(self.pending.items()):
            if now - record.since > PENDING_TTL:
                self.pending.pop(key, None)
                # 记成已处理，避免无日期的源（NGINX）下一轮又把同一条重新入队，
                # 让 TTL 变成"每 7 天循环一次"而不是真正的丢弃。
                self.seen[key] = record.fingerprint
                self.seen_at[key] = now
                dropped_pending += 1

        if len(self.pending) > MAX_PENDING:
            ordered = sorted(self.pending.items(), key=lambda pair: pair[1].since)
            for key, record in ordered[: len(self.pending) - MAX_PENDING]:
                self.pending.pop(key, None)
                self.seen[key] = record.fingerprint
                self.seen_at[key] = now
                dropped_pending += 1

        cutoff = now - SEEN_RETENTION
        dropped_seen = 0
        for key, stamp in list(self.seen_at.items()):
            if stamp < cutoff and key not in self.pending:
                self.seen.pop(key, None)
                self.seen_at.pop(key, None)
                dropped_seen += 1

        if len(self.seen) > MAX_SEEN:
            need = len(self.seen) - MAX_SEEN
            # 一次排序搞定：按 seen_at 从旧到新，缺失 seen_at 的（手工改过 state）
            # 视为最旧。原来的写法先按 seen_at 删一轮、再"兜底"扫一遍 seen，
            # 兜底那轮是从字典迭代序里随便删，可能把刚写入的记录删掉。
            for key in sorted(self.seen, key=lambda item: (self.seen_at.get(item, 0), item)):
                if need <= 0:
                    break
                if key in self.pending:
                    continue
                self.seen.pop(key, None)
                self.seen_at.pop(key, None)
                dropped_seen += 1
                need -= 1
        return dropped_seen, dropped_pending

    # ------------------------------------------------------------ 序列化
    def to_dict(self) -> dict:
        return {
            "version": STATE_VERSION,
            "saved_at": self.saved_at,
            "heartbeat": self.heartbeat,
            "sources": {key: health.to_dict() for key, health in self.sources.items()},
            "seen": dict(self.seen),
            "seen_at": dict(self.seen_at),
            "pending": {key: record.to_dict() for key, record in self.pending.items()},
        }

    @classmethod
    def from_dict(cls, raw: dict) -> State:
        if not isinstance(raw, dict):
            raise StateError("state.json 顶层必须是对象")
        version = raw.get("version", 0)
        if version != STATE_VERSION:
            raise StateError(
                f"state.json 版本 {version!r} 与当前格式（v{STATE_VERSION}）不兼容。"
                "请在 Actions 里用 reset 模式跑一次，或本地执行 `python watch.py --reset`；"
                "重建基线后即可正常运行，历史条目不会被补推。"
            )

        state = cls()
        state.saved_at = _as_int(raw.get("saved_at", 0), "state.saved_at")
        state.heartbeat = _as_int(raw.get("heartbeat", 0), "state.heartbeat")
        sources = raw.get("sources", {})
        if not isinstance(sources, dict):
            raise StateError("state.sources 必须是对象")
        state.sources = {
            sanitize_text(str(key)): SourceHealth.from_dict(value)
            for key, value in sources.items()
        }

        seen = raw.get("seen", {})
        if not isinstance(seen, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in seen.items()
        ):
            raise StateError("state.seen 必须是字符串对象")
        state.seen = {
            sanitize_text(key): sanitize_text(value) for key, value in seen.items()
        }

        seen_at = raw.get("seen_at", {})
        if not isinstance(seen_at, dict):
            raise StateError("state.seen_at 必须是对象")
        state.seen_at = {}
        for key, value in seen_at.items():
            state.seen_at[sanitize_text(str(key))] = _as_int(
                value, f"state.seen_at.{key}"
            )

        pending = raw.get("pending", {})
        if not isinstance(pending, dict):
            raise StateError("state.pending 必须是对象")
        state.pending = {
            sanitize_text(str(key)): Pending.from_dict(sanitize_text(str(key)), value)
            for key, value in pending.items()
        }
        return state

    # ------------------------------------------------------------ 读写
    def save(self, path: Path | str) -> bool:
        """原子写入；内容没有实质变化时直接返回 False，不碰文件。

        例外是心跳：公开仓库连续 60 天没有提交会被停掉定时任务，
        所以哪怕内容完全没变，每 HEARTBEAT 也强制写一次。
        """
        path = Path(path)
        now = int(time.time())
        if not self._pruned:
            dropped_seen, dropped_pending = self.prune(now)
            if dropped_seen or dropped_pending:
                log(f"   清理状态：seen -{dropped_seen}，待送达 -{dropped_pending}")
            self._pruned = True

        if now - self.heartbeat >= HEARTBEAT:
            self.heartbeat = now

        payload = self.to_dict()
        payload.pop("saved_at", None)

        previous = None
        if path.exists():
            try:
                previous = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                previous = None
        if isinstance(previous, dict):
            previous.pop("saved_at", None)
            if previous == payload:
                return False

        self.saved_at = now
        payload["saved_at"] = now
        text = dump_json(payload, indent=None) + "\n"
        temp = path.with_name(path.name + ".tmp")
        try:
            with temp.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
        finally:
            if temp.exists():
                temp.unlink()
        return True


def load_state(path: Path | str) -> State:
    path = Path(path)
    if not path.exists():
        return State()
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise StateError(f"state.json 读取失败：{exc}") from exc
    except UnicodeDecodeError as exc:
        raise StateError(f"state.json 不是 UTF-8 编码：{exc}") from exc
    try:
        # Python 的 json 默认接受 NaN/Infinity；它们会让 int()/float 比较
        # 在后续校验里抛 ValueError，必须在解析入口就拒绝。
        # parse_float 额外拦住 1e400 这类溢出成 inf 的合法数字。
        raw = json.loads(
            text,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
        )
    except ValueError as exc:
        raise StateError(f"state.json 不是合法 JSON（已停止，避免覆盖基线）：{exc}") from exc
    return State.from_dict(raw)
