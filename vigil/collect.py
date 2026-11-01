"""抓取编排：逐源抓取、过滤、入队，以及跨源合并。"""
from __future__ import annotations

import re
import time

from .models import (
    BudgetExceeded,
    Config,
    Failure,
    FetchError,
    Item,
    NotModified,
    ParseError,
    Report,
    log,
)
from .net import fetch
from .parse import PARSERS
from .state import State
from .translate import build_translator

HEALTH_REFRESH = 3600


def _coarse(previous: int, now: int) -> int:
    """last_ok 这类只用于诊断的时间戳按小时刷新，避免每轮都改动 state。"""
    return now if now - previous >= HEALTH_REFRESH else previous


def collect(
    config: Config,
    state: State,
    now: int,
    *,
    deadline: float,
    preview: bool = False,
) -> Report:
    """抓取所有源。

    preview=True 时只读：不写基线、不入队、不改健康计数，用来支持 --dry-run。
    """
    report = Report()
    cutoff = now - config.window_hours * 3600
    translator = build_translator(deadline=deadline)

    for source in config.sources:
        health = state.health(source.key)

        if time.monotonic() >= deadline:
            report.skipped.append(Failure(source.name, source.key, "整轮时间预算不足"))
            if not preview:
                health.skipped += 1
            log(f"→ {source.name}（跳过：本轮时间预算不足）")
            continue
        if not preview:
            health.skipped = 0

        conditional = health.initialized
        try:
            response = fetch(
                source.url,
                etag=health.etag if conditional else "",
                last_modified=health.last_modified if conditional else "",
                headers=source.headers,
                deadline=deadline,
            )
        except NotModified:
            if not preview:
                health.fail = 0
                health.last_ok = _coarse(health.last_ok, now)
            log(f"→ {source.name}（304 未变化）")
            continue
        except BudgetExceeded as exc:
            if not preview:
                health.skipped += 1
            report.skipped.append(Failure(source.name, source.key, str(exc)))
            log(f"→ {source.name}（跳过：{exc}）")
            continue
        except (FetchError, OSError) as exc:
            if not preview:
                health.fail += 1
            report.failures.append(Failure(source.name, source.key, str(exc)))
            log(f"→ {source.name}\n⚠ 抓取失败：{exc}")
            continue

        try:
            parsed = PARSERS[source.kind](response.text, source)
        except ParseError as exc:
            if not preview:
                health.fail += 1
            report.failures.append(Failure(source.name, source.key, str(exc)))
            log(f"→ {source.name}\n⚠ 解析失败：{exc}")
            continue
        except Exception as exc:  # noqa: BLE001 - 单个源的意外不该拖垮整轮
            # 畸形字段（比如 JSON 里的 NaN）、解析器自身的 bug 都可能抛别的异常。
            # 以前它会一路冒到 main，整轮直接挂掉、所有源都白抓；
            # 现在降级成"这个源失败"，其余源照常，连续 3 轮自然走告警。
            if not preview:
                health.fail += 1
            report.failures.append(Failure(source.name, source.key, f"解析器异常：{exc!r}"))
            log(f"→ {source.name}\n⚠ 解析器异常：{exc!r}")
            continue

        if not preview:
            health.fail = 0
            health.etag = response.etag
            health.last_modified = response.last_modified
            health.last_ok = _coarse(health.last_ok, now)
            if parsed:
                health.had_items = True
                health.empty = 0
            elif health.had_items:
                # 以前有内容，现在合法但为空：可能是页面结构变了
                health.empty += 1
        if not parsed:
            log(f"→ {source.name}（合法但没有任何条目）")

        matched = parsed
        if source.match:
            matcher = re.compile(source.match, re.I)
            matched = [item for item in parsed if matcher.search(item.title)]
            log(f"   按 match 保留 {len(matched)}/{len(parsed)} 条")

        if not health.initialized and not preview:
            if not parsed:
                # 空的首次响应不建立基线：等真正有内容时再记，避免下一轮把整份历史当新条目推出去
                log(f"→ {source.name}\n   首次接入但内容为空，暂不建立基线")
                continue
            for item in parsed:
                state.remember(item, now)
            health.initialized = True
            log(f"→ {source.name}\n   首次接入，记录基线 {len(parsed)} 条（本轮不推送）")
            continue

        fresh: list[Item] = []
        for item in matched:
            if item.published and item.published < cutoff:
                continue
            if not state.is_fresh(item):
                # 只有真正记过账的条目才需要延长保留期；队列里的条目由 since 管
                if not preview and item.key in state.seen:
                    state.touch(item.key, now)
                continue
            fresh.append(item)

        # 先翻译再入队：pending 里存的就是最终要发出去的内容
        if fresh and translator:
            translated = translator.translate(fresh)
            if translated:
                log(f"   已翻译 {translated} 条")

        # 队列里还没译文的条目补一次：翻译接口上一轮挂了，这一轮恢复了
        if translator and not preview:
            stale = [
                item for item in state.pending_items(source.key)
                if not item.title_zh or (item.summary and not item.summary_zh)
            ]
            if stale:
                done = translator.translate(stale)
                for item in stale:
                    # 标题翻失败、摘要翻成功也是常见情况（标题里常有接口不认的符号），
                    # 所以只要任一字段补上了就要写回，否则下一轮会重翻、白烧配额
                    if item.title_zh or item.summary_zh:
                        state.refresh(item)
                if done:
                    log(f"   补齐待送达条目的译文 {done} 条")

        queued: list[Item] = []
        for item in fresh:
            if preview or state.queue(item, now):
                queued.append(item)

        report.items.extend(queued)
        log(f"→ {source.name}\n   共 {len(parsed)} 条，新条目 {len(queued)} 条")

    return report


def merge(items: list[Item], config: Config) -> list[Item]:
    """同一个 CVE 被不同源同时报到时合并成一条。

    只合并"来自不同源"的条目：同一个源里两条独立公告即使提到同一个 CVE
    也必须各自保留，否则会静默丢消息。
    """
    order = {source.key: index for index, source in enumerate(config.sources)}
    by_cve: dict[str, list[Item]] = {}
    merged: list[Item] = []

    for item in items:
        if len(item.cves) == 1:
            by_cve.setdefault(item.cves[0], []).append(item)
        else:
            merged.append(item)

    for group in by_cve.values():
        if len({item.source_key for item in group}) < 2:
            merged.extend(group)
            continue
        winner = min(
            group,
            key=lambda item: (not item.exploited, order.get(item.source_key, 999), -item.published),
        )
        winner.also = tuple(sorted({item.source_name for item in group if item is not winner}))
        # 只记直接对手的 key：被吸收的条目本身不可能带 merged（它从未写进 state）
        winner.merged = tuple(sorted({item.key for item in group if item is not winner}))
        merged.append(winner)

    return merged
