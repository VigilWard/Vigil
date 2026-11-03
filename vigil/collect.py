"""抓取编排：逐源抓取、过滤、入队，以及跨源合并。"""
from __future__ import annotations

import re
import time

from .models import (
    EMPTY_ALERT,
    FAIL_ALERT,
    SKIP_ALERT,
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


def _step(value: int, threshold: int) -> int:
    """连续计数加到阈值就停。

    只有"是否到阈值"有意义，继续累加会让 state 每轮都变（每 10 分钟一个
    commit），告警文案也会变成"已连续 137 轮失败"。empty 一直是这么做的，
    fail / skipped 以前漏了。
    """
    return min(value + 1, threshold)


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
                health.skipped = _step(health.skipped, SKIP_ALERT)
            log(f"→ {source.name}（跳过：本轮时间预算不足）")
            continue

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
                health.skipped = 0
                health.last_ok = _coarse(health.last_ok, now)
                # 304 表示"内容和上一轮一样"。如果上一轮就是空内容，
                # 这一轮仍然是空内容，必须继续累计，否则支持 ETag 的源
                # 永远到不了 EMPTY_ALERT 阈值。
                if 0 < health.empty < EMPTY_ALERT:
                    health.empty += 1
            log(f"→ {source.name}（304 未变化）")
            continue
        except BudgetExceeded as exc:
            if not preview:
                health.skipped = _step(health.skipped, SKIP_ALERT)
            report.skipped.append(Failure(source.name, source.key, str(exc)))
            log(f"→ {source.name}（跳过：{exc}）")
            continue
        except (FetchError, OSError) as exc:
            if not preview:
                health.fail = _step(health.fail, FAIL_ALERT)
                # 真的去抓了（只是失败了），本轮不算"没检查"
                health.skipped = 0
            report.failures.append(Failure(source.name, source.key, str(exc)))
            log(f"→ {source.name}\n⚠ 抓取失败：{exc}")
            continue

        # 走到这里说明真的拿到了响应：后续无论是解析失败还是内容为空，
        # 都算"检查过"了。清零放在这里而不是抓取之前，否则抓取中途
        # 预算耗尽（BudgetExceeded）每轮都被先清零，skipped 永远到不了阈值。
        if not preview:
            health.skipped = 0

        try:
            parsed = PARSERS[source.kind](response.text, source)
        except ParseError as exc:
            if not preview:
                health.fail = _step(health.fail, FAIL_ALERT)
            report.failures.append(Failure(source.name, source.key, str(exc)))
            log(f"→ {source.name}\n⚠ 解析失败：{exc}")
            continue
        except Exception as exc:  # noqa: BLE001 - 单个源的意外不该拖垮整轮
            # 畸形字段（比如 JSON 里的 NaN）、解析器自身的 bug 都可能抛别的异常。
            # 以前它会一路冒到 main，整轮直接挂掉、所有源都白抓；
            # 现在降级成"这个源失败"，其余源照常，连续 3 轮自然走告警。
            if not preview:
                health.fail = _step(health.fail, FAIL_ALERT)
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
            else:
                # 两种情况都计数：
                #   以前有内容 → 页面结构可能变了；
                #   从来就没有内容 → 地址或解析规则可能不对。
                # 以前只在 had_items 时计数，导致"一上来就是空"的新源
                # 既建不了基线、也永远到不了告警阈值，静默死掉。
                # 到阈值就停，避免 304 每轮把计数推到无穷大、每轮都改 state。
                health.empty = min(health.empty + 1, EMPTY_ALERT)
        if not parsed:
            log(f"→ {source.name}（合法但没有任何条目）")

        matched = parsed
        pattern = source.match.strip()
        if pattern:
            matcher = re.compile(pattern, re.I)
            matched = [item for item in parsed if matcher.search(item.title)]
            log(f"   按 match 保留 {len(matched)}/{len(parsed)} 条")

        if not health.initialized and not preview:
            if not parsed:
                # 空的首次响应不建立基线：等真正有内容时再记，避免下一轮把整份历史当新条目推出去。
                # empty 仍在累计，连续 3 轮就会走告警，不会静默死掉。
                log(f"→ {source.name}\n   首次接入但内容为空，暂不建立基线"
                    f"（已连续 {health.empty} 轮）")
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
