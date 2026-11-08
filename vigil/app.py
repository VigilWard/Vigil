"""命令行入口与一轮运行的编排。

本模块只做三件事：解析参数、串起"抓取 → 送达 → 告警"、给出退出码。
告警判定在 alerts.py，消息编排在 digest.py，推送目标解析在 targets.py。
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path

from .alerts import apply_alerts, build_alerts, send_alerts
from .collect import collect
from .config import load_config
from .digest import compose, merge
from .feishu import card_of, send_card
from .models import (
    CONFIG_FILE,
    CST,
    FETCH_BUDGET,
    MAX_CARD_BODY_BYTES,
    MAX_MESSAGES,
    PUSH_INTERVAL,
    RUN_BUDGET,
    STATE_FILE,
    Config,
    Item,
    Message,
    PushError,
    PushTarget,
    Report,
    VigilError,
    echo,
    log,
)
from .render import render_item
from .state import State, load_state
from .targets import load_targets

# --test 发的示例消息固定用这个时间，避免同一份示例在不同时区/不同日期下变样。
_SAMPLE_PUBLISHED = int(datetime(2026, 11, 1, 9, 15, tzinfo=CST).timestamp())


def _deliver(
    config: Config,
    state: State,
    targets: list[PushTarget],
    report: Report,
    now: int,
    state_path: Path,
    deadline: float,
) -> bool:
    """把待送达队列推给每个目标；每确认一条就立即落盘。"""
    if not targets:
        if not state.pending:
            return True
        log(f"有 {len(state.pending)} 条待送达，但未配置飞书 webhook；内容不会写进公开日志。")
        return False

    target_ids = {target.tid for target in targets}
    # 删掉的目标也要把告警记账一起收尾：alert_sent 只在"已恢复"时按目标 pop，
    # 目标从配置里消失后它的记录永远 pop 不掉，health.alert 会永久粘住；
    # 而且这个目标以后加回来，会立刻收到一条它从没收到过对应告警的"已恢复正常"。
    pruned = state.prune_alerts(target_ids)
    # 目标集合可能比上一轮小了（删掉某个群）。已经满足当前集合的记录不会再被
    # 任何 target 选中，不在这里转正就只能等 7 天 TTL，白占队列。
    # 转正后必须立刻落盘：这支分支不会再发消息，也就没有别的地方会 save。
    retired = state.retire(target_ids, now)
    if retired or pruned:
        state.save(state_path)
    if retired:
        # 转正意味着"不再补发"，删错配置时这行日志是唯一的线索
        log(f"   目标集合变小：{retired} 条待送达记录已转正（不会再补发）")
    if not state.pending:
        # 没有待送达条目就不发卡片：源异常提示只在"本来就要发消息"时搭车，
        # 否则一个坏掉的源会让群里每 10 分钟收到一条空卡片。持续性故障由
        # build_alerts() 的 3 轮阈值 + 6 小时节流单独告警。
        return True

    ok = True
    for target in targets:
        items = merge(state.pending_for(target.tid), config)
        if not items:
            continue
        messages = compose(
            config, items,
            failures=report.failures,
            skipped=report.skipped,
            budget=MAX_CARD_BODY_BYTES,
            max_messages=MAX_MESSAGES,
        )
        for index, message in enumerate(messages, 1):
            try:
                send_card(card_of(message), target, deadline=deadline)
            except PushError as exc:
                log(f"⚠ 推送到 {target.tid} 失败：{exc}；未确认的消息会留在队列里")
                ok = False
                break
            state.ack(message.keys, target.tid, target_ids, now)
            state.save(state_path)
            log(f"   目标 {target.tid} 第 {index}/{len(messages)} 条已确认送达")
            if index < len(messages):
                # 飞书自定义机器人限流 5 次/秒，连续发很容易撞上 11232
                time.sleep(PUSH_INTERVAL)
    return ok


def cmd_run(config: Config, state: State, state_path: Path) -> int:
    now = int(time.time())
    start = time.monotonic()
    # 先读推送目标：webhook 配置有问题就立刻退出，不用白抓一轮再报错
    targets = load_targets()
    # 抓取单独限时，给推送和告警留出剩余预算
    report = collect(config, state, now, deadline=start + FETCH_BUDGET)
    # 配置里删掉/改了身份的源，健康记录不再有人读，顺手回收（否则永远留在 state 里）
    dropped = state.prune_sources({source.key for source in config.sources})
    if dropped:
        log(f"   清理了 {dropped} 条已删除源的记录")
    # 先落盘：即使后面进程被杀，基线和队列也不会丢
    state.save(state_path)

    deadline = start + RUN_BUDGET
    ok = _deliver(config, state, targets, report, now, state_path, deadline)

    # 没有 webhook 时用虚拟目标算一遍，保证"有告警但发不出去"仍然能把退出码变红
    alerts = build_alerts(config, state, now,
                          {target.tid for target in targets} if targets else None)
    if alerts:
        if not targets:
            log("有源状态告警，但未配置飞书 webhook。")
            ok = False
        else:
            sent_all, delivered = send_alerts(targets, alerts, deadline)
            if delivered:
                # 按目标记账：收到的那几个群不再重复收，没收到的下一轮补
                apply_alerts(state, alerts, delivered, now)
                state.save(state_path)
                log(f"源状态告警已发送（{len(alerts)} 项，{len(delivered)} 个源有目标确认）")
            if not sent_all:
                ok = False

    log(
        f"本轮结束：新条目 {len(report.items)} 条，"
        f"待送达 {len(state.pending)} 条，失败源 {len(report.failures)} 个"
    )
    return 0 if ok else 1


def _print_messages(messages: list[Message], *, header: str | None = None) -> None:
    if header:
        log(header)
    for index, message in enumerate(messages, 1):
        size = len(message.as_text().encode("utf-8", "replace"))
        log(f"--- 第 {index}/{len(messages)} 条，{size} 字节（终端里不显示颜色和加粗） ---")
        echo(message.as_text())


def cmd_dry_run(config: Config, state_path: Path) -> int:
    # load_state 本身就会在文件不存在时返回空状态，不需要再判断一次
    state = load_state(state_path)
    now = int(time.time())
    report = collect(config, state, now, deadline=time.monotonic() + FETCH_BUDGET, preview=True)

    # 下一轮真正会发的，是"这轮新抓到的"加上"队列里还没送达的"。
    # 同一个 key 如果内容变了，state.queue 会用新版本替换队列里的旧版本，
    # 所以预览时也要先剔掉旧版本，否则同一条公告会打印两遍。
    pending = state.pending_items()
    fresh_keys = {item.key for item in report.items}
    pending = [item for item in pending if item.key not in fresh_keys]

    # 还没有基线的源，第一次真实运行只会 state.remember、不会推送。
    # 必须在 merge 之前就按源拆开：真跑时新源条目根本不进队列，不会参与
    # 跨源合并。先 merge 再拆会让新生源的高危条目把老源条目"吞"进 merged，
    # 预览显示 0 条会发，而真跑其实会发那一条老源条目。
    new_keys = {source.key for source in config.sources if not state.health(source.key).initialized}
    fresh_new = [item for item in report.items if item.source_key in new_keys]
    fresh_old = [item for item in report.items if item.source_key not in new_keys]
    items = merge(fresh_old + pending, config)
    baselining = merge(fresh_new, config)

    for failure in report.failures:
        log(f"⚠ {failure.name}：{failure.detail}")
    for skipped in report.skipped:
        # 被预算跳过的源也要在预览里出现：全被跳过时 items 为空，
        # 后面会提前 return，compose 的 notes 根本走不到。
        log(f"⚠ {skipped.name}：本轮未检查（{skipped.detail}）")

    if pending:
        log(f"注：队列里还有 {len(pending)} 条上一轮没送达的，会一起发。")

    # 用和线上一致的卡片预算与消息上限渲染，否则这里显示的条数和实际发出去的对不上
    messages = compose(config, items, failures=report.failures,
                       skipped=report.skipped, markup=False, budget=MAX_CARD_BODY_BYTES,
                       max_messages=MAX_MESSAGES)
    _print_messages(messages)

    if baselining:
        # 这些条目首轮只会被 remember，不存在"顺延"：截断提示必须关掉。
        # 数量可能被每源 limit 截断，所以头部同时说明总数与展示条数。
        preview = compose(config, baselining, markup=False,
                          budget=MAX_CARD_BODY_BYTES, max_messages=MAX_MESSAGES,
                          show_overflow=False)
        shown = (f"（下面展示其中最要紧的 {len(preview)} 条）"
                 if len(preview) < len(baselining) else "")
        _print_messages(preview, header=(
            f"--- 以下来自尚未建基线的源：本轮共 {len(baselining)} 条{shown}，"
            "首次真实运行只建基线、不会推送 ---"
        ))

    if not messages and not baselining:
        log("dry-run：没有需要推送的新条目（已送达过的、或源没有变化）。")
        return 0

    extra = f"；另有 {len(baselining)} 条来自首次接入的源，只建基线" if baselining else ""
    # 全是"只建基线"的条目时没有可顺延的东西，别把通用说明挂在一句空话后面
    tail = "（超出每源 limit / 单轮上限的部分顺延）" if messages else ""
    log(f"dry-run：候选 {len(items)} 条，本轮会发 {len(messages)} 条消息{tail}{extra}"
        "。未发送、未改动基线。")
    return 0


def sample_message() -> Message:
    """--test 发的示例卡片；预览工具也复用它，保证演示和线上一致。

    正文走 render_item 而不是手写字符串：以后增删字段时示例会自动跟上，
    不会出现"测试卡片和真实消息长得不一样"这种验证不到位的假象。
    """
    item = Item(
        source_key="vigil-sample",
        source_name="Vigil 测试源",
        uid="CVE-2026-00000",
        title="This is a style test message",
        title_zh="这是一条样式测试消息",
        link="https://open.feishu.cn/",
        published=_SAMPLE_PUBLISHED,
        summary="If you can read this, the whole delivery chain works.",
        summary_zh="收到这张卡片，说明推送链路整条都是通的；正式消息的排版与这里一致。",
        cves=("CVE-2026-00000",),
        exploited=True,
        ransomware=True,
        severity=4,
        cvss=9.8,
    )
    return Message("🔴 Vigil 测试消息", "Vigil 测试源", render_item(item), template="carmine")


def cmd_test() -> int:
    targets = load_targets()
    if not targets:
        log("未配置 FEISHU_WEBHOOK / FEISHU_WEBHOOKS。")
        return 1
    # 发一张真实的卡片：既验证 webhook 和签名，也验证卡片渲染
    card = card_of(sample_message())
    deadline = time.monotonic() + RUN_BUDGET
    failed = False
    for target in targets:
        try:
            send_card(card, target, deadline=deadline)
        except PushError as exc:
            log(f"发送到 {target.tid} 失败：{exc}")
            failed = True
        else:
            log(f"测试卡片已确认送达：{target.tid}")
    return 1 if failed else 0


def cmd_reset(state_path: Path) -> int:
    State().save(state_path)
    log("基线、健康状态和待送达队列已清空；下一轮会逐源重建基线，不会补推历史条目。")
    return 0


def main(argv: list[str] | None = None) -> int:
    local_config = CONFIG_FILE.with_name("config.local.json")
    default_config = local_config if local_config.exists() else CONFIG_FILE

    parser = argparse.ArgumentParser(
        prog="watch.py",
        description="安全公告增量抓取并推送到飞书",
    )
    parser.add_argument("--config", default=str(default_config), help="配置文件路径")
    parser.add_argument("--state", default=str(STATE_FILE), help="状态文件路径")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--test", action="store_true", help="只发一条测试消息")
    modes.add_argument("--dry-run", action="store_true",
                       help="只打印将要推送的内容：不发飞书、不改基线（开着翻译时仍会请求翻译接口）")
    modes.add_argument("--reset", action="store_true", help="清空基线与待送达队列")
    args = parser.parse_args(argv)
    state_path = Path(args.state)

    try:
        if args.test:
            return cmd_test()
        if args.reset:
            return cmd_reset(state_path)
        config = load_config(args.config)
        if args.dry_run:
            return cmd_dry_run(config, state_path)
        return cmd_run(config, load_state(state_path), state_path)
    except (VigilError, OSError, UnicodeError) as exc:
        log(f"错误：{exc}")
        return 2
