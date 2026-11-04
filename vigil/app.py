"""命令行入口与一轮运行的编排。"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from .collect import collect, merge
from .config import load_config
from .feishu import card_of, send, send_card
from .models import (
    ALERT_REPEAT,
    ALERT_SWITCH_GAP,
    CONFIG_FILE,
    EMPTY_ALERT,
    FAIL_ALERT,
    FETCH_BUDGET,
    MAX_CARD_BODY_BYTES,
    MAX_MESSAGES,
    MAX_TEXT_BYTES,
    PUSH_INTERVAL,
    RUN_BUDGET,
    SKIP_ALERT,
    STATE_FILE,
    Config,
    ConfigError,
    PushError,
    PushTarget,
    Report,
    VigilError,
    echo,
    log,
)
from .render import Message, compose, shorten_bytes
from .state import State, load_state


@dataclass(slots=True)
class Alert:
    kind: str
    key: str
    text: str
    # 这一条该发给哪些目标。多群时不同群的送达进度不一样，不能一把梭发给所有人。
    targets: set[str] = field(default_factory=set)


FEISHU_HOST_SUFFIXES = (".feishu.cn", ".larksuite.com")


def _is_feishu_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host in ("feishu.cn", "larksuite.com") or host.endswith(FEISHU_HOST_SUFFIXES)


def load_targets() -> list[PushTarget]:
    """读取推送目标。

    FEISHU_WEBHOOKS 支持 JSON 数组或逗号/换行分隔的多条 webhook；
    FEISHU_WEBHOOK 是单目标的兼容写法。
    """
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


def build_alerts(
    config: Config,
    state: State,
    now: int,
    target_ids: set[str] | None = None,
) -> list[Alert]:
    """根据健康状态决定这一轮要发哪些告警、分别发给谁。

    target_ids=None 表示"不针对具体目标"（预览脚本用），此时按一个虚拟目标算，
    保证预览里能看到告警长什么样。
    """
    targets = {"*"} if target_ids is None else set(target_ids)
    alerts: list[Alert] = []
    for source in config.sources:
        health = state.sources.get(source.key)
        if health is None:
            continue

        kind = ""
        if health.fail >= FAIL_ALERT:
            kind = "fail"
        elif health.skipped >= SKIP_ALERT:
            kind = "skip"
        elif health.empty >= EMPTY_ALERT:
            kind = "empty"

        if not kind:
            # 恢复通知只发给"确实收到过告警"的那些目标。
            # 必须要求 empty == 0：fail 之后只要来一轮"200 + 0 条"，
            # fail 就清零、empty 才 1，此时源其实还不健康，发"已恢复正常"
            # 会立刻被 3 轮后的"返回空内容"打脸。
            stale = {tid for tid, sent in health.alert_sent.items() if sent}
            if health.empty == 0 and stale & targets:
                alerts.append(Alert("recovered", source.key,
                                    f"✅ {source.name} 已恢复正常。", stale & targets))
            continue

        # 换了故障类型通常立刻发（empty → fail 是升级）；同一种故障按
        # ALERT_REPEAT 节流；另外只要还有目标没收到过这一条，也要补发（多群场景）。
        # 但"类型一变就发"会被反复横跳的源利用来绕过 6 小时节流，所以类型
        # 切换本身也受 ALERT_SWITCH_GAP 约束。health.alert 为空表示当前目标
        # 都没收到过（新源、或记账刚被 prune_alerts 清掉），这种情况立刻发。
        # "返回空内容"是稳态，只提醒一次，等恢复时再通知。
        repeatable = kind in ("fail", "skip")
        if health.alert != kind:
            if health.alert and now - health.alert_at < ALERT_SWITCH_GAP:
                continue
            need = set(targets)
        else:
            need = {tid for tid in targets if health.alert_sent.get(tid) != kind}
            if not need and repeatable and now - health.alert_at >= ALERT_REPEAT:
                need = set(targets)
        if not need:
            continue

        if kind == "fail":
            text = f"⚠ {source.name} 已连续 {health.fail} 轮抓取/解析失败，请检查源地址或页面结构。"
        elif kind == "skip":
            text = f"⚠ {source.name} 已连续 {health.skipped} 轮因时间预算不足未检查，源可能太慢。"
        elif health.had_items:
            text = f"⚠ {source.name} 已有内容，但已连续 {health.empty} 轮返回空内容，页面结构可能已变化。"
        else:
            # 新接入的源一次都没解析出条目：多半是地址写错、或者 match 之外的原因。
            # 以前这种情况既不计 empty 也不告警，源会永远静默。
            text = (f"⚠ {source.name} 接入后连续 {health.empty} 轮没有解析出任何条目，"
                    "请检查源地址与解析规则。")
        alerts.append(Alert(kind, source.key, text, need))
    return alerts


def apply_alerts(state: State, alerts: list[Alert], delivered: dict[str, set[str]], now: int) -> None:
    """按"实际送达的目标"记账，没送到的目标下一轮继续补。"""
    for alert in alerts:
        got = delivered.get(alert.key, set())
        if not got:
            continue
        health = state.health(alert.key)
        if alert.kind == "recovered":
            for tid in got:
                health.alert_sent.pop(tid, None)
            if not health.alert_sent:
                health.alert = ""
                health.alert_at = 0
        else:
            for tid in got:
                health.alert_sent[tid] = alert.kind
            health.alert = alert.kind
            health.alert_at = now


def _alert_chunks(alerts: list[Alert], budget: int):
    """按字节预算切分告警，保证每条告警都能完整进入某个 chunk。"""
    chunk: list[tuple[Alert, str]] = []
    size = 0
    for alert in alerts:
        text = alert.text
        length = len(text.encode("utf-8", "replace"))
        separator = 1 if chunk else 0
        if chunk and size + separator + length > budget:
            yield chunk
            chunk = []
            size = 0
            separator = 0
        if length > budget:
            # 正常不会走到这里（源名有长度上限），但保留兜底。
            text = shorten_bytes(text, budget)
            length = len(text.encode("utf-8", "replace"))
            log("⚠ 单条状态告警超过纯文本预算，已截断")
        chunk.append((alert, text))
        size += separator + length
    if chunk:
        yield chunk


def _send_alerts(
    targets: list[PushTarget],
    alerts: list[Alert],
    deadline: float,
) -> tuple[bool, dict[str, set[str]]]:
    """按目标、按预算分块发送。返回 (是否全部成功, {源 key: 已收到的目标集合})。"""
    delivered: dict[str, set[str]] = {}
    ok = True
    for target in targets:
        mine = [alert for alert in alerts if target.tid in alert.targets]
        if not mine:
            continue
        for chunk in _alert_chunks(mine, MAX_TEXT_BYTES):
            text = "\n".join(part for _, part in chunk)
            try:
                send(text, target, deadline=deadline)
            except PushError as exc:
                log(f"⚠ 状态告警发送到 {target.tid} 失败：{exc}")
                ok = False
                break
            for alert, _ in chunk:
                delivered.setdefault(alert.key, set()).add(target.tid)
    return ok, delivered


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
            config, items, now,
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


def cmd_run(config: Config, state: State, state_path) -> int:
    now = int(time.time())
    start = time.monotonic()
    # 先读推送目标：webhook 配置有问题就立刻退出，不用白抓一轮再报错
    targets = load_targets()
    # 抓取单独限时，给推送和告警留出剩余预算
    report = collect(config, state, now, deadline=start + FETCH_BUDGET)
    # 先落盘：即使后面进程被杀，基线和队列也不会丢
    state.save(state_path)

    deadline = start + RUN_BUDGET
    ok = _deliver(config, state, targets, report, now, Path(state_path), deadline)

    # 没有 webhook 时用虚拟目标算一遍，保证"有告警但发不出去"仍然能把退出码变红
    alerts = build_alerts(config, state, now,
                          {target.tid for target in targets} if targets else None)
    if alerts:
        if not targets:
            log("有源状态告警，但未配置飞书 webhook。")
            ok = False
        else:
            sent_all, delivered = _send_alerts(targets, alerts, deadline)
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


def cmd_dry_run(config: Config, state_path) -> int:
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
    items = merge(report.items + pending, config)

    for failure in report.failures:
        log(f"⚠ {failure.name}：{failure.detail}")

    new_keys = {source.key for source in config.sources
                if not state.health(source.key).initialized}
    if new_keys:
        names = [source.name for source in config.sources if source.key in new_keys]
        # 用 merge 之前的集合统计：跨源合并会把新源条目并进老源的 winner
        count = sum(1 for item in report.items if item.source_key in new_keys)
        log(f"注：{'、'.join(names)} 还没有基线；本轮它们产出 {count} 条，"
            "首次真实运行只建基线、不会推送。")
    if pending:
        log(f"注：队列里还有 {len(pending)} 条上一轮没送达的，会一起发。")

    if not items:
        log("dry-run：没有需要推送的新条目（已送达过的、或源没有变化）。")
        return 0

    # 用和线上一致的卡片预算与消息上限渲染，否则这里显示的条数和实际发出去的对不上
    messages = compose(config, items, now, failures=report.failures,
                       skipped=report.skipped, markup=False, budget=MAX_CARD_BODY_BYTES,
                       max_messages=MAX_MESSAGES)
    for index, message in enumerate(messages, 1):
        size = len(message.as_text().encode("utf-8", "replace"))
        log(f"--- 第 {index}/{len(messages)} 条，{size} 字节（终端里不显示颜色和加粗） ---")
        echo(message.as_text())
    log(f"dry-run：候选 {len(items)} 条，本轮会发 {len(messages)} 条消息"
        f"（超出每源 limit / 单轮上限的部分顺延）。未发送、未改动基线。")
    return 0


def sample_message() -> Message:
    """--test 发的示例卡片；预览工具也复用它，保证演示和线上一致。"""
    return Message(
        "🔴 Vigil 测试消息",
        "webhook、签名与卡片渲染正常 · 严重（CVSS 9.8） · 第 1/1 条",
        "【来源】Vigil 测试源\n"
        "【编号】CVE-2026-00000\n"
        "【发布时间】2026-11-01 09:15\n"
        "【标题翻译】**这是一条样式测试消息**\n"
        "【标题原文】This is a style test message\n"
        "【等级】<font color='red'>严重（CVSS 9.8）</font>\n"
        "【标记】<font color='red'>已确认在野利用、已知勒索团伙利用</font>\n"
        "【摘要翻译】收到这张卡片，说明推送链路整条都是通的；正式消息的排版与这里一致。\n"
        "【摘要原文】If you can read this, the whole delivery chain works.\n"
        "【链接】https://open.feishu.cn/",
        template="carmine",
    )


def cmd_test() -> int:
    targets = load_targets()
    if not targets:
        log("未配置 FEISHU_WEBHOOK / FEISHU_WEBHOOKS。")
        return 1
    # 发一张真实的卡片：既验证 webhook 和签名，也验证卡片渲染
    message = sample_message()
    card = card_of(message)
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


def cmd_reset(state_path) -> int:
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
    modes.add_argument("--dry-run", action="store_true", help="只打印将要推送的内容，不发送、不改基线")
    modes.add_argument("--reset", action="store_true", help="清空基线与待送达队列")
    args = parser.parse_args(argv)

    try:
        if args.test:
            return cmd_test()
        if args.reset:
            return cmd_reset(args.state)
        config = load_config(args.config)
        if args.dry_run:
            return cmd_dry_run(config, args.state)
        return cmd_run(config, load_state(args.state), args.state)
    except (VigilError, OSError, UnicodeError) as exc:
        log(f"错误：{exc}")
        return 2
