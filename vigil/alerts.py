"""源健康告警：什么时候发、发给谁、怎么分块，以及按目标记账。

与"新条目推送"分开：条目走卡片、按条确认；这里走纯文本、按目标记账。
两者的失败语义一样——没送到的目标下一轮补，但互不影响。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .feishu import send
from .models import (
    ALERT_REPEAT,
    ALERT_SWITCH_GAP,
    EMPTY_ALERT,
    FAIL_ALERT,
    MAX_TEXT_BYTES,
    SKIP_ALERT,
    Config,
    PushError,
    PushTarget,
    log,
    shorten_bytes,
)
from .state import State


@dataclass(slots=True)
class Alert:
    kind: str
    key: str
    text: str
    # 这一条该发给哪些目标。多群时不同群的送达进度不一样，不能一把梭发给所有人。
    targets: set[str] = field(default_factory=set)


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
            # 必须要求本轮真的检查成功且解析出内容：只判 empty 会漏掉两种假恢复——
            #   1) 上一轮恢复通知发送失败，alert_sent 还留着上一个故障类型，
            #      这一轮源又失败了一次（fail=1 < 阈值），却照样发"已恢复正常"；
            #   2) 这一轮源被时间预算跳过（skipped=1），根本没检查。
            # 两者都会让群里收到与事实相反的消息，并且清掉记账、掩盖持续故障。
            stale = {tid for tid, sent in health.alert_sent.items() if sent}
            if health.fail == 0 and health.skipped == 0 and health.empty == 0 and stale & targets:
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
            text = f"⚠ {source.name} 已连续 {health.fail} 轮以上抓取/解析失败，请检查源地址或页面结构。"
        elif kind == "skip":
            text = f"⚠ {source.name} 已连续 {health.skipped} 轮以上因时间预算不足未检查，源可能太慢。"
        elif health.had_items:
            text = f"⚠ {source.name} 已有内容，但已连续 {health.empty} 轮以上返回空内容，页面结构可能已变化。"
        else:
            # 新接入的源一次都没解析出条目：多半是地址写错、或者 match 之外的原因。
            # 以前这种情况既不计 empty 也不告警，源会永远静默。
            text = (f"⚠ {source.name} 接入后连续 {health.empty} 轮以上没有解析出任何条目，"
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
            separator = 0        # 新块的第一条前面没有换行，不能再算 1 字节
        if length > budget:
            # 正常不会走到这里（源名有长度上限），但保留兜底。
            text = shorten_bytes(text, budget)
            length = len(text.encode("utf-8", "replace"))
            log("⚠ 单条状态告警超过纯文本预算，已截断")
        chunk.append((alert, text))
        size += separator + length
    if chunk:
        yield chunk


def send_alerts(
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
