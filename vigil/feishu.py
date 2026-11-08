"""飞书自定义机器人推送：签名、重试、送达确认。"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import math
import time
import urllib.error
import urllib.request

from . import net
from .models import (
    MAX_RESPONSE,
    RETRY_AFTER_CAP,
    RETRY_BACKOFF,
    RETRY_MAX_WAIT,
    RETRY_STATUS,
    USER_AGENT,
    BudgetExceeded,
    FetchError,
    Message,
    PushError,
    PushTarget,
    log,
)

# 飞书在限流时返回 HTTP 200 + 业务码：9499（通用）和 11232（自定义机器人最常遇到，
# 单机器人 100 次/分钟、5 次/秒）。两者都属于可重试，不能当成永久错误。
RATE_LIMIT_CODES = frozenset({9499, 11232})
# 重试次数单独设置：推送和抓取面对的是不同服务，改推送次数不该影响抓取。
# 退避节奏仍与抓取共用 RETRY_BACKOFF / RETRY_MAX_WAIT / RETRY_STATUS。
PUSH_ATTEMPTS = 3


class _BusinessError(PushError):
    """业务错误（签名错、webhook 失效、返回了非 JSON 的错误页），重试没有意义。"""


class _RateLimited(PushError):
    """限流，值得退避重试。"""


class _Ambiguous(PushError):
    """请求已经发出，但响应没读完整：飞书可能已经把卡片投递出去了。

    自定义机器人没有幂等键，重试就是真的再发一张卡片。所以这一轮不再重试，
    消息留在待送达队列里，交给下一轮的补发流程——宁可晚一轮，也不连刷三张。
    """


def sign(secret: str, timestamp: int) -> str:
    """飞书签名：base64(HMAC-SHA256(key="timestamp\\nsecret", msg=""))。"""
    key = f"{timestamp}\n{secret}".encode()
    digest = hmac.new(key, digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def _payload(body: dict, target: PushTarget) -> bytes:
    """加上时间戳和签名，再序列化。body 里已经包含 msg_type。"""
    timestamp = int(time.time())
    payload = {"timestamp": timestamp, **body}
    if target.secret:
        payload["sign"] = sign(target.secret, timestamp)
    # errors="replace" 兜底：正常情况下 Item 层已经清掉孤立代理项；
    # 即使漏网，也不能让整轮在 encode 时 traceback。
    return json.dumps(payload, ensure_ascii=False).encode("utf-8", "replace")


def card_of(message: Message) -> dict:
    """把一条消息包成消息卡片。

    颜色只出现在三处：头部模板色、等级、勒索/在野利用标记——其余保持正文原样，
    避免给动态文本套样式带来的转义风险。
    """
    header: dict = {
        "template": message.template,
        "title": {"tag": "plain_text", "content": message.title},
    }
    if message.subtitle:
        header["subtitle"] = {"tag": "plain_text", "content": message.subtitle}
    elements = []
    if message.body:
        elements.append({"tag": "div", "text": {"tag": "lark_md", "content": message.body}})
    return {"config": {"wide_screen_mode": True}, "header": header, "elements": elements}


def _check_response(raw: bytes) -> None:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        # 200 + HTML 一般是 WAF/代理的错误页，等 1.2 秒再撞一次不会变好；
        # 归到业务错误可以省下每条 3.6 秒的无意义退避。
        raise _BusinessError("飞书返回了非 JSON 响应") from exc
    if not isinstance(data, dict):
        raise _BusinessError("飞书响应不是 JSON 对象")

    if "code" in data:
        code, message = data["code"], data.get("msg", "")
    elif "StatusCode" in data:
        # 老格式用 StatusMessage 而不是 msg，只读 msg 会让错误信息变成空字符串
        code = data["StatusCode"]
        message = data.get("StatusMessage") or data.get("msg", "")
    else:
        raise _BusinessError("飞书响应缺少 code/StatusCode，无法确认送达")

    if type(code) is not int:
        raise _BusinessError(f"飞书响应状态类型无效：{code!r}")
    if code == 0:
        return
    if code in RATE_LIMIT_CODES:
        raise _RateLimited(f"飞书限流：{message}")
    raise _BusinessError(f"飞书返回错误 {code}：{message}")


def _post_once(body: dict, target: PushTarget, deadline: float | None) -> None:
    request = urllib.request.Request(
        target.webhook,
        data=_payload(body, target),
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    response = net.open_url(request, timeout=net.request_timeout(deadline))
    try:
        try:
            raw = net.read_limited(response, MAX_RESPONSE, deadline)
        except (BudgetExceeded, FetchError):
            # 超预算 / 响应体超限：确定性失败，重试没有意义
            raise
        except (TimeoutError, OSError, http.client.HTTPException, EOFError) as exc:
            # 连接已经建立、请求已经发出，只是没读完响应：可能已送达
            raise _Ambiguous(f"请求已发出但没读到完整响应：{exc}") from exc
    finally:
        # 不用 with：__exit__ 抛错会覆盖已经读到的响应（或覆盖 _Ambiguous），
        # 让"确定成功/可能已送达"变成"可重试的连接错误"。关闭失败本身不影响
        # 送达判定，吞掉即可。
        with contextlib.suppress(OSError, http.client.HTTPException):
            response.close()
    _check_response(raw)


def _send(body: dict, target: PushTarget, deadline: float | None) -> None:
    """只有确认飞书返回 code=0 才算成功。"""
    last_error = "未知错误"
    attempts = 0
    for attempt in range(PUSH_ATTEMPTS):
        attempts += 1
        wait: float | None = None
        try:
            _post_once(body, target, deadline)
            return
        except _BusinessError:
            raise
        except _Ambiguous as exc:
            # 可能已经送达：重试只会多刷卡片，留给下一轮
            raise PushError(str(exc)) from exc
        except _RateLimited as exc:
            last_error = str(exc)
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            if exc.code not in RETRY_STATUS:
                # 不在这里拼 target.tid：调用方（_deliver / send_alerts）已经带了目标信息，
                # 两边都拼会变成"推送到 xxx 失败：推送到 xxx 失败：..."
                raise PushError(last_error) from exc
            wait = net.retry_after(exc.headers)
            if wait is not None and wait > RETRY_AFTER_CAP:
                # 与抓取侧一致：等太久就本轮放弃，别占着预算干等。
                # Retry-After: inf 也能解析成浮点数，格式化前要先判有限性。
                shown = f"{wait:.0f}s" if math.isfinite(wait) else "一个极大的时长"
                raise PushError(
                    f"飞书要求 {shown} 后重试，超过单次等待上限 {RETRY_AFTER_CAP:.0f}s"
                ) from exc
        except BudgetExceeded as exc:
            raise PushError(f"推送超过整轮时间预算：{exc}") from exc
        except FetchError as exc:
            # 响应体超过上限这类确定性失败：重试三次结果完全一样，只是白下载
            raise PushError(f"推送失败：{exc}") from exc
        except (urllib.error.URLError, TimeoutError, OSError,
                http.client.HTTPException, EOFError) as exc:
            # 连接阶段失败（请求多半没发出去），换一次连接有意义。
            # 注意 urllib 在 getresponse() 之前就已经写出请求体，"等响应头超时"
            # 也会落到这里并重试——无法与"根本没连上"区分。自定义机器人没有
            # 幂等键，这是 at-least-once 的固有代价：宁可偶尔重复一张，也不丢。
            last_error = str(getattr(exc, "reason", exc)) or exc.__class__.__name__

        if attempt + 1 >= PUSH_ATTEMPTS:
            break
        delay = wait if wait is not None else min(RETRY_BACKOFF * (2 ** attempt), RETRY_MAX_WAIT)
        try:
            left = net.budget_left(deadline)
        except BudgetExceeded:
            break
        if left is not None and delay > left:
            # 等不起就别占着预算：这一条留在队列里，下一轮补发
            break
        log(f"   推送失败（{last_error}），{delay:.1f}s 后重试")
        time.sleep(delay)

    raise PushError(f"已尝试 {attempts} 次仍失败：{last_error}")


def send(text: str, target: PushTarget, *, deadline: float | None = None) -> None:
    """发送纯文本消息（状态告警、--test 用）。"""
    _send({"msg_type": "text", "content": {"text": text}}, target, deadline)


def send_card(card: dict, target: PushTarget, *, deadline: float | None = None) -> None:
    """发送消息卡片。"""
    _send({"msg_type": "interactive", "card": card}, target, deadline)
