"""飞书推送：签名、响应判定、重试策略与卡片封装。"""
import json
import unittest
from unittest import mock

from tests.support import FakeResponse, http_error
from vigil import feishu
from vigil.digest import compose
from vigil.models import (
    MAX_CARD_BODY_BYTES,
    Config,
    FetchError,
    Item,
    Message,
    PushError,
    PushTarget,
    Source,
)

TARGET = PushTarget("https://open.feishu.cn/open-apis/bot/v2/hook/xxx", "my-secret")


class TestSign(unittest.TestCase):
    def test_matches_documented_algorithm(self):
        import base64
        import hashlib
        import hmac

        timestamp = 1700000000
        expected = base64.b64encode(
            hmac.new(f"{timestamp}\nmy-secret".encode(), digestmod=hashlib.sha256).digest()
        ).decode()
        self.assertEqual(feishu.sign("my-secret", timestamp), expected)


class TestPayload(unittest.TestCase):
    def test_payload_and_signature(self):
        captured = {}

        def fake(request, timeout=None):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(b'{"code":0,"msg":"success"}')

        with mock.patch("vigil.net.open_url", fake):
            feishu.send("hello", TARGET)

        body = captured["body"]
        self.assertEqual(body["msg_type"], "text")
        self.assertEqual(body["content"]["text"], "hello")
        self.assertEqual(body["sign"], feishu.sign("my-secret", body["timestamp"]))

    def test_no_secret_means_no_sign(self):
        captured = {}

        def fake(request, timeout=None):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(b'{"code":0}')

        with mock.patch("vigil.net.open_url", fake):
            feishu.send("hi", PushTarget("https://hook.test/x", ""))

        self.assertNotIn("sign", captured["body"])


class TestResponseHandling(unittest.TestCase):
    def test_business_error_is_not_retried(self):
        body = FakeResponse(b'{"code":19021,"msg":"sign match fail"}')
        with mock.patch("vigil.net.open_url", return_value=body) as opener, \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)

    def test_rate_limit_is_retried(self):
        responses = [FakeResponse(b'{"code":9499,"msg":"too many request"}'),
                     FakeResponse(b'{"code":0}')]
        with mock.patch("vigil.net.open_url", side_effect=responses) as opener, \
                mock.patch("time.sleep"):
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 2)

    def test_server_error_is_retried(self):
        with mock.patch("vigil.net.open_url", side_effect=http_error(503)) as opener, \
                mock.patch("time.sleep"), self.assertRaises(PushError):
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, feishu.PUSH_ATTEMPTS)

    def test_client_error_is_not_retried(self):
        with mock.patch("vigil.net.open_url", side_effect=http_error(404)) as opener, \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)

    def test_recovers_on_second_attempt(self):
        side_effect = [http_error(502), FakeResponse(b'{"code":0}')]
        with mock.patch("vigil.net.open_url", side_effect=side_effect) as opener, \
                mock.patch("time.sleep"):
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 2)

    def test_non_json_response(self):
        """200 + HTML 是代理/WAF 的错误页，等 1.2 秒再撞一次不会变好。"""
        body = FakeResponse(b"<html>502</html>")
        with mock.patch("vigil.net.open_url", return_value=body) as opener, \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)

    def test_non_object_json_rejected(self):
        body = FakeResponse(b"[]")
        with mock.patch("vigil.net.open_url", return_value=body) as opener, \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)

    def test_missing_code(self):
        body = FakeResponse(b'{"msg":"ok"}')
        with mock.patch("vigil.net.open_url", return_value=body) as opener, \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)

    def test_string_code_rejected(self):
        body = FakeResponse(b'{"code":"0"}')
        with mock.patch("vigil.net.open_url", return_value=body) as opener, \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)

    def test_status_code_field_supported(self):
        body = FakeResponse(b'{"StatusCode":0}')
        with mock.patch("vigil.net.open_url", return_value=body) as opener:
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)

    def test_legacy_status_message_is_reported(self):
        """老格式用 StatusMessage；只读 msg 会让报错信息变成空的。"""
        body = FakeResponse(b'{"StatusCode":19021,"StatusMessage":"sign match fail"}')
        with mock.patch("vigil.net.open_url", return_value=body), \
                self.assertRaises(PushError) as ctx:
            feishu.send("hi", TARGET)
        self.assertIn("sign match fail", str(ctx.exception))

    def test_oversized_response_is_not_retried(self):
        """net 层的 FetchError 必须转成 PushError（否则会以"配置错误"退出码 2
        结束整轮、连累其它群），且确定性失败不重试：重试三次只是白下载三遍。"""
        with mock.patch("vigil.net.open_url", return_value=FakeResponse(b"")), \
                mock.patch("vigil.net.read_limited",
                           side_effect=FetchError("响应超过上限")) as reader, \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)
        self.assertEqual(reader.call_count, 1)

    def test_close_error_does_not_turn_success_into_retry(self):
        """响应已经读完、close 才报错：不能把它当成连接失败去重发。"""
        class CloseBoom(FakeResponse):
            def close(self):
                raise OSError("close failed")

        with mock.patch("vigil.net.open_url",
                        return_value=CloseBoom(b'{"code":0}')) as opener, \
                mock.patch("time.sleep") as sleeper:
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)
        sleeper.assert_not_called()

    def test_close_error_does_not_mask_ambiguous_result(self):
        """读响应已经超时（可能已送达）时，close 报错不能把它变回"可重试"。"""
        class Broken(FakeResponse):
            def read(self, size=None):
                raise TimeoutError("read timed out")

            def close(self):
                raise OSError("close failed")

        with mock.patch("vigil.net.open_url", return_value=Broken(b"")) as opener, \
                mock.patch("time.sleep") as sleeper, \
                self.assertRaises(PushError) as ctx:
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)
        sleeper.assert_not_called()
        self.assertIn("已发出", str(ctx.exception))

    def test_infinite_retry_after_is_reported_without_inf(self):
        """Retry-After: inf 能被 float() 解析，但格式化前必须判有限性。"""
        error = http_error(429, {"Retry-After": "inf"})
        with mock.patch("vigil.net.open_url", side_effect=error) as opener, \
                mock.patch("time.sleep") as sleeper, \
                self.assertRaises(PushError) as ctx:
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)
        sleeper.assert_not_called()
        self.assertIn("超过单次等待上限", str(ctx.exception))
        self.assertNotIn("inf", str(ctx.exception).lower())

    def test_retry_after_is_capped_without_deadline(self):
        """没有 deadline 时也要受单次等待上限约束，不能真的睡两分钟。"""
        error = http_error(429, {"Retry-After": "120"})
        waits: list[float] = []
        with mock.patch("vigil.net.open_url", side_effect=error) as opener, \
                mock.patch("time.sleep", side_effect=waits.append), \
                self.assertRaises(PushError) as ctx:
            feishu.send("hi", TARGET)
        self.assertEqual(opener.call_count, 1)
        self.assertEqual(waits, [])
        self.assertIn("超过单次等待上限", str(ctx.exception))

    def test_read_timeout_is_not_retried(self):
        """请求已发出、读响应超时：飞书可能已投递，重试只会多刷卡片。"""
        class BrokenRead(FakeResponse):
            def read(self, size=None):
                raise TimeoutError("read timed out")

        with mock.patch("vigil.net.open_url", return_value=BrokenRead(b"")), \
                mock.patch("time.sleep") as sleeper, self.assertRaises(PushError) as ctx:
            feishu.send("hi", TARGET)
        self.assertIn("已发出", str(ctx.exception))
        sleeper.assert_not_called()


class TestCard(unittest.TestCase):
    def test_card_structure(self):
        message = Message("🔴 Ivanti 认证绕过", "CISA KEV",
                          "【编号】CVE-2026-1111", template="red")
        card = feishu.card_of(message)

        self.assertEqual(card["header"]["template"], "red")
        self.assertEqual(card["header"]["title"]["content"], "🔴 Ivanti 认证绕过")
        self.assertIn("CISA KEV", card["header"]["subtitle"]["content"])
        self.assertEqual(card["elements"][0]["tag"], "div")
        self.assertEqual(card["elements"][0]["text"]["tag"], "lark_md")
        self.assertIn("CVE-2026-1111", card["elements"][0]["text"]["content"])

    def test_card_without_body_has_no_elements(self):
        card = feishu.card_of(Message("t", "", ""))
        self.assertEqual(card["elements"], [])
        self.assertNotIn("subtitle", card["header"])

    def test_send_card_payload(self):
        captured = {}

        def fake(request, timeout=None):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(b'{"code":0}')

        card = feishu.card_of(Message("t", "s", "b", template="orange"))
        with mock.patch("vigil.net.open_url", fake):
            feishu.send_card(card, TARGET)

        body = captured["body"]
        self.assertEqual(body["msg_type"], "interactive")
        self.assertEqual(body["card"]["header"]["template"], "orange")
        self.assertEqual(body["sign"], feishu.sign("my-secret", body["timestamp"]))

    def test_single_message_fits_request_limit(self):
        """飞书自定义机器人请求体上限 20KB；即使转义把正文撑大几倍也要留余量。"""
        config = Config(sources=[Source("源A", "https://a.test/1")], max_items=50)
        source = config.sources[0]
        items = [
            Item(source_key=source.key, source_name=source.name, uid=f"u{i}",
                 title="标题" * 40, link="https://example.test/" + "x" * 100,
                 published=1000 - i, summary="很长的描述" * 40,
                 cves=("CVE-2026-1111",), severity=4, cvss=9.8)
            for i in range(40)
        ]
        messages = compose(config, items, budget=MAX_CARD_BODY_BYTES)
        self.assertTrue(messages)
        for message in messages:
            payload = feishu._payload(
                {"msg_type": "interactive", "card": feishu.card_of(message)},
                TARGET,
            )
            self.assertLess(len(payload), 20000)


if __name__ == "__main__":
    unittest.main()
