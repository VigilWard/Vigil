"""飞书推送：签名、响应判定、重试策略与卡片封装。"""
import json
import unittest
from unittest import mock

from tests.support import FakeResponse, http_error
from vigil import feishu
from vigil.models import MAX_CARD_BODY_BYTES, Config, Item, PushError, PushTarget, Source
from vigil.render import Message, compose

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
        body = FakeResponse(b"<html>502</html>")
        with mock.patch("vigil.net.open_url", return_value=body), \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)

    def test_missing_code(self):
        body = FakeResponse(b'{"msg":"ok"}')
        with mock.patch("vigil.net.open_url", return_value=body), \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)

    def test_string_code_rejected(self):
        body = FakeResponse(b'{"code":"0"}')
        with mock.patch("vigil.net.open_url", return_value=body), \
                self.assertRaises(PushError):
            feishu.send("hi", TARGET)

    def test_status_code_field_supported(self):
        body = FakeResponse(b'{"StatusCode":0}')
        with mock.patch("vigil.net.open_url", return_value=body):
            feishu.send("hi", TARGET)


class TestCard(unittest.TestCase):
    def test_card_structure(self):
        message = Message("🔴 Ivanti 认证绕过", "CISA KEV · 11-01 21:50 · 严重（CVSS 9.8） · 第 1/1 条",
                          "【编号】CVE-2026-1111")
        card = feishu.card_of(message, "red")

        self.assertEqual(card["header"]["template"], "red")
        self.assertEqual(card["header"]["title"]["content"], "🔴 Ivanti 认证绕过")
        self.assertIn("CISA KEV", card["header"]["subtitle"]["content"])
        self.assertEqual(card["elements"][0]["tag"], "div")
        self.assertEqual(card["elements"][0]["text"]["tag"], "lark_md")
        self.assertIn("CVE-2026-1111", card["elements"][0]["text"]["content"])

    def test_card_without_body_has_no_elements(self):
        card = feishu.card_of(Message("t", "", ""), "blue")
        self.assertEqual(card["elements"], [])
        self.assertNotIn("subtitle", card["header"])

    def test_send_card_payload(self):
        captured = {}

        def fake(request, timeout=None):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(b'{"code":0}')

        card = feishu.card_of(Message("t", "s", "b"), "orange")
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
        messages = compose(config, items, 1793000000, budget=MAX_CARD_BODY_BYTES)
        self.assertTrue(messages)
        for message in messages:
            payload = feishu._payload(
                {"msg_type": "interactive", "card": feishu.card_of(message, message.template)},
                TARGET,
            )
            self.assertLess(len(payload), 20000)


if __name__ == "__main__":
    unittest.main()
