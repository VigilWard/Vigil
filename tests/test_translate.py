"""翻译层：多源解析、拆段、自动降级与开关。"""
import hashlib
import io
import json
import os
import unittest
import urllib.parse
from unittest import mock

from vigil.models import Item
from vigil.translate import (
    MAX_REQUESTS,
    BaiduProvider,
    GoogleProvider,
    MyMemoryProvider,
    Translator,
    build_translator,
    parse_baidu,
    parse_mymemory,
    parse_translation,
    split_text,
)


class FakeResponse:
    def __init__(self, body: bytes):
        self._body = io.BytesIO(body)
        self.headers: dict[str, str] = {}

    def read(self, size=None):
        return self._body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def google_body(translated: str, source: str = "原文") -> bytes:
    """按 Google 的真实返回结构造响应。"""
    payload = [[[translated, source, None, None, 10]], None, "en", None, None, None, None, []]
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def responder(body: bytes):
    """每次调用都造一个新的响应对象，避免同一个 BytesIO 被读空。"""
    return lambda *args, **kwargs: FakeResponse(body)


def make_items(count):
    return [
        Item(source_key="s", source_name="源", uid=str(i), title=f"Title {i}",
             link="https://e.test", published=0, summary=f"Summary {i}")
        for i in range(count)
    ]


class TestParse(unittest.TestCase):
    def test_single_segment(self):
        raw = json.dumps([[["身份验证绕过", "Authentication Bypass", None, None, 10]],
                          None, "en"])
        self.assertEqual(parse_translation(raw), "身份验证绕过")

    def test_multiple_segments_are_joined(self):
        raw = json.dumps([[["第一段。", "First.", None, None, 10],
                           ["第二段。", "Second.", None, None, 10]], None, "en"])
        self.assertEqual(parse_translation(raw), "第一段。第二段。")

    def test_null_segments_ignored(self):
        raw = json.dumps([[["译文", "src", None, None, 10], None]])
        self.assertEqual(parse_translation(raw), "译文")

    def test_bad_structure(self):
        for raw in ('{"a":1}', "[]", '[1,2]', "not json"):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                parse_translation(raw)


class TestSplit(unittest.TestCase):
    def test_short_text_untouched(self):
        self.assertEqual(split_text("hello", 100), ["hello"])

    def test_long_text_split_by_sentence(self):
        text = " ".join(["This is a sentence."] * 50)
        chunks = split_text(text, 100)
        self.assertGreater(len(chunks), 1)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), 100)

    def test_join_keeps_content(self):
        text = " ".join(f"Sentence number {i}." for i in range(30))
        self.assertEqual(" ".join(split_text(text, 100)).split(), text.split())


class TestTranslate(unittest.TestCase):
    def setUp(self):
        # 节流会真的 sleep，测试里不需要等
        patcher = mock.patch("vigil.translate.time.sleep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_fills_fields(self):
        item = make_items(1)[0]
        with mock.patch("vigil.net.open_url", side_effect=responder(google_body("中文译文"))):
            translator = Translator()
            self.assertEqual(translator.translate([item]), 1)
        self.assertEqual(item.title_zh, "中文译文")
        self.assertEqual(item.summary_zh, "中文译文")

    def test_request_params(self):
        urls = []

        def fake(request, timeout=None):
            urls.append(request.full_url)
            return FakeResponse(google_body("译文"))

        item = make_items(1)[0]
        with mock.patch("vigil.net.open_url", fake):
            Translator().translate([item])

        query = urllib.parse.parse_qs(urllib.parse.urlsplit(urls[0]).query)
        self.assertEqual(query["client"], ["gtx"])
        self.assertEqual(query["sl"], ["en"])
        self.assertEqual(query["tl"], ["zh-CN"])
        self.assertEqual(query["dt"], ["t"])
        self.assertEqual(query["q"], [item.title])

    def test_failure_falls_back_and_stops(self):
        items = make_items(5)
        with mock.patch("vigil.net.open_url", side_effect=OSError("网络不通")):
            translator = Translator()
            self.assertEqual(translator.translate(items), 0)
        self.assertEqual(translator.failures, 2)          # 连续失败两次就放弃
        self.assertEqual(translator.requests, 2)
        self.assertEqual(items[0].title_zh, "")

    def test_partial_success_is_kept(self):
        """标题翻好了、摘要失败，标题译文要留下。"""
        item = make_items(1)[0]
        calls = {"n": 0}

        def fake(request, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return FakeResponse(google_body("中文标题"))
            raise OSError("boom")

        with mock.patch("vigil.net.open_url", fake):
            Translator().translate([item])
        self.assertEqual(item.title_zh, "中文标题")
        self.assertEqual(item.summary_zh, "")

    def test_request_cap(self):
        items = make_items(200)
        with mock.patch("vigil.net.open_url", side_effect=responder(google_body("译"))):
            translator = Translator()
            translator.translate(items)
        self.assertEqual(translator.requests, MAX_REQUESTS)

    def test_skips_already_translated(self):
        items = make_items(2)
        items[0].title_zh = "已有"
        items[0].summary_zh = "已有"
        with mock.patch("vigil.net.open_url", side_effect=responder(google_body("译"))) as opener:
            Translator().translate(items)
        self.assertEqual(opener.call_count, 2)   # 只翻第二条的标题和摘要

    def test_empty_summary_makes_one_request(self):
        item = make_items(1)[0]
        item.summary = ""
        with mock.patch("vigil.net.open_url", side_effect=responder(google_body("译"))) as opener:
            Translator().translate([item])
        self.assertEqual(opener.call_count, 1)


class TestBuild(unittest.TestCase):
    def test_enabled_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNotNone(build_translator())

    def test_disabled(self):
        with mock.patch.dict(os.environ, {"TRANSLATE": "0"}, clear=True):
            self.assertIsNone(build_translator())

    def test_custom_endpoint(self):
        env = {"TRANSLATE_ENDPOINT": "https://mirror.test/translate_a/single"}
        with mock.patch.dict(os.environ, env, clear=True):
            translator = build_translator()
        assert translator is not None
        google = next(p for p in translator.providers if p.name == "google")
        self.assertEqual(google.endpoint, "https://mirror.test/translate_a/single")


if __name__ == "__main__":
    unittest.main()


def mymemory_body(translated: str, status=200, detail="") -> str:
    return json.dumps({
        "responseData": {"translatedText": translated, "match": 0.85},
        "responseStatus": status,
        "responseDetails": detail,
    }, ensure_ascii=False)


class TestParseMyMemory(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(parse_mymemory(mymemory_body("身份验证绕过")), "身份验证绕过")

    def test_quota_exhausted_is_an_error(self):
        """配额用尽时 MyMemory 返回 HTTP 200 + responseStatus 429，不能当成成功。"""
        raw = mymemory_body("", status=429, detail="MYMEMORY WARNING: YOU USED ALL FREE TRANSLATIONS")
        with self.assertRaises(ValueError) as ctx:
            parse_mymemory(raw)
        self.assertIn("429", str(ctx.exception))

    def test_empty_translation_is_an_error(self):
        with self.assertRaises(ValueError):
            parse_mymemory(mymemory_body("   "))

    def test_bad_structure(self):
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            parse_mymemory("[]")


class TestFallback(unittest.TestCase):
    """Google 挂了要自动换 MyMemory，这是本项目的核心诉求。"""

    def _translator(self):
        return Translator([
            GoogleProvider("https://google.test/x"),
            MyMemoryProvider("https://mymemory.test/get"),
        ])

    def test_google_failure_falls_back_to_mymemory(self):
        def fake(request, timeout=None):
            if "google.test" in request.full_url:
                raise OSError("连接超时")
            return FakeResponse(mymemory_body("身份验证绕过").encode())

        item = make_items(1)[0]
        with mock.patch("vigil.net.open_url", fake), mock.patch("vigil.translate.time.sleep"):
            translator = self._translator()
            self.assertEqual(translator.translate([item]), 1)
        self.assertEqual(item.title_zh, "身份验证绕过")
        self.assertEqual(translator.requests, 4)   # 标题、摘要各试了两个源

    def test_google_is_skipped_after_two_strikes(self):
        calls = []

        def fake(request, timeout=None):
            calls.append(request.full_url)
            if "google.test" in request.full_url:
                raise OSError("连接超时")
            return FakeResponse(mymemory_body("译文").encode())

        items = make_items(3)
        with mock.patch("vigil.net.open_url", fake), mock.patch("vigil.translate.time.sleep"):
            self._translator().translate(items)
        google_calls = [url for url in calls if "google.test" in url]
        self.assertEqual(len(google_calls), 2, "连续失败两次后就该停用，不该每条都去撞")
        self.assertTrue(all(item.title_zh for item in items))

    def test_all_providers_down_keeps_original(self):
        item = make_items(1)[0]
        with mock.patch("vigil.net.open_url", side_effect=OSError("全挂")), \
                mock.patch("vigil.translate.time.sleep"):
            translator = self._translator()
            self.assertEqual(translator.translate([item]), 0)
        self.assertEqual(item.title_zh, "")
        self.assertEqual(translator.failures, 1)

    def test_mymemory_hits_the_documented_endpoint(self):
        urls = []

        def fake(request, timeout=None):
            urls.append(request.full_url)
            return FakeResponse(mymemory_body("译文").encode())

        with mock.patch("vigil.net.open_url", fake), mock.patch("vigil.translate.time.sleep"):
            self._translator().translate(make_items(1))
        mymemory_url = next(url for url in urls if "mymemory.test" in url)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(mymemory_url).query)
        self.assertEqual(query["langpair"], ["en|zh-CN"])


class TestBuildTranslator(unittest.TestCase):
    def test_chain_without_baidu(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            translator = build_translator()
        assert translator is not None
        self.assertEqual([p.name for p in translator.providers], ["google", "mymemory"])

    def test_google_has_a_shorter_timeout(self):
        """Google 经常被限流，超时必须比其它源短，否则每轮白等满 6 秒。"""
        self.assertLess(GoogleProvider("https://x").timeout,
                        MyMemoryProvider("https://y").timeout)

    def test_email_is_forwarded(self):
        with mock.patch.dict(os.environ, {"TRANSLATE_EMAIL": "me@example.com"}, clear=True):
            translator = build_translator()
        assert translator is not None
        mymemory = next(p for p in translator.providers if p.name == "mymemory")
        assert isinstance(mymemory, MyMemoryProvider)
        self.assertEqual(mymemory.email, "me@example.com")


def baidu_body(dst: str, **extra) -> str:
    payload = {"from": "en", "to": "zh", "trans_result": [{"src": "x", "dst": dst}]}
    payload.update(extra)
    return json.dumps(payload, ensure_ascii=False)


class TestParseBaidu(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(parse_baidu(baidu_body("身份验证绕过")), "身份验证绕过")

    def test_multiple_segments_are_joined(self):
        raw = json.dumps({"trans_result": [{"dst": "第一行"}, {"dst": "第二行"}]}, ensure_ascii=False)
        self.assertEqual(parse_baidu(raw), "第一行第二行")

    def test_error_code_is_an_error(self):
        """百度出错时同样返回 HTTP 200，靠 error_code 区分，必须当成失败。"""
        raw = json.dumps({"error_code": "54003", "error_msg": "Invalid Access Limit"})
        with self.assertRaises(ValueError) as ctx:
            parse_baidu(raw)
        self.assertIn("54003", str(ctx.exception))

    def test_empty_result_is_an_error(self):
        with self.assertRaises(ValueError):
            parse_baidu(json.dumps({"trans_result": []}))

    def test_bad_structure(self):
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            parse_baidu("[]")


class TestBaiduProvider(unittest.TestCase):
    def test_signature_matches_documented_formula(self):
        """sign = md5(appid + 原文 + salt + 密钥)，小写十六进制。"""
        captured = {}

        def fake(request, timeout=None):
            captured["body"] = urllib.parse.parse_qs(request.data.decode())
            captured["url"] = request.full_url
            return FakeResponse(baidu_body("身份验证绕过").encode())

        provider = BaiduProvider("https://baidu.test/x", "appid123", "secret456")
        with mock.patch("vigil.net.open_url", fake):
            self.assertEqual(provider.translate("Authentication Bypass", None), "身份验证绕过")

        body = captured["body"]
        expected = hashlib.md5(
            f"appid123{'Authentication Bypass'}{body['salt'][0]}secret456".encode()
        ).hexdigest()
        self.assertEqual(body["sign"], [expected])
        self.assertEqual(body["from"], ["en"])
        self.assertEqual(body["to"], ["zh"])

    def test_secret_never_appears_in_the_url(self):
        """密钥只参与 md5，绝不能出现在请求地址里（日志和报错都可能带 URL）。"""
        seen = []

        def fake(request, timeout=None):
            seen.append(request.full_url)
            return FakeResponse(baidu_body("译文").encode())

        with mock.patch("vigil.net.open_url", fake):
            BaiduProvider("https://baidu.test/x", "appid123", "secret456").translate("hi", None)
        self.assertNotIn("secret456", seen[0])
        self.assertNotIn("appid123", seen[0])

    def test_slowest_provider_sets_its_own_interval(self):
        """百度标准版 QPS=1，间隔必须比免费源大，否则必然撞 54003。"""
        self.assertGreater(BaiduProvider("https://x", "a", "b").min_interval,
                           GoogleProvider("https://y").min_interval)


class TestBaiduInChain(unittest.TestCase):
    def test_absent_without_credentials(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            translator = build_translator()
        assert translator is not None
        self.assertEqual([p.name for p in translator.providers], ["google", "mymemory"])

    def test_sits_between_google_and_mymemory(self):
        """顺序是 Google → 百度 → MyMemory：质量优先，百度兜底。"""
        env = {"BAIDU_APPID": "appid", "BAIDU_KEY": "key"}
        with mock.patch.dict(os.environ, env, clear=True):
            translator = build_translator()
        assert translator is not None
        self.assertEqual([p.name for p in translator.providers], ["google", "baidu", "mymemory"])

    def test_half_configured_is_ignored(self):
        with mock.patch.dict(os.environ, {"BAIDU_APPID": "appid"}, clear=True):
            translator = build_translator()
        assert translator is not None
        self.assertNotIn("baidu", [p.name for p in translator.providers])
