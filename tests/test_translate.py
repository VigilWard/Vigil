"""翻译层：Google 返回解析、拆段、失败降级与开关。"""
import io
import json
import os
import unittest
import urllib.parse
from unittest import mock

from vigil.models import Item
from vigil.translate import (
    MAX_REQUESTS,
    Translator,
    build_translator,
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
        self.assertEqual(translator.endpoint, "https://mirror.test/translate_a/single")


if __name__ == "__main__":
    unittest.main()
