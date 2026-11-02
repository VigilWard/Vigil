"""按缺陷归档的回归测试。

这些用例覆盖曾经真实踩到的坑：每个类的 docstring 写清"为什么"，避免以后被改回去。
与模块级测试（test_net / test_parse / test_state ...）的分工是：模块测试覆盖正常行为，
这里覆盖出过问题的边界（编码损坏、预算耗尽、多群记账、截断响应等）。
"""
import gzip
import io
import json
import os
import time
import unittest
import urllib.error
import urllib.request
import zlib
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import watch
from tests.support import FakeResponse, http_error
from vigil import feishu, net
from vigil.app import _send_alerts, build_alerts, load_targets
from vigil.collect import collect, merge
from vigil.config import load_config
from vigil.models import (
    EMPTY_ALERT,
    FAIL_ALERT,
    MAX_CLEAN_CHARS,
    MAX_INFLATE,
    MAX_NAME_CHARS,
    MAX_SEEN,
    MAX_TEXT_BYTES,
    PENDING_TTL,
    Config,
    ConfigError,
    Failure,
    FetchError,
    Item,
    NotModified,
    ParseError,
    PushError,
    PushTarget,
    Source,
    StateError,
)
from vigil.net import Response
from vigil.parse import clean, cvss_of, parse_json, parse_nginx, parse_rss, parse_time, severity_of
from vigil.render import compose, paginate, render_item, sanitize_link
from vigil.state import STATE_VERSION, State, load_state
from vigil.translate import Provider, Translator

# 固定时间戳，避免用例依赖真实时钟
NOW = 1793000000


def make_item(uid="1", *, title="标题", summary="", source_key="s", published=1000):
    return Item(source_key=source_key, source_name="源", uid=uid, title=title,
                link="https://e.test/1", published=published, summary=summary)


class TestFeishuRateLimit(unittest.TestCase):
    def test_11232_is_treated_as_rate_limit(self):
        """11232 是自定义机器人最常见的限流码，之前被当成永久错误，一次都不重试。"""
        responses = [FakeResponse(b'{"code":11232,"msg":"frequency limited"}'),
                     FakeResponse(b'{"code":0}')]
        with mock.patch("vigil.net.open_url", side_effect=responses) as opener, \
                mock.patch("time.sleep"):
            feishu.send("hi", PushTarget("https://open.feishu.cn/hook/x", ""))
        self.assertEqual(opener.call_count, 2)

    def test_11232_keeps_retrying_until_attempts_exhausted(self):
        body = FakeResponse(b'{"code":11232,"msg":"frequency limited"}')
        with mock.patch("vigil.net.open_url", return_value=body) as opener, \
                mock.patch("time.sleep"), self.assertRaises(PushError):
            feishu.send("hi", PushTarget("https://open.feishu.cn/hook/x", ""))
        self.assertEqual(opener.call_count, feishu.PUSH_ATTEMPTS)

    def test_signature_error_is_still_not_retried(self):
        body = FakeResponse(b'{"code":19021,"msg":"sign match fail"}')
        with mock.patch("vigil.net.open_url", return_value=body) as opener, \
                self.assertRaises(PushError):
            feishu.send("hi", PushTarget("https://open.feishu.cn/hook/x", ""))
        self.assertEqual(opener.call_count, 1)


class TestHeaderSafety(unittest.TestCase):
    def test_config_rejects_newline_in_header(self):
        """Secret 粘贴时带尾随换行会让 http.client 抛 ValueError，整轮崩掉。

        尾随换行由 strip 兜掉；夹在中间的换行（更危险，等于头注入）必须报错。
        """
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({
                "sources": [{"name": "a", "url": "https://a.test/1",
                             "headers": {"Authorization": "Bearer abc\ndef"}}]
            }), encoding="utf-8")
            with self.assertRaises(ConfigError) as ctx:
                load_config(path)
        self.assertIn("换行", str(ctx.exception))

    def test_config_tolerates_trailing_newline(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({
                "sources": [{"name": "a", "url": "https://a.test/1",
                             "headers": {"Authorization": "Bearer abc\n"}}]
            }), encoding="utf-8")
            self.assertEqual(load_config(path).sources[0].headers["Authorization"], "Bearer abc")

    def test_config_rejects_bad_header_name(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({
                "sources": [{"name": "a", "url": "https://a.test/1",
                             "headers": {"Bad Name": "v"}}]
            }), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_config_strips_header_value(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({
                "sources": [{"name": "a", "url": "https://a.test/1",
                             "headers": {"Authorization": "  Bearer abc  "}}]
            }), encoding="utf-8")
            self.assertEqual(load_config(path).sources[0].headers["Authorization"], "Bearer abc")

    def test_fetch_turns_bad_header_into_fetch_error(self):
        """即使绕过了配置校验，也必须是"这个源失败"，而不是整轮崩。"""
        with self.assertRaises(FetchError):
            net.fetch("https://a.test/x", headers={"X-Token": "a\nb"}, timeout=0.1)


class TestRetryAfter(unittest.TestCase):
    def test_retry_after_over_cap_is_refused(self):
        """源站要求等 60s，超过单次等待上限 30s：本轮放弃。

        这里报的是「超过上限」，不是「预算不够」——以前把 cap 当成剩余预算，
        哪怕本轮还有 5 分钟也会谎称预算耗尽。
        """
        error = http_error(429, {"Retry-After": "60"})
        with mock.patch("vigil.net.open_url", side_effect=error) as opener, \
                self.assertRaises(FetchError) as ctx:
            net.fetch("https://a.test/x", deadline=time.monotonic() + 120)
        self.assertEqual(opener.call_count, 1)
        self.assertIn("上限", str(ctx.exception))

    def test_retry_after_over_remaining_budget_is_refused(self):
        """Retry-After 在上限内，但本轮只剩 5s：如实说清剩多少，而不是提前重试。"""
        error = http_error(429, {"Retry-After": "10"})
        with mock.patch("vigil.net.open_url", side_effect=error) as opener, \
                self.assertRaises(FetchError) as ctx:
            net.fetch("https://a.test/x", deadline=time.monotonic() + 5)
        self.assertEqual(opener.call_count, 1)
        self.assertIn("只剩", str(ctx.exception))

    def test_retry_after_within_budget_is_honoured(self):
        waits: list[float] = []
        error = http_error(429, {"Retry-After": "3"})
        with mock.patch("vigil.net.open_url", side_effect=error), \
                mock.patch("time.sleep", side_effect=waits.append), \
                self.assertRaises(FetchError):
            net.fetch("https://a.test/x", deadline=time.monotonic() + 60)
        self.assertEqual(waits, [3.0, 3.0])


class TestDecompression(unittest.TestCase):
    def test_deflate_bomb_is_rejected(self):
        """deflate 分支原来直接 zlib.decompress，没有任何上限。"""
        raw = zlib.compress(b"\0" * (MAX_INFLATE + 1024), 9)
        with self.assertRaises(FetchError) as ctx:
            net._decompress(raw, "deflate", None)
        self.assertIn("上限", str(ctx.exception))

    def test_deflate_roundtrip(self):
        raw = zlib.compress("中文内容".encode(), 9)
        self.assertEqual(net._decompress(raw, "deflate", None).decode("utf-8"), "中文内容")

    def test_gzip_roundtrip(self):
        raw = gzip.compress("中文内容".encode())
        self.assertEqual(net._decompress(raw, "gzip", None).decode("utf-8"), "中文内容")


class TestXmlEntity(unittest.TestCase):
    BOMB = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<rss version="2.0"><channel><item><title>&lol2;</title><guid>1</guid></item></channel></rss>"""

    def test_custom_entity_is_rejected(self):
        with self.assertRaises(ParseError) as ctx:
            parse_rss(self.BOMB, Source("x", "https://a.test/1"))
        self.assertIn("实体", str(ctx.exception))

    def test_plain_doctype_still_allowed(self):
        payload = ('<?xml version="1.0"?><!DOCTYPE rss PUBLIC "-//Netscape Communications//DTD RSS 0.91//EN" '
                   '"http://my.netscape.com/publish/formats/rss-0.91.dtd">'
                   "<rss version=\"0.91\"><channel><item><title>旧源</title><guid>1</guid></item>"
                   "</channel></rss>")
        self.assertEqual(len(parse_rss(payload, Source("x", "https://a.test/1"))), 1)


class TestParseTime(unittest.TestCase):
    def test_eight_digit_date_is_not_epoch(self):
        """20261031 曾经被当成 Unix 时间戳，算成 1970-08-23。"""
        expected = int(datetime(2026, 10, 31, tzinfo=timezone.utc).timestamp())
        self.assertEqual(parse_time("20261031"), expected)

    def test_epoch_strings_still_work(self):
        self.assertEqual(parse_time("1793318400"), 1793318400)


NGINX_HTML = (
    "<ul><li><p>Buffer overflow in the mp4 module<br>Severity: medium<br>"
    '<a href="https://my.f5.com/manage/s/article/K0001">Advisory</a><br>'
    '<a href="https://www.cve.org/CVERecord?id=CVE-2026-15176">CVE-2026-15176</a><br>'
    "Not vulnerable: 1.31.7+<br>Vulnerable: 0.1.29-1.31.6</p></li></ul>"
)
NGINX_SOURCE = Source("NGINX", "https://nginx.org/x", kind="nginx")


class TestNginxLink(unittest.TestCase):
    def test_keeps_vendor_advisory_link(self):
        self.assertEqual(parse_nginx(NGINX_HTML, NGINX_SOURCE)[0].link,
                         "https://my.f5.com/manage/s/article/K0001")

    def test_summary_drops_noise_but_keeps_details(self):
        item = parse_nginx(NGINX_HTML, NGINX_SOURCE)[0]
        self.assertNotIn("Advisory", item.summary)
        self.assertNotIn("CVE-2026-15176", item.summary)
        self.assertIn("Vulnerable: 0.1.29-1.31.6", item.summary)


class TestPendingDedup(unittest.TestCase):
    def test_pending_item_is_not_fresh(self):
        """待送达条目不算新条目，否则推送失败期间每轮都会重复翻译一遍。"""
        state = State()
        item = make_item()
        state.queue(item, 100)
        self.assertFalse(state.is_fresh(item))

    def test_changed_content_is_fresh_even_if_pending(self):
        state = State()
        state.queue(make_item(title="旧"), 100)
        self.assertTrue(state.is_fresh(make_item(title="新")))

    def test_queue_is_idempotent_for_same_fingerprint(self):
        state = State()
        item = make_item()
        self.assertTrue(state.queue(item, 100))
        self.assertFalse(state.queue(item, 200))
        self.assertEqual(state.pending[item.key].since, 100)

    def test_refresh_writes_back_translation(self):
        state = State()
        item = make_item()
        state.queue(item, 100)

        refreshed = make_item()
        refreshed.title_zh = "中文标题"
        state.refresh(refreshed)
        self.assertEqual(state.pending[item.key].item["title_zh"], "中文标题")

    def test_refresh_ignores_unknown_key(self):
        state = State()
        state.refresh(make_item())
        self.assertEqual(state.pending, {})

    def test_ack_without_targets_does_nothing(self):
        state = State()
        item = make_item()
        state.queue(item, 100)
        state.ack([item.key], "a", set(), 100)
        self.assertIn(item.key, state.pending)
        self.assertEqual(state.seen, {})


class TestSeenCap(unittest.TestCase):
    def test_seen_is_pruned_to_hard_limit(self):
        """裁剪时跳过 pending 后没有补偿，实测 20005 条只删 0 条。"""
        state = State()
        now = int(time.time())
        for index in range(MAX_SEEN + 5):
            state.seen[f"k:{index}"] = "fp"
            state.seen_at[f"k:{index}"] = now - 100
        dropped, _ = state.prune(now)
        self.assertLessEqual(len(state.seen), MAX_SEEN)
        self.assertEqual(dropped, 5)


class TestPaginateCounting(unittest.TestCase):
    def test_header_block_is_not_counted_as_item(self):
        """分组标题溢出时不能算成"另有 1 条"。"""
        blocks = [("x" * 200, ["k1"]), ("【在野利用】", []), ("源B（1条）", [])]
        pages, overflow = paginate(blocks, budget=300, max_pages=1)
        self.assertEqual(len(pages), 1)
        self.assertEqual(overflow, 0)

    def test_item_blocks_are_counted(self):
        blocks = [("x" * 200, ["k1"]), ("y" * 200, ["k2"]), ("z" * 200, ["k3"])]
        pages, overflow = paginate(blocks, budget=300, max_pages=1)
        self.assertEqual(len(pages), 1)
        self.assertEqual(overflow, 2)
        self.assertEqual(pages[0][1], ["k1"])

    def test_zero_pages_counts_items_only(self):
        pages, overflow = paginate([("x", ["1"]), ("【标题】", [])], budget=500, max_pages=0)
        self.assertEqual(pages, [])
        self.assertEqual(overflow, 1)


class TestPageTemplate(unittest.TestCase):
    def setUp(self):
        self.config = Config(sources=[Source("源A", "https://a.test/1")], max_items=50)

    def _items(self, count):
        source = self.config.sources[0]
        items = [Item(source_key=source.key, source_name=source.name, uid="hot",
                      title="在野利用条目", link="https://e.test/hot", published=2000,
                      summary="描述" * 60, exploited=True, severity=4)]
        for index in range(count):
            items.append(Item(source_key=source.key, source_name=source.name, uid=f"u{index}",
                              title=f"普通条目 {index}", link=f"https://e.test/{index}",
                              published=1000 - index, summary="描述" * 60))
        return items

    def test_template_follows_each_page(self):
        pages = compose(self.config, self._items(20), 1793000000, budget=900)
        self.assertGreater(len(pages), 1)
        self.assertEqual(pages[0].template, "red")
        for page in pages[1:]:
            self.assertEqual(page.template, "blue")


class TestEscapedPayloadSize(unittest.TestCase):
    def test_heavy_escaping_still_fits_feishu_limit(self):
        """实体转义会让正文膨胀几倍，必须确认满页请求体仍在 20KB 以内。"""
        config = Config(sources=[Source("A", "https://a.test/1")], max_items=50)
        source = config.sources[0]
        items = [Item(source_key=source.key, source_name=source.name, uid=f"u{i}",
                      title="*_[]()#+`$!\\" * 12, link="https://e.test/" + "x" * 200,
                      published=1000 - i, summary="*_[]()#+`$!\\ " * 20,
                      cves=("CVE-2026-1111",), severity=4, cvss=9.8)
                 for i in range(30)]
        pages = compose(config, items, 1793000000)
        self.assertTrue(pages)
        for page in pages:
            payload = feishu._payload(
                {"msg_type": "interactive", "card": feishu.card_of(page, page.template)},
                PushTarget("https://open.feishu.cn/hook/x", "secret"),
            )
            self.assertLess(len(payload), 20000)


class TestFingerprint(unittest.TestCase):
    def test_summary_is_not_part_of_fingerprint(self):
        """摘要里常有浏览量/更新时间这类易变字段，算进指纹会导致无限重推。"""
        self.assertEqual(make_item(summary="v1").fingerprint,
                         make_item(summary="v2").fingerprint)

    def test_title_change_still_counts(self):
        self.assertNotEqual(make_item(title="旧标题").fingerprint,
                            make_item(title="新标题").fingerprint)

    def test_severity_change_still_counts(self):
        low = make_item()
        high = make_item()
        high.severity = 4
        self.assertNotEqual(low.fingerprint, high.fingerprint)

    def test_summary_change_is_not_fresh(self):
        state = State()
        state.remember(make_item(summary="v1"), 100)
        self.assertFalse(state.is_fresh(make_item(summary="v2")))


class TestSourceNameEscaping(unittest.TestCase):
    def test_source_name_with_markdown_chars_is_escaped(self):
        config = Config(sources=[Source("A*B", "https://a.test/1")])
        source = config.sources[0]
        item = Item(source_key=source.key, source_name=source.name, uid="u1",
                    title="标题", link="", published=1, summary="")
        body = compose(config, [item], 1793000000)[0].body
        self.assertIn("A&#42;B（1条）", body)


class TestStateVersion(unittest.TestCase):
    def test_v1_state_is_rejected_with_reset_hint(self):
        """v2 改了指纹输入，旧 state 必须明确要求重建，而不是把历史条目重推一遍。"""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(json.dumps({"version": 1, "seen": {"k:1": "fp"}}),
                            encoding="utf-8")
            with self.assertRaises(StateError) as ctx:
                load_state(path)
        self.assertIn("--reset", str(ctx.exception))


class TestWebhookConfig(unittest.TestCase):
    def test_object_without_webhook_is_rejected(self):
        """写了对象却没给地址，多半是复制漏了，不该静默跳过。"""
        from vigil.app import load_targets
        with mock.patch.dict(os.environ, {
            "FEISHU_WEBHOOK": "", "FEISHU_WEBHOOKS": '[{"secret": "x"}]',
        }), self.assertRaises(ConfigError):
            load_targets()

    def test_empty_items_are_ignored(self):
        from vigil.app import load_targets
        with mock.patch.dict(os.environ, {
            "FEISHU_WEBHOOK": "",
            "FEISHU_WEBHOOKS": "https://open.feishu.cn/hook/a,,",
        }):
            self.assertEqual(len(load_targets()), 1)


class TestHeartbeat(unittest.TestCase):
    def test_weekly_heartbeat_forces_a_commit(self):
        """公开仓库 60 天无提交会被停掉定时任务，没新条目时也要留心跳。"""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            state = State()
            state.health("k").initialized = True
            self.assertTrue(state.save(path))

            reloaded = load_state(path)
            self.assertFalse(reloaded.save(path), "内容没变时不该产生提交")

            # 一周后再跑一轮：即使内容没变，也必须留下一次心跳提交
            later = int(time.time()) + 8 * 86400
            with mock.patch("vigil.state.time.time", return_value=later):
                self.assertTrue(reloaded.save(path), "心跳到期时必须强制写一次")


class TestSummaryNoise(unittest.TestCase):
    def test_trailing_link_is_stripped(self):
        """不少源把详情页地址也写进正文，和【链接】重复。"""
        from vigil.parse import build_item
        item = build_item(Source("s", "https://a.test/1"), uid="1", title="标题",
                          summary="详细说明 https://a.test/1", link="https://a.test/1")
        assert item is not None
        self.assertEqual(item.summary, "详细说明")

    def test_severity_line_not_duplicated_in_summary(self):
        item = parse_nginx(NGINX_HTML, NGINX_SOURCE)[0]
        self.assertEqual(item.severity, 2)
        self.assertNotIn("Severity", item.summary)


class TestCollectTranslation(unittest.TestCase):
    def setUp(self):
        self.config = Config(sources=[Source("源A", "https://a.test/feed.xml")])
        self.key = self.config.sources[0].key
        self.feed = (
            '<?xml version="1.0"?><rss version="2.0"><channel>'
            "<item><title>New advisory</title><link>https://a.test/1</link>"
            "<guid>g1</guid><description>desc</description></item>"
            "</channel></rss>"
        )

    def _collect(self, state, translator, now=2000000000):
        response = lambda *a, **k: Response(self.feed, '"e"', "")   # noqa: E731
        with mock.patch("vigil.collect.build_translator", lambda deadline=None: translator), \
                mock.patch("vigil.collect.fetch", response):
            return collect(self.config, state, now, deadline=time.monotonic() + 30)

    def test_pending_item_with_translation_is_not_retranslated(self):
        state = State()
        state.health(self.key).initialized = True
        # 用真实解析结果入队，保证指纹与这一轮抓到的完全一致
        item = parse_rss(self.feed, self.config.sources[0])[0]
        item.title_zh = "中文标题"
        item.summary_zh = "中文摘要"
        state.queue(item, 100)

        calls = []

        class Translator:
            def translate(self, items):
                calls.append([i.uid for i in items])
                return 0

        report = self._collect(state, Translator())
        self.assertEqual(calls, [], "已有译文的待送达条目不该再翻一遍")
        self.assertEqual(report.items, [])

    def test_missing_translation_is_backfilled(self):
        state = State()
        state.health(self.key).initialized = True
        item = parse_rss(self.feed, self.config.sources[0])[0]
        state.queue(item, 100)

        class Translator:
            def translate(self, items):
                for entry in items:
                    entry.title_zh = "中文标题"
                return len(items)

        self._collect(state, Translator())
        self.assertEqual(state.pending[item.key].item["title_zh"], "中文标题")

    def test_summary_only_translation_is_backfilled(self):
        """标题翻失败、摘要翻成功时，摘要译文也必须写回。

        以前写回条件是 `if item.title_zh`，摘要译文会被丢掉：日志报"补齐 1 条"，
        实际什么都没存，下一轮还要再请求一次。
        """
        state = State()
        state.health(self.key).initialized = True
        item = parse_rss(self.feed, self.config.sources[0])[0]
        state.queue(item, 100)

        class Translator:
            def translate(self, items):
                for entry in items:
                    entry.summary_zh = "中文摘要"
                return len(items)

        self._collect(state, Translator())
        self.assertEqual(state.pending[item.key].item["summary_zh"], "中文摘要")


class TestRetryableDecode(unittest.TestCase):
    class Truncated:
        """模拟被截断的响应体：读到一半就没有了。"""

        status = 200

        def __init__(self, body: bytes, encoding: str):
            self._body = io.BytesIO(body)
            self.headers = {"Content-Encoding": encoding}

        def read(self, size=None):
            return self._body.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def test_truncated_gzip_is_retried(self):
        """传输截断是可重试的；以前抛的是 FetchError，直接判源失败、一次都不重试。"""
        body = gzip.compress(b"x" * 5000)[:20]
        with mock.patch("vigil.net.open_url",
                        side_effect=lambda *a, **k: self.Truncated(body, "gzip")) as opener, \
                mock.patch("time.sleep"), self.assertRaises(FetchError):
            net.fetch("https://a.test/x")
        self.assertEqual(opener.call_count, net.HTTP_RETRIES)

    def test_truncated_gzip_recovers(self):
        good = gzip.compress("中文内容".encode(), 9)
        responses = [self.Truncated(good[:20], "gzip"), self.Truncated(good, "gzip")]
        with mock.patch("vigil.net.open_url", side_effect=responses), mock.patch("time.sleep"):
            self.assertEqual(net.fetch("https://a.test/x").text, "中文内容")


class TestFeishuRetryAfter(unittest.TestCase):
    def test_retry_after_is_honoured(self):
        """飞书返回 Retry-After 时要真的等，而不是一次都不重试。

        以前用 `remaining(deadline, RETRY_MAX_WAIT)` 拿到的是 8s 的 cap，
        Retry-After 一超过 8s 就被当成"预算不够"直接放弃。
        """
        responses = [http_error(503, {"Retry-After": "10"}), FakeResponse(b'{"code":0}')]
        waits: list[float] = []
        with mock.patch("vigil.net.open_url", side_effect=responses) as opener, \
                mock.patch("time.sleep", side_effect=waits.append):
            feishu.send("hi", PushTarget("https://hook.test/x", ""))
        self.assertEqual(opener.call_count, 2)
        self.assertEqual(waits, [10.0])

    def test_error_message_reports_real_attempts(self):
        """报错要说清真正试了几次，不能一律写"连续 3 次失败"。"""
        with mock.patch("vigil.net.open_url", side_effect=http_error(503)) as opener, \
                mock.patch("time.sleep"), self.assertRaises(PushError) as ctx:
            feishu.send("hi", PushTarget("https://hook.test/x", ""))
        self.assertIn(f"已尝试 {opener.call_count} 次", str(ctx.exception))


class TestLinkSanitizing(unittest.TestCase):
    def test_link_markup_is_stripped(self):
        """链接也来自外部源：<font> / ** 这类字符必须剔除，否则能往卡片里注入样式。"""
        item = make_item()
        item.link = "https://x.test/a<font color='red'>**伪造**</font>"
        line = render_item(item).split("【链接】")[1]
        self.assertNotIn("<", line)
        self.assertNotIn(">", line)
        self.assertNotIn("**", line)
        self.assertNotIn("<font", render_item(item))

    def test_normal_url_is_untouched(self):
        """URL 里合法的 _ & ( ) # + 不能被转义，否则链接就不点不动了。"""
        for url in ("https://nginx.org/en/security_advisories.html",
                    "https://e.test/a?x=1&y=2",
                    "https://e.test/wiki/Foo_(bar)#Section"):
            item = make_item()
            item.link = url
            self.assertIn(url, render_item(item))


class TestTitleSpacing(unittest.TestCase):
    def test_markup_and_plain_agree(self):
        """两种模式排版必须一致，否则 --dry-run 看到的样子和线上卡片对不上。"""
        item = make_item(title="同一个标题")
        self.assertIn("【标题原文】**同一个标题**", render_item(item, markup=True))
        self.assertIn("【标题原文】同一个标题", render_item(item, markup=False))


class TestWebhookFallback(unittest.TestCase):
    def test_empty_array_falls_back_to_single(self):
        """FEISHU_WEBHOOKS 写了个 "[]" 时不能把 FEISHU_WEBHOOK 一起废掉。"""
        from vigil.app import load_targets
        with mock.patch.dict(os.environ, {
            "FEISHU_WEBHOOK": "https://open.feishu.cn/hook/a",
            "FEISHU_WEBHOOKS": "[]",
        }):
            self.assertEqual([t.webhook for t in load_targets()],
                             ["https://open.feishu.cn/hook/a"])

    def test_only_separators_falls_back_to_single(self):
        """逗号/换行分隔但一个地址都没有，同样要回落。"""
        from vigil.app import load_targets
        with mock.patch.dict(os.environ, {
            "FEISHU_WEBHOOK": "https://open.feishu.cn/hook/a",
            "FEISHU_WEBHOOKS": " , \n , ",
        }):
            self.assertEqual(len(load_targets()), 1)

    def test_separators_alone_yield_nothing(self):
        from vigil.app import load_targets
        with mock.patch.dict(os.environ, {"FEISHU_WEBHOOK": "", "FEISHU_WEBHOOKS": " , "}):
            self.assertEqual(load_targets(), [])


class TestAlertPerTarget(unittest.TestCase):
    """多群场景：一个群收到了，另一个群失败，失败的那个下一轮必须还能收到。"""

    def setUp(self):
        from vigil.app import apply_alerts, build_alerts
        self.build = build_alerts
        self.apply = apply_alerts
        self.config = Config(sources=[Source("坏源", "https://a.test/1")])
        self.state = State()
        self.state.health(self.config.sources[0].key).fail = FAIL_ALERT
        self.a = PushTarget("https://hook.test/a", "")
        self.b = PushTarget("https://hook.test/b", "")

    def _send(self, fail_for: set[str]):
        from vigil.app import _send_alerts

        def fake(text, target, *, deadline=None):
            if target.webhook in fail_for:
                raise PushError("模拟失败")

        alerts = self.build(self.config, self.state, 1000, {self.a.tid, self.b.tid})
        with mock.patch("vigil.app.send", fake):
            ok, delivered = _send_alerts([self.a, self.b], alerts, 1e9)
        return alerts, ok, delivered

    def test_failed_target_gets_it_next_round(self):
        alerts, ok, delivered = self._send({self.b.webhook})
        self.assertFalse(ok)
        self.apply(self.state, alerts, delivered, 1000)
        health = self.state.health(self.config.sources[0].key)
        self.assertEqual(health.alert_sent, {self.a.tid: "fail"})

        again = self.build(self.config, self.state, 1100, {self.a.tid, self.b.tid})
        self.assertEqual([alert.targets for alert in again], [{self.b.tid}])

    def test_recovery_only_goes_to_targets_that_got_the_alert(self):
        alerts, ok, delivered = self._send(set())
        self.assertTrue(ok)
        self.apply(self.state, alerts, delivered, 1000)

        self.state.health(self.config.sources[0].key).fail = 0
        recovered = self.build(self.config, self.state, 2000, {self.a.tid, self.b.tid})
        self.assertEqual([alert.kind for alert in recovered], ["recovered"])


class TestSeenPruneOrder(unittest.TestCase):
    def test_oldest_entries_are_dropped(self):
        """裁剪要按 seen_at 从旧到新，不能从字典迭代序里随便删。"""
        state = State()
        now = 1_000_000
        for index in range(MAX_SEEN + 3):
            key = f"k:{index}"
            state.seen[key] = "fp"
            state.seen_at[key] = now - 1000 + index
        dropped, _ = state.prune(now)
        self.assertEqual(dropped, 3)
        self.assertEqual(len(state.seen), MAX_SEEN)
        self.assertNotIn("k:0", state.seen)          # 最旧的三条被删
        self.assertIn(f"k:{MAX_SEEN + 2}", state.seen)   # 最新的还在

    def test_entries_without_seen_at_count_as_oldest(self):
        state = State()
        now = 1_000_000
        for index in range(MAX_SEEN):
            state.seen[f"k:{index}"] = "fp"
            state.seen_at[f"k:{index}"] = now
        state.seen["no-stamp:1"] = "fp"      # 手工改过 state，缺 seen_at
        dropped, _ = state.prune(now)
        self.assertEqual(dropped, 1)
        self.assertNotIn("no-stamp:1", state.seen)


class TestSplitText(unittest.TestCase):
    def test_long_sentence_without_punctuation_is_split(self):
        """没有句号的超长文本也必须切开，否则 URL 超长、服务端返回 414。"""
        from vigil.translate import split_text
        chunks = split_text("A" * 5000, 1200)
        self.assertGreater(len(chunks), 1)
        self.assertLessEqual(max(len(chunk) for chunk in chunks), 1200)
        self.assertEqual("".join(chunks), "A" * 5000)


class TestPaginateKeyless(unittest.TestCase):
    def test_keyless_page_is_not_dropped(self):
        """只有"源异常提示"这类没有条目 key 的块时，内容也不能被静默丢掉。"""
        pages, overflow = paginate([("⚠ 抓取失败：坏源\n", [])], budget=500, max_pages=3)
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0][1], [])
        self.assertEqual(overflow, 0)

    def test_failure_notice_rides_with_items(self):
        config = Config(sources=[Source("源A", "https://a.test/1")])
        items = [Item(source_key=config.sources[0].key, source_name="源A", uid="u1",
                      title="标题", link="", published=1, summary="")]
        pages = compose(config, items, 1793000000, failures=[Failure("坏源", "k", "HTTP 500")])
        self.assertIn("抓取失败：坏源", pages[0].body)
        self.assertEqual(len(pages[0].keys), 1)


class TestSourceKeyNormalization(unittest.TestCase):
    def test_whitespace_does_not_change_identity(self):
        """两侧空白不该让源的基线失效。"""
        self.assertEqual(Source("a", "https://a.test/1", match=" advisory ").key,
                         Source("b", "https://a.test/1", match="advisory").key)

    def test_kind_is_normalized(self):
        self.assertEqual(Source("a", "https://a.test/1", kind="rss").key,
                         Source("b", "https://a.test/1", kind=" RSS ").key)

    def test_escapes_are_not_case_folded(self):
        r"""`\D` 和 `\d` 语义相反，绝不能被折叠成同一个源身份。

        之前这里用 casefold 归一化 match，两个正则会撞成同一个 key，
        配置直接被判"与前一个源身份相同"。
        """
        self.assertNotEqual(Source("a", "https://a.test/1", match=r"\D{4}").key,
                            Source("b", "https://a.test/1", match=r"\d{4}").key)


class TestParseTimeRobustness(unittest.TestCase):
    def test_nan_and_infinity_do_not_raise(self):
        """JSON 里的 NaN / Infinity 是合法字面量，int() 会抛异常。

        以前一个畸形的时间字段能把整轮抓取打挂，而且抛的是 ValueError，
        连"这个源失败"都算不上。
        """
        for value in (float("nan"), float("inf"), float("-inf"), 1e308):
            self.assertEqual(parse_time(value), 0)


class TestCleanInputCap(unittest.TestCase):
    def test_input_is_capped(self):
        """超长正文会被截断：摘要最终只留 300 字，没必要对几十万字跑十几遍正则。"""
        self.assertEqual(len(clean("a" * (MAX_CLEAN_CHARS + 5000))), MAX_CLEAN_CHARS)

    def test_pathological_angle_brackets_are_cheap(self):
        """大量未闭合的 < 曾让 _TAG 在每个位置回溯 4000 次（O(n·4000)）。"""
        self.assertEqual(len(clean("<" * 400_000)), MAX_CLEAN_CHARS)

    def test_less_than_in_prose_is_not_swallowed(self):
        """安全公告里 "affected versions < 1.2.3" 的 < 不是标签，不能被吃掉。"""
        self.assertEqual(clean("Affected: nginx < 1.25.3, fixed in 1.25.4"),
                         "Affected: nginx < 1.25.3, fixed in 1.25.4")
        self.assertEqual(clean("Price < 5 and > 2"), "Price < 5 and > 2")

    def test_real_tags_still_stripped(self):
        self.assertEqual(clean("<p>foo</p> <b>bar</b>"), "foo bar")
        self.assertEqual(clean('<a href="https://e.test/x">链接</a>'), "链接")
        self.assertEqual(clean("a<br/>b"), "a b")
        self.assertEqual(clean("x <!-- 注释 --> y"), "x y")


class TestNginxLinearScan(unittest.TestCase):
    def test_unclosed_list_item_is_not_an_item(self):
        html = "<ul><li><p>no closing tag<br>Severity: high<br>CVE-2026-1111</p></ul>"
        with self.assertRaises(ParseError):
            parse_nginx(html, NGINX_SOURCE)

    def test_link_tag_is_not_mistaken_for_list_item(self):
        html = ('<ul><li><p>真条目<br>Severity: high<br>CVE-2026-1111</p></li></ul>'
                '<link rel="alternate" href="https://e.test/x">')
        items = parse_nginx(html, NGINX_SOURCE)
        self.assertEqual([item.uid for item in items], ["CVE-2026-1111"])


class TestFeishuTransportError(unittest.TestCase):
    def test_fetch_error_becomes_push_error(self):
        """net 层的 FetchError 必须转成 PushError，否则会以"配置错误"退出码 2
        结束整轮，连累其它群一起放弃。"""
        with mock.patch("vigil.net.open_url", return_value=FakeResponse(b"")), \
                mock.patch("vigil.net.read_limited", side_effect=FetchError("响应超过上限")), \
                mock.patch("time.sleep"), self.assertRaises(PushError):
            feishu.send("hi", PushTarget("https://hook.test/x", ""))


def make_cve_item(source, uid, title, *, severity=0, cvss=0.0, exploited=False,
                  published=10, cve="CVE-2026-1111"):
    return Item(
        source_key=source.key, source_name=source.name, uid=uid, title=title,
        link="", published=published, cves=(cve,), severity=severity, cvss=cvss,
        exploited=exploited,
    )


class TestMergeSafety(unittest.TestCase):
    def setUp(self):
        self.a = Source("源A", "https://a.test/1")
        self.b = Source("源B", "https://b.test/2")
        self.config = Config([self.a, self.b])

    def test_same_source_items_survive_cross_source_merge(self):
        a1 = make_cve_item(self.a, "a1", "A 的第一条")
        a2 = make_cve_item(self.a, "a2", "A 的第二条")
        b1 = make_cve_item(self.b, "b1", "B 的公告")
        out = merge([a1, a2, b1], self.config)
        self.assertEqual(len(out), 2)
        winner = next(item for item in out if item.uid in ("a1", "a2"))
        self.assertEqual(winner.also, ("源B",))
        self.assertEqual(winner.merged, (b1.key,))
        self.assertIn(a2 if winner is a1 else a1, out)

    def test_high_severity_source_wins(self):
        debian = Source("Debian DSA", "https://debian.test/1")
        oss = Source("oss-security", "https://oss.test/2")
        config = Config([debian, oss])
        low = make_cve_item(debian, "d1", "low", severity=1, cvss=2.1)
        critical = make_cve_item(oss, "o1", "critical", severity=4, cvss=9.8)
        out = merge([low, critical], config)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].source_key, oss.key)
        self.assertEqual(out[0].severity, 4)
        self.assertEqual(out[0].cvss, 9.8)
        self.assertEqual(out[0].also, ("Debian DSA",))

    def test_winner_reflects_group_max_severity(self):
        kev = Source("CISA KEV", "https://kev.test/1")
        oss = Source("oss-security", "https://oss.test/2")
        config = Config([kev, oss])
        exploited = make_cve_item(kev, "k1", "KEV", severity=1, cvss=2.0, exploited=True)
        critical = make_cve_item(oss, "o1", "critical", severity=4, cvss=9.8)
        out = merge([exploited, critical], config)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].exploited)
        self.assertEqual(out[0].severity, 4)
        self.assertEqual(out[0].cvss, 9.8)

    def test_only_one_representative_per_source_is_absorbed(self):
        a1 = make_cve_item(self.a, "a1", "A1")
        a2 = make_cve_item(self.a, "a2", "A2")
        b1 = make_cve_item(self.b, "b1", "B1")
        b2 = make_cve_item(self.b, "b2", "B2")
        out = merge([a1, a2, b1, b2], self.config)
        self.assertEqual(len(out), 3)
        winner = next(item for item in out if item.merged)
        self.assertEqual(len(winner.merged), 1)


class TestEmptyAlertWithEtag(unittest.TestCase):
    def test_304_still_counts_as_empty(self):
        source = Source("空源", "https://a.test/feed")
        config = Config([source])
        state = State()
        health = state.health(source.key)
        health.initialized = True
        health.had_items = True
        empty = '<rss version="2.0"><channel><title>t</title></channel></rss>'

        def fake_fetch(url, *, etag="", last_modified="", headers=None, deadline=None):
            if etag:
                raise NotModified()
            return Response(empty, '"e1"', "")

        with mock.patch("vigil.collect.fetch", fake_fetch), \
                mock.patch("vigil.collect.build_translator", lambda deadline=None: None):
            for index in range(3):
                collect(config, state, NOW + index * 600, deadline=time.monotonic() + 30)

        self.assertEqual(state.health(source.key).empty, EMPTY_ALERT)
        alerts = build_alerts(config, state, NOW, {"target"})
        self.assertEqual([alert.kind for alert in alerts], ["empty"])

    def test_empty_counter_does_not_grow_forever(self):
        source = Source("空源", "https://a.test/feed")
        config = Config([source])
        state = State()
        health = state.health(source.key)
        health.initialized = True
        health.had_items = True
        empty = '<rss version="2.0"><channel><title>t</title></channel></rss>'

        def fake_fetch(url, *, etag="", last_modified="", headers=None, deadline=None):
            if etag:
                raise NotModified()
            return Response(empty, '"e1"', "")

        with mock.patch("vigil.collect.fetch", fake_fetch), \
                mock.patch("vigil.collect.build_translator", lambda deadline=None: None):
            for index in range(8):
                collect(config, state, NOW + index * 600, deadline=time.monotonic() + 30)

        self.assertEqual(state.health(source.key).empty, EMPTY_ALERT)


class TestSurrogateSafety(unittest.TestCase):
    def test_json_lone_surrogate_is_sanitized(self):
        source = Source("JSON", "https://a.test/api", kind="json", mapping={})
        raw = '[{"id":"1","title":"bad \\ud800 title","link":"https://e.test/1"}]'
        item = parse_json(raw, source)[0]
        self.assertNotIn("\ud800", item.title)
        self.assertTrue(item.title.encode("utf-8"))
        self.assertTrue(item.fingerprint)

    def test_surrogate_survives_state_roundtrip_safely(self):
        source = Source("源", "https://a.test/1")
        item = Item(source_key=source.key, source_name=source.name, uid="1",
                    title="bad \ud800 title", link="", published=1)
        state = State()
        now = int(time.time())
        state.queue(item, now)
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            self.assertTrue(state.save(path))
            text = path.read_text(encoding="utf-8")
            loaded = load_state(path)
        self.assertNotIn("\ud800", text)
        self.assertIn(item.key, loaded.pending)

    def test_payload_encoding_never_crashes(self):
        payload = feishu._payload(
            {"msg_type": "text", "content": {"text": "bad \ud800"}},
            PushTarget("https://hook.test/x", ""),
        )
        self.assertIn(b"bad", payload)


class TestStateItemValidation(unittest.TestCase):
    BASE = {"source_key": "s", "source_name": "源", "uid": "1", "title": "标题"}

    def test_nan_cvss_is_rejected(self):
        with self.assertRaises(StateError):
            Item.from_dict({**self.BASE, "cvss": "nan"})

    def test_out_of_range_severity_is_rejected(self):
        with self.assertRaises(StateError):
            Item.from_dict({**self.BASE, "severity": 99})

    def test_cves_must_be_an_array(self):
        with self.assertRaises(StateError):
            Item.from_dict({**self.BASE, "cves": "CVE-2026-1111"})


class TestItemConstruction(unittest.TestCase):
    def test_string_cves_is_not_split_into_characters(self):
        item = Item(source_key="s", source_name="源", uid="1", title="t",
                    cves="CVE-2026-1111")  # type: ignore[arg-type]
        self.assertEqual(item.cves, ("CVE-2026-1111",))

    def test_infinite_published_is_clamped(self):
        item = Item(source_key="s", source_name="源", uid="1", title="t",
                    published=float("inf"))  # type: ignore[arg-type]
        self.assertEqual(item.published, 0)


class TestConfigAndStateEncoding(unittest.TestCase):
    def _config(self, tmp: str) -> Path:
        path = Path(tmp) / "config.json"
        path.write_text(json.dumps({"sources": [{"name": "a", "url": "https://a.test"}]}),
                        encoding="utf-8")
        return path

    def test_bom_config_is_accepted(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"sources": [{"name": "a", "url": "https://a.test"}]}),
                            encoding="utf-8-sig")
            self.assertEqual(len(load_config(path).sources), 1)

    def test_bom_state_is_accepted(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(json.dumps({"version": STATE_VERSION}), encoding="utf-8-sig")
            self.assertEqual(load_state(path).seen, {})

    def test_non_utf8_config_is_a_config_error(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_bytes(b'{"sources": [{"name": "\xd6\xd0", "url": "https://a.test"}]}')
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_non_utf8_state_is_a_state_error(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_bytes(b'{"version": 2, "seen": {"\xd6": "x"}}')
            with self.assertRaises(StateError):
                load_state(path)

    def test_save_over_non_utf8_state_does_not_crash(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_bytes(b'{"version": 2, "seen": {"\xd6": "x"}}')
            self.assertTrue(State().save(path))
            self.assertEqual(load_state(path).seen, {})

    def test_invalid_saved_at_is_a_state_error(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(json.dumps({"version": STATE_VERSION, "saved_at": "x"}),
                            encoding="utf-8")
            with self.assertRaises(StateError):
                load_state(path)

    def test_nan_in_state_is_a_state_error(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text('{"version": 2, "saved_at": NaN}', encoding="utf-8")
            with self.assertRaises(StateError):
                load_state(path)

    def test_main_returns_2_instead_of_traceback(self):
        with TemporaryDirectory() as tmp:
            bad_config = Path(tmp) / "bad.json"
            bad_config.write_bytes(b'{"sources": [{"name": "\xd6\xd0", "url": "https://a.test"}]}')
            with redirect_stdout(io.StringIO()):
                self.assertEqual(watch.main(["--config", str(bad_config),
                                             "--state", str(Path(tmp) / "state.json")]), 2)

            config = self._config(tmp)
            bad_state = Path(tmp) / "bad-state.json"
            bad_state.write_bytes(b'{"version": 2, "seen": {"\xd6": "x"}}')
            with redirect_stdout(io.StringIO()):
                self.assertEqual(watch.main(["--config", str(config),
                                             "--state", str(bad_state)]), 2)


class TestConfigNormalization(unittest.TestCase):
    def test_kind_whitespace_and_case_are_normalized(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"sources": [{
                "name": "a", "url": "https://a.test", "kind": " RSS ",
            }]}), encoding="utf-8")
            self.assertEqual(load_config(path).sources[0].kind, "rss")


class TestMatchWhitespace(unittest.TestCase):
    def test_whitespace_around_match_is_ignored(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"sources": [{
                "name": "a", "url": "https://a.test/feed", "match": " advisory ",
            }]}), encoding="utf-8")
            config = load_config(path)
            source = config.sources[0]
            self.assertEqual(source.match, "advisory")

            state = State()
            state.health(source.key).initialized = True
            feed = ('<rss version="2.0"><channel><item><title>Security advisory: x</title>'
                    "<guid>g1</guid></item></channel></rss>")
            with mock.patch("vigil.collect.fetch",
                            lambda *a, **k: Response(feed, "", "")), \
                    mock.patch("vigil.collect.build_translator", lambda deadline=None: None):
                report = collect(config, state, NOW, deadline=time.monotonic() + 30)
            self.assertEqual(len(report.items), 1)


class TestCvssBareScore(unittest.TestCase):
    def test_bare_decimal_score(self):
        self.assertEqual(cvss_of("CVSS 9.8"), 9.8)
        self.assertEqual(severity_of("CVSS 9.8 critical"), 4)

    def test_bare_integer_score(self):
        self.assertEqual(cvss_of("CVSS 10"), 10.0)
        self.assertEqual(cvss_of("CVSS 9"), 9.0)

    def test_known_versions_are_not_scores(self):
        self.assertEqual(cvss_of("CVSS 3.1"), 0.0)
        self.assertEqual(cvss_of("CVSS 4.0"), 0.0)
        self.assertEqual(cvss_of("CVSS 3"), 0.0)


class TestAtomRel(unittest.TestCase):
    def test_full_uri_alternate_rel_is_recognized(self):
        payload = (
            '<feed xmlns="http://www.w3.org/2005/Atom"><entry>'
            "<title>x</title>"
            '<link rel="http://www.iana.org/assignments/relation/alternate" '
            'href="https://e.test/a"/>'
            "<id>1</id></entry></feed>"
        )
        item = parse_rss(payload, Source("x", "https://a.test/1"))[0]
        self.assertEqual(item.link, "https://e.test/a")


class TestNginxTruncation(unittest.TestCase):
    def test_truncated_list_is_an_error(self):
        source = Source("NGINX", "https://nginx.org/x", kind="nginx")
        html = ('<ul>'
                '<li><p>Good advisory<br>Severity: high<br>CVE-2026-1111</p></li>'
                '<li><p>Truncated advisory<br>Severity: high<br>CVE-2026-2222</p>'
                '</ul>')
        with self.assertRaises(ParseError):
            parse_nginx(html, source)


class TestTtlDropDoesNotRequeue(unittest.TestCase):
    def test_dropped_pending_is_not_queued_again(self):
        source = Source("NGINX", "https://a.test/x", kind="nginx")
        config = Config([source])
        state = State()
        state.health(source.key).initialized = True
        state.health(source.key).had_items = True
        html = '<ul><li><p>Test advisory<br>Severity: high<br>CVE-2026-1111</p></li></ul>'
        item = parse_nginx(html, source)[0]
        state.queue(item, 0)
        state.prune(PENDING_TTL + 10)
        self.assertEqual(state.pending, {})
        self.assertIn(item.key, state.seen)

        with mock.patch("vigil.collect.fetch",
                        lambda *a, **k: Response(html, "", "")), \
                mock.patch("vigil.collect.build_translator", lambda deadline=None: None):
            report = collect(config, state, PENDING_TTL + 10, deadline=time.monotonic() + 30)
        self.assertEqual(report.items, [])
        self.assertEqual(state.pending, {})


class TestRenderBounds(unittest.TestCase):
    def test_rendered_item_is_bounded(self):
        item = Item(source_key="s", source_name="源", uid="1",
                    title="T" * 5000, summary="S" * 5000,
                    link="https://e.test/" + "x" * 5000, published=1)
        text = render_item(item, markup=False)
        self.assertLess(len(text), 2000)


class TestLinkEntitySanitizing(unittest.TestCase):
    def test_html_entities_cannot_reconstruct_markup(self):
        item = Item(source_key="s", source_name="源", uid="1", title="标题",
                    link="https://x.test/?q=&#60;font color='red'&#62;x&#42;&#42;",
                    published=1)
        text = render_item(item)
        self.assertNotIn("&#60;", text)
        self.assertNotIn("&#42;", text)
        self.assertNotIn("<font color=red>", text)
        self.assertIn("https://x.test/?q=", text)

    def test_normal_query_ampersand_is_kept(self):
        url = "https://e.test/a?x=1&y=2"
        self.assertEqual(sanitize_link(url), url)
        self.assertEqual(sanitize_link("https://e.test/a?x=1&amp;y=2"),
                         "https://e.test/a?x=1&amp;y=2")


class TestAlertChunking(unittest.TestCase):
    def _alerts(self, count=250):
        sources = [Source(f"源{i:03d}-" + "X" * 70, f"https://a.test/{i}") for i in range(count)]
        config = Config(sources)
        state = State()
        for source in sources:
            state.health(source.key).fail = FAIL_ALERT
        target = PushTarget("https://hook.test/a", "")
        return build_alerts(config, state, NOW, {target.tid}), target

    def test_long_alert_set_is_split_and_fully_delivered(self):
        alerts, target = self._alerts()
        texts = []

        def fake(text, target, *, deadline=None):
            texts.append(text)

        with mock.patch("vigil.app.send", fake):
            ok, delivered = _send_alerts([target], alerts, 1e9)
        self.assertTrue(ok)
        self.assertGreaterEqual(len(texts), 2)
        self.assertTrue(all(len(text.encode("utf-8")) <= MAX_TEXT_BYTES for text in texts))
        self.assertEqual(len(delivered), len(alerts))

    def test_failed_chunk_is_not_marked_delivered(self):
        alerts, target = self._alerts()
        calls = 0
        texts = []

        def fake(text, target, *, deadline=None):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise PushError("模拟失败")
            texts.append(text)

        with mock.patch("vigil.app.send", fake):
            ok, delivered = _send_alerts([target], alerts, 1e9)
        self.assertFalse(ok)
        self.assertGreater(len(delivered), 0)
        self.assertLess(len(delivered), len(alerts))

    def test_oversized_single_alert_is_truncated(self):
        """单条告警超过纯文本预算时要截断，不能把超长消息发给飞书。"""
        from vigil.app import Alert, _alert_chunks

        alert = Alert("fail", "k", "n", "x" * 500, set())
        chunks = list(_alert_chunks([alert], 100))
        self.assertEqual(len(chunks), 1)
        self.assertLessEqual(len(chunks[0][0][1].encode("utf-8")), 100)


class TestPaginationNoOrphanHeader(unittest.TestCase):
    def test_every_page_has_an_item(self):
        config = Config([Source("源A", "https://a.test/1")], max_items=10)
        items = [Item(source_key=config.sources[0].key, source_name="源A", uid=f"u{i}",
                      title=f"标题 {i}", link="", published=1000 - i, summary="描述")
                 for i in range(10)]
        pages = compose(config, items, NOW, budget=200)
        self.assertGreater(len(pages), 1)
        for page in pages:
            self.assertTrue(page.keys, page.body)


class TestRedirectSsrf(unittest.TestCase):
    def test_private_and_non_http_redirects_are_rejected(self):
        handler = net.SafeRedirectHandler()
        request = urllib.request.Request("https://a.test/x")
        for target in ("http://127.0.0.1/x", "http://127.1/x",
                       "http://2130706433/x", "http://0x7f000001/x",
                       "http://169.254.169.254/latest",
                       "http://localhost/x", "file:///etc/passwd", "https://[::1]/x"):
            with self.assertRaises(urllib.error.HTTPError):
                handler.redirect_request(request, None, 302, "Found", {}, target)

    def test_public_redirect_is_allowed(self):
        handler = net.SafeRedirectHandler()
        request = urllib.request.Request("https://a.test/x")
        new = handler.redirect_request(request, None, 302, "Found", {}, "https://b.test/y")
        self.assertEqual(new.full_url, "https://b.test/y")


class TestSecretWhitespace(unittest.TestCase):
    def test_push_target_strips_secret(self):
        target = PushTarget(" https://hook.test/x ", " abc\n")
        self.assertEqual(target.webhook, "https://hook.test/x")
        self.assertEqual(target.secret, "abc")

    def test_json_target_secret_is_stripped(self):
        with mock.patch.dict(os.environ, {
            "FEISHU_WEBHOOK": "",
            "FEISHU_SECRET": "",
            "FEISHU_WEBHOOKS": '[{"webhook":"https://open.feishu.cn/hook/a","secret":"abc\\n"}]',
        }):
            target = load_targets()[0]
        self.assertEqual(target.secret, "abc")


class TestWebhookHost(unittest.TestCase):
    def test_non_feishu_host_is_rejected(self):
        with mock.patch.dict(os.environ, {
            "FEISHU_WEBHOOK": "https://hook.test/a",
            "FEISHU_WEBHOOKS": "",
            "FEISHU_SECRET": "",
            "FEISHU_ALLOW_ANY_HOST": "",
        }, clear=True), self.assertRaises(ConfigError):
            load_targets()

    def test_feishu_host_is_accepted(self):
        with mock.patch.dict(os.environ, {
            "FEISHU_WEBHOOK": "https://open.feishu.cn/open-apis/bot/v2/hook/a",
            "FEISHU_WEBHOOKS": "",
            "FEISHU_SECRET": "",
        }, clear=True):
            self.assertEqual(len(load_targets()), 1)

    def test_escape_hatch_allows_proxy(self):
        with mock.patch.dict(os.environ, {
            "FEISHU_WEBHOOK": "https://hook.test/a",
            "FEISHU_WEBHOOKS": "",
            "FEISHU_SECRET": "",
            "FEISHU_ALLOW_ANY_HOST": "1",
        }, clear=True):
            self.assertEqual(len(load_targets()), 1)


class TestTranslateBudget(unittest.TestCase):
    def test_expired_deadline_stops_without_calling_provider(self):
        class FakeProvider(Provider):
            name = "fake"

            def translate(self, text, deadline):
                raise AssertionError("不应在预算耗尽后请求翻译源")

        item = Item(source_key="s", source_name="源", uid="1", title="Title",
                    link="", published=1, summary="Summary")
        translator = Translator([FakeProvider("https://x.test")],
                                deadline=time.monotonic() - 1)
        self.assertEqual(translator.translate([item]), 0)


class TestNameLength(unittest.TestCase):
    def test_too_long_name_is_rejected(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"sources": [{
                "name": "x" * (MAX_NAME_CHARS + 1), "url": "https://a.test",
            }]}), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_max_length_name_is_accepted(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps({"sources": [{
                "name": "x" * MAX_NAME_CHARS, "url": "https://a.test",
            }]}), encoding="utf-8")
            self.assertEqual(len(load_config(path).sources), 1)


if __name__ == "__main__":
    unittest.main()
