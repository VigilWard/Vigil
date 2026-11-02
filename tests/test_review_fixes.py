"""2026-11 代码审查发现问题的回归测试。

覆盖：跨源合并、ETag 空内容告警、孤立代理项、编码/BOM、saved_at、
match 空白、CVSS 裸分数、NGINX 截断、TTL 重入队、链接实体、告警分块、
分页孤儿标题、重定向 SSRF、Secret 空白与翻译预算。
"""
import io
import json
import os
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import watch
from vigil import feishu, net
from vigil.app import _send_alerts, build_alerts, load_targets
from vigil.collect import collect, merge
from vigil.config import load_config
from vigil.models import (
    EMPTY_ALERT,
    FAIL_ALERT,
    MAX_NAME_CHARS,
    MAX_TEXT_BYTES,
    PENDING_TTL,
    Config,
    ConfigError,
    Item,
    NotModified,
    ParseError,
    PushError,
    PushTarget,
    Source,
    StateError,
)
from vigil.net import Response
from vigil.parse import cvss_of, parse_json, parse_nginx, severity_of
from vigil.render import compose, render_item, sanitize_link
from vigil.state import STATE_VERSION, State, load_state
from vigil.translate import Provider, Translator

NOW = 1793000000


def make_item(source, uid, title, *, severity=0, cvss=0.0, exploited=False,
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
        a1 = make_item(self.a, "a1", "A 的第一条")
        a2 = make_item(self.a, "a2", "A 的第二条")
        b1 = make_item(self.b, "b1", "B 的公告")
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
        low = make_item(debian, "d1", "low", severity=1, cvss=2.1)
        critical = make_item(oss, "o1", "critical", severity=4, cvss=9.8)
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
        exploited = make_item(kev, "k1", "KEV", severity=1, cvss=2.0, exploited=True)
        critical = make_item(oss, "o1", "critical", severity=4, cvss=9.8)
        out = merge([exploited, critical], config)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].exploited)
        self.assertEqual(out[0].severity, 4)
        self.assertEqual(out[0].cvss, 9.8)

    def test_only_one_representative_per_source_is_absorbed(self):
        a1 = make_item(self.a, "a1", "A1")
        a2 = make_item(self.a, "a2", "A2")
        b1 = make_item(self.b, "b1", "B1")
        b2 = make_item(self.b, "b2", "B2")
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

    def test_invalid_saved_at_is_a_state_error(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(json.dumps({"version": STATE_VERSION, "saved_at": "x"}),
                            encoding="utf-8")
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


class TestLinkSanitizing(unittest.TestCase):
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
