"""端到端状态机：基线 → 增量 → 失败重试 → 告警 → 多目标。"""
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import watch
from vigil.models import FetchError, NotModified, PushError, PushTarget
from vigil.net import Response


def build_rss(entries, dated=True):
    """entries: [(guid, title, description)]"""
    stamp = (f"<pubDate>{format_datetime(datetime.now(timezone.utc))}</pubDate>"
             if dated else "")
    body = "".join(
        f"<item><title>{title}</title><link>https://a.test/{guid}</link>"
        f"<guid>{guid}</guid>{stamp}<description>{desc}</description></item>"
        for guid, title, desc in entries
    )
    return ('<?xml version="1.0" encoding="UTF-8"?><rss version="2.0">'
            f"<channel><title>t</title>{body}</channel></rss>")


class FlowCase(unittest.TestCase):
    def setUp(self):
        handle = TemporaryDirectory()
        self.addCleanup(handle.cleanup)
        self.dir = Path(handle.name)
        self.config_path = self.dir / "config.json"
        self.state_path = self.dir / "state.json"

        self.mode = "ok"
        self.feed = build_rss([("g1", "旧条目", "d1")])
        self.posts = []
        self.fail_for = set()

        self.webhook = "https://hook.test/a"
        patches: list = [
            mock.patch("vigil.collect.fetch", self._fetch),
            mock.patch("vigil.app.send", self._send),
            mock.patch("vigil.app.send_card", self._send_card),
            mock.patch.dict(os.environ, {
                "FEISHU_WEBHOOK": self.webhook,
                "FEISHU_WEBHOOKS": "",
                "FEISHU_ALLOW_ANY_HOST": "1",
                "TRANSLATE": "0",
            }),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

        self.write_config()

    def write_config(self, sources=None):
        self.config_path.write_text(json.dumps({
            "window_hours": 48,
            "max_items": 10,
            "sources": sources or [{"name": "源A", "url": "https://a.test/feed.xml"}],
        }), encoding="utf-8")

    def _fetch(self, url, *, etag="", last_modified="", headers=None, deadline=None):
        if self.mode == "fail":
            raise FetchError("模拟 502")
        if self.mode == "304":
            raise NotModified()
        return Response(self.feed, '"etag"', "")

    def _send(self, text, target, *, deadline=None):
        if target.webhook in self.fail_for:
            raise PushError("模拟推送失败")
        self.posts.append(text)

    @staticmethod
    def _card_text(card) -> str:
        header = card.get("header", {})
        title = header.get("title", {}).get("content", "")
        subtitle = header.get("subtitle", {}).get("content", "")
        body = "\n".join(
            element.get("text", {}).get("content", "")
            for element in card.get("elements", [])
        )
        return f"{title} · {subtitle}\n{body}"

    def _send_card(self, card, target, *, deadline=None):
        if target.webhook in self.fail_for:
            raise PushError("模拟推送失败")
        self.posts.append(self._card_text(card))

    def run_main(self, *args):
        return watch.main(["--config", str(self.config_path), "--state", str(self.state_path)] + list(args))

    def state(self):
        return json.loads(self.state_path.read_text(encoding="utf-8"))


class TestBasics(FlowCase):
    def test_first_run_only_baselines(self):
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.posts, [])
        state = self.state()
        self.assertTrue(state["sources"])
        self.assertTrue(all(record["initialized"] for record in state["sources"].values()))
        self.assertEqual(state["pending"], {})

    def test_second_run_pushes_only_new(self):
        self.run_main()
        self.feed = build_rss([("g2", "新条目", "d2"), ("g1", "旧条目", "d1")])
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(self.posts), 1)
        self.assertIn("新条目", self.posts[0])
        self.assertNotIn("旧条目", self.posts[0])

    def test_304_does_nothing(self):
        self.run_main()
        self.mode = "304"
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.posts, [])

    def test_dry_run_does_not_write_state(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.run_main("--dry-run"), 0)
        self.assertFalse(self.state_path.exists())
        self.assertEqual(self.posts, [])
        self.assertIn("旧条目", output.getvalue())

    def test_dry_run_after_baseline_is_quiet(self):
        self.run_main()
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.run_main("--dry-run"), 0)
        self.assertIn("没有需要推送的新条目", output.getvalue())

    def test_dry_run_shows_items_stuck_in_queue(self):
        """上一轮没送达的条目，下一轮会跟着一起发，dry-run 必须体现出来。"""
        self.run_main()
        self.feed = build_rss([("g2", "新条目", "d2")])
        self.fail_for = {self.webhook}
        self.assertEqual(self.run_main(), 1)      # 推送失败，条目留在队列

        self.fail_for = set()
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.run_main("--dry-run"), 0)
        text = output.getvalue()
        self.assertIn("新条目", text)
        self.assertIn("队列里还有 1 条", text)

    def test_dry_run_does_not_duplicate_superseded_pending(self):
        """队列里的旧版本会被这一轮的新版本替换，预览不能把两版都打印出来。"""
        self.run_main()
        self.feed = build_rss([("g2", "第一版公告", "d")])
        self.fail_for = {self.webhook}
        self.assertEqual(self.run_main(), 1)

        self.fail_for = set()
        self.feed = build_rss([("g2", "第二版公告", "d")])
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.run_main("--dry-run"), 0)
        text = output.getvalue()
        self.assertIn("第二版公告", text)
        self.assertNotIn("第一版公告", text)

    def test_reset_clears_baseline(self):
        self.run_main()
        self.assertEqual(self.run_main("--reset"), 0)
        state = self.state()
        self.assertEqual(state["seen"], {})
        self.assertEqual(state["sources"], {})

    def test_undated_items_are_not_filtered_by_window(self):
        self.run_main()
        self.feed = build_rss([("g2", "无日期公告", "d2")], dated=False)
        self.assertEqual(self.run_main(), 0)
        self.assertIn("无日期公告", self.posts[-1])

    def test_empty_first_response_does_not_baseline_empty_set(self):
        # 首次接入拿到空 feed 时不能标记"已建基线"，否则下一轮会把整份历史当新条目推出去
        self.feed = '<rss version="2.0"><channel><title>t</title></channel></rss>'
        self.assertEqual(self.run_main(), 0)
        self.feed = build_rss([("g1", "历史条目", "d1")])
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.posts, [], "第二次才拿到内容，应当建立基线而不是推送")

    def test_bad_config_exits_2(self):
        self.config_path.write_text("{broken", encoding="utf-8")
        self.assertEqual(self.run_main(), 2)


class TestDelivery(FlowCase):
    def test_push_failure_keeps_item_for_retry(self):
        self.run_main()
        self.feed = build_rss([("g2", "新条目", "d2")])
        self.fail_for = {self.webhook}

        self.assertEqual(self.run_main(), 1)
        state = self.state()
        self.assertEqual(len(state["pending"]), 1)
        self.assertFalse(any(key.endswith(":g2") for key in state["seen"]),
                         "推送失败时不能把条目记为已送达，否则消息永久丢失")

        self.fail_for = set()
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(self.state()["pending"]), 0)
        self.assertIn("新条目", self.posts[-1])

    def test_missing_webhook_keeps_pending(self):
        self.run_main()
        self.feed = build_rss([("g2", "新条目", "d2")])
        with mock.patch.dict(os.environ, {"FEISHU_WEBHOOK": "", "FEISHU_WEBHOOKS": ""}):
            self.assertEqual(self.run_main(), 1)
        self.assertEqual(len(self.state()["pending"]), 1)
        self.assertEqual(self.posts, [])

    def test_multiple_targets_require_both_acks(self):
        second = "https://hook.test/b"
        with mock.patch.dict(os.environ, {
            "FEISHU_WEBHOOK": "",
            "FEISHU_WEBHOOKS": json.dumps([self.webhook, second]),
        }):
            self.run_main()
            self.feed = build_rss([("g2", "新条目", "d2")])
            self.fail_for = {second}
            self.assertEqual(self.run_main(), 1)

            pending = self.state()["pending"]
            self.assertEqual(len(pending), 1)
            record = next(iter(pending.values()))
            self.assertIn(PushTarget(self.webhook).tid, record["sent"])
            self.assertNotIn(PushTarget(second).tid, record["sent"])

            self.fail_for = set()
            self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.state()["pending"], {})
        self.assertEqual(len(self.posts), 2)


class TestFiltering(FlowCase):
    def test_match_filter(self):
        self.write_config([{"name": "源A", "url": "https://a.test/feed.xml",
                            "match": "advisory|security"}])
        self.feed = build_rss([("g1", "Security advisory: 基线", "d")])
        self.run_main()
        self.feed = build_rss([("g2", "PHP 8.5.12 Released!", "x"),
                               ("g3", "Security advisory: 严重漏洞", "y")])
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(self.posts), 1)
        self.assertIn("Security advisory", self.posts[0])
        self.assertNotIn("Released", self.posts[0])

    def test_new_source_only_baselines(self):
        self.run_main()
        self.feed = build_rss([("g1", "旧条目", "d1"), ("g2", "新条目", "d2")])
        self.write_config([
            {"name": "源A", "url": "https://a.test/feed.xml"},
            {"name": "源B", "url": "https://b.test/feed.xml"},
        ])
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(len(self.posts), 1)
        self.assertIn("新条目", self.posts[0])
        self.assertNotIn("源B", self.posts[0])


class TestAlerts(FlowCase):
    def test_failure_alert_after_threshold_and_throttle(self):
        self.run_main()
        self.mode = "fail"
        for _ in range(2):
            self.run_main()
        self.assertEqual(self.posts, [], "没到阈值不该发消息")

        self.run_main()
        self.assertEqual(len(self.posts), 1)
        self.assertIn("已连续 3 轮", self.posts[0])

        self.run_main()
        self.assertEqual(len(self.posts), 1, "6 小时内不该重复告警")

    def test_recovery_notification(self):
        self.run_main()
        self.mode = "fail"
        for _ in range(3):
            self.run_main()
        self.mode = "ok"
        self.assertEqual(self.run_main(), 0)
        self.assertIn("已恢复正常", self.posts[-1])

    def test_empty_alert_fires_once_and_does_not_repeat(self):
        self.run_main()
        self.feed = '<rss version="2.0"><channel><title>t</title></channel></rss>'
        for _ in range(3):
            self.run_main()
        self.assertEqual(len(self.posts), 1)
        self.assertIn("返回空内容", self.posts[0])

        # 内容没变（304）时不应该每 6 小时复读同一条告警
        self.mode = "304"
        for _ in range(5):
            self.run_main()
        self.assertEqual(len(self.posts), 1, "空内容告警是稳态，不该反复推送")

    def test_match_source_with_no_hits_does_not_alert(self):
        self.write_config([{"name": "PHP", "url": "https://a.test/feed.xml",
                            "match": "advisory|security"}])
        self.feed = build_rss([("g1", "Security advisory: 基线", "d")])
        self.run_main()
        self.feed = build_rss([("g2", "PHP 8.5.12 Released!", "x")])
        for _ in range(4):
            self.run_main()
        self.assertEqual(self.posts, [], "过滤后 0 条是正常情况，不能报'结构变化'")


class TestTestMode(FlowCase):
    def test_test_mode_sends_a_card(self):
        self.assertEqual(self.run_main("--test"), 0)
        self.assertEqual(len(self.posts), 1)
        self.assertIn("测试消息", self.posts[0])


class TestTranslation(FlowCase):
    class FakeTranslator:
        def translate(self, items):
            for item in items:
                item.title_zh = "中文：" + item.title
                item.summary_zh = "中文摘要"
            return len(items)

    def setUp(self):
        super().setUp()
        patcher = mock.patch("vigil.collect.build_translator",
                             lambda deadline=None: self.FakeTranslator())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_card_contains_translation(self):
        self.run_main()
        self.feed = build_rss([("g2", "New advisory", "desc")])
        self.assertEqual(self.run_main(), 0)

        message = self.posts[-1]
        self.assertIn("【标题翻译】**中文：New advisory**", message)
        self.assertIn("【标题原文】New advisory", message)
        self.assertIn("【摘要翻译】中文摘要", message)
        self.assertIn("【摘要原文】desc", message)

    def test_translation_does_not_break_dedup(self):
        self.run_main()
        self.feed = build_rss([("g2", "New advisory", "desc")])
        self.run_main()
        self.run_main()
        self.assertEqual(len(self.posts), 1)


class TestPendingLifecycle(FlowCase):
    def test_pending_survives_process_restart(self):
        self.run_main()
        self.feed = build_rss([("g2", "新条目", "d2")])
        self.fail_for = {self.webhook}
        self.run_main()

        self.assertEqual(len(self.state()["pending"]), 1)
        # 新的进程重新读 state，仍然能补发
        self.fail_for = set()
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.state()["pending"], {})

    def test_delivered_items_are_deduplicated(self):
        self.run_main()
        self.feed = build_rss([("g2", "新条目", "d2")])
        self.run_main()
        self.run_main()
        self.assertEqual(len(self.posts), 1)


class TestOneMessagePerItem(FlowCase):
    def test_each_item_gets_its_own_message(self):
        """一条公告一条消息：3 条新条目就是 3 条消息，不再挤在一张卡片里。"""
        self.run_main()
        self.feed = build_rss([(f"g{i}", f"公告 {i}", f"描述 {i}") for i in range(3)])
        self.assertEqual(self.run_main(), 0)

        self.assertEqual(len(self.posts), 3)
        for index, post in enumerate(self.posts):
            self.assertIn(f"公告 {index}", post)
        # 每条消息只带自己那一条，不会把邻居也塞进来
        self.assertNotIn("公告 0", self.posts[1])
        self.assertNotIn("公告 2", self.posts[1])

    def test_message_cap_keeps_the_rest_pending(self):
        """超出单轮上限的条目不能凭空消失：必须留在队列里，下一轮补发。"""
        self.run_main()
        self.feed = build_rss([(f"g{i}", f"公告 {i}", "描述") for i in range(5)])
        with mock.patch("vigil.app.MAX_MESSAGES", 2):
            self.assertEqual(self.run_main(), 0)

        self.assertEqual(len(self.posts), 2)
        self.assertEqual(len(self.state()["pending"]), 3)

        # 下一轮把剩下的补完
        self.assertEqual(self.run_main(), 0)
        self.assertEqual(self.state()["pending"], {})
        self.assertEqual(len(self.posts), 5)

    def test_sent_items_are_acked_per_message(self):
        """逐条确认：每条消息送达后，它自己那一批 key 立刻转正。"""
        self.run_main()
        self.feed = build_rss([("n0", "公告 0", "描述"), ("n1", "公告 1", "描述")])
        self.assertEqual(self.run_main(), 0)

        state = self.state()
        self.assertEqual(state["pending"], {})
        self.assertEqual(len(state["seen"]), 3)      # 基线 1 条 + 新条目 2 条


if __name__ == "__main__":
    unittest.main()
