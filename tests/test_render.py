"""消息渲染：一条公告一条消息、等级排序与顺延。"""
import unittest

from vigil.collect import merge
from vigil.models import MAX_CARD_BODY_BYTES, Config, Failure, Item, Source
from vigil.render import (
    card_template,
    compose,
    render_item,
    select_items,
)


def make_item(idx, *, source_key="s1", source_name="源A", exploited=False,
              severity=0, cvss=0.0, published=1000, summary="描述", cves=(), title=None):
    return Item(
        source_key=source_key, source_name=source_name, uid=f"u{idx}",
        title=title or f"标题 {idx}", link=f"https://e.test/{idx}",
        published=published - idx, summary=summary, cves=cves,
        exploited=exploited, severity=severity, cvss=cvss,
    )


def items_for(config, count, **kwargs):
    source = config.sources[0]
    return [make_item(i, source_key=source.key, source_name=source.name, **kwargs)
            for i in range(count)]


class TestRenderItem(unittest.TestCase):
    def test_field_layout(self):
        text = render_item(make_item(1, summary="摘要", cves=("CVE-2026-1111",)), markup=False)
        lines = text.splitlines()
        self.assertEqual(lines[0], "【编号】CVE-2026-1111")
        self.assertEqual(lines[1], "【标题原文】标题 1")
        self.assertEqual(lines[2], "【摘要原文】摘要")
        self.assertEqual(lines[3], "【链接】https://e.test/1")

    def test_cve_prefix_stripped_from_title(self):
        item = make_item(1, title="CVE-2026-118636: Apache MINA: Unsafe Deserialization",
                         cves=("CVE-2026-118636",))
        self.assertIn("【标题原文】Apache MINA: Unsafe Deserialization", render_item(item, markup=False))

    def test_title_that_is_only_a_cve_is_kept(self):
        item = make_item(1, title="CVE-2026-1111", cves=("CVE-2026-1111",))
        self.assertIn("【标题原文】CVE-2026-1111", render_item(item, markup=False))

    def test_multiple_cves_on_one_line(self):
        item = make_item(1, cves=("CVE-2026-40001", "CVE-2026-40002"))
        self.assertEqual(render_item(item, markup=False).splitlines()[0],
                         "【编号】CVE-2026-40001、CVE-2026-40002")

    def test_missing_cve_omits_line(self):
        text = render_item(make_item(1, cves=()), markup=False)
        self.assertNotIn("【编号】", text)
        self.assertTrue(text.startswith("【标题原文】"))

    def test_missing_summary_and_link(self):
        item = make_item(1, summary="", cves=("CVE-2026-1111",))
        item.link = ""
        self.assertEqual(render_item(item, markup=False).splitlines(),
                         ["【编号】CVE-2026-1111", "【标题原文】标题 1"])

    def test_severity_line(self):
        item = make_item(1, cves=("CVE-2026-1111",), severity=4)
        self.assertIn("【等级】严重", render_item(item, markup=False))

    def test_severity_line_with_cvss(self):
        item = make_item(1, cves=("CVE-2026-1111",), severity=3, cvss=8.2)
        self.assertIn("【等级】高（CVSS 8.2）", render_item(item, markup=False))

    def test_no_severity_line_when_unknown(self):
        self.assertNotIn("【等级】", render_item(make_item(1), markup=False))

    def test_ransomware_line(self):
        item = make_item(1, summary="摘要", cves=("CVE-2026-1111",))
        item.ransomware = True
        lines = render_item(item, markup=False).splitlines()
        self.assertEqual(lines[2], "【标记】已知勒索团伙利用")

    def test_exploited_mark_is_in_the_body(self):
        """分组标题【在野利用】没有了，这个信号必须落在每条自己的正文里。"""
        item = make_item(1, exploited=True)
        self.assertIn("【标记】已确认在野利用", render_item(item, markup=False))

    def test_exploited_and_ransomware_share_one_line(self):
        item = make_item(1, exploited=True)
        item.ransomware = True
        self.assertIn("【标记】已确认在野利用、已知勒索团伙利用", render_item(item, markup=False))

    def test_translated_title_and_summary_keep_both_lines(self):
        item = make_item(1, title="Ivanti Connect Secure Authentication Bypass",
                         summary="English summary", cves=("CVE-2026-1111",))
        item.title_zh = "Ivanti Connect Secure 身份认证绕过"
        item.summary_zh = "这是一段中文摘要"
        lines = render_item(item, markup=False).splitlines()
        self.assertEqual(lines[1], "【标题翻译】Ivanti Connect Secure 身份认证绕过")
        self.assertEqual(lines[2], "【标题原文】Ivanti Connect Secure Authentication Bypass")
        self.assertIn("【摘要翻译】这是一段中文摘要", lines)
        self.assertIn("【摘要原文】English summary", lines)

    def test_no_translation_shows_only_original(self):
        """没译文时不能出现「翻译」标签——标签必须和内容对得上。"""
        text = render_item(make_item(1, summary="English summary"), markup=False)
        self.assertNotIn("【标题翻译】", text)
        self.assertNotIn("【摘要翻译】", text)
        self.assertIn("【标题原文】", text)
        self.assertIn("【摘要原文】", text)

    def test_translated_title_keeps_cve_prefix_out(self):
        item = make_item(1, title="CVE-2026-1111: Foo", cves=("CVE-2026-1111",))
        item.title_zh = "CVE-2026-1111: 中文标题"
        self.assertIn("【标题翻译】中文标题", render_item(item, markup=False))

    def test_multiline_input_is_collapsed(self):
        """state 里的条目被手工改过时，换行不能把卡片排版挤歪。

        真实数据经 clean() 处理过不会有换行，但渲染层再兜一次，代价几乎为零。
        """
        item = make_item(1, title="第一行\n第二行", summary="摘要一\n摘要二")
        lines = render_item(item, markup=False).splitlines()
        self.assertEqual(lines[0], "【标题原文】第一行 第二行")
        self.assertEqual(lines[1], "【摘要原文】摘要一 摘要二")

    def test_identical_translation_is_not_repeated(self):
        """译文和原文一样（中文源）时只留一行，别出现两行一模一样的内容。"""
        item = make_item(1, title="Same title")
        item.title_zh = "Same title"
        text = render_item(item, markup=False)
        self.assertNotIn("【标题翻译】", text)
        self.assertEqual(text.count("Same title"), 1)

    def test_also_line(self):
        merged = make_item(1)
        merged.also = ("oss-security",)
        self.assertIn("【另见】oss-security", render_item(merged, markup=False))


class TestMarkup(unittest.TestCase):
    def test_title_is_bold(self):
        # 不加空格：与【编号】【摘要】【链接】一致，也让 --dry-run 和线上卡片对齐
        text = render_item(make_item(1, title="标题一"))
        self.assertIn("【标题原文】**标题一**", text)

    def test_high_severity_is_red(self):
        item = make_item(1, severity=4, cvss=9.8)
        self.assertIn("<font color='red'>严重（CVSS 9.8）</font>", render_item(item))

    def test_low_severity_is_grey(self):
        self.assertIn("<font color='grey'>低</font>", render_item(make_item(1, severity=1)))

    def test_medium_severity_not_colored(self):
        self.assertIn("【等级】中", render_item(make_item(1, severity=2)))

    def test_ransomware_is_red(self):
        item = make_item(1)
        item.ransomware = True
        self.assertIn("<font color='red'>已知勒索团伙利用</font>", render_item(item))

    def test_exploited_is_red(self):
        self.assertIn("<font color='red'>已确认在野利用</font>",
                      render_item(make_item(1, exploited=True)))

    def test_dynamic_text_is_escaped(self):
        # 飞书 lark_md 不支持反斜杠转义，必须换成 HTML 实体
        item = make_item(1, title="a * b * c", summary="x_y [z]")
        text = render_item(item)
        self.assertIn("a &#42; b &#42; c", text)
        self.assertIn("x&#95;y &#91;z&#93;", text)
        self.assertNotIn("\\*", text)

    def test_ampersand_is_escaped_once(self):
        item = make_item(1, title="R&D <script>")
        text = render_item(item)
        self.assertIn("R&amp;D &#60;script&#62;", text)
        self.assertNotIn("&amp;amp;", text)

    def test_plain_mode_has_no_markup(self):
        item = make_item(1, severity=4, cvss=9.8)
        text = render_item(item, markup=False)
        self.assertNotIn("<font", text)
        self.assertNotIn("**", text)


class TestSelectItems(unittest.TestCase):
    def setUp(self):
        self.config = Config(sources=[
            Source("源A", "https://a.test/1"),
            Source("源B", "https://b.test/2"),
        ], max_items=2)
        self.a, self.b = self.config.sources

    def test_per_source_limit(self):
        selected, deferred = select_items(self.config, items_for(self.config, 5))
        self.assertEqual(len(selected), 2)
        self.assertEqual(deferred, 3)

    def test_limit_keeps_the_most_severe_not_the_first(self):
        """limit 截断前必须先按等级排序，否则高危条目会被排在前面的普通条目挤掉。"""
        config = Config(sources=[Source("源A", "https://a.test/1", limit=1)], max_items=5)
        key = config.sources[0].key
        low = make_item(1, source_key=key, severity=1, published=900)
        critical = make_item(2, source_key=key, severity=4, published=100)
        selected, deferred = select_items(config, [low, critical])
        self.assertEqual([item.uid for item in selected], ["u2"])
        self.assertEqual(deferred, 1)

    def test_source_removed_from_config_uses_global_limit(self):
        orphan = make_item(9, source_key="gone", source_name="已删除的源")
        selected, deferred = select_items(self.config, [orphan])
        self.assertEqual(len(selected), 1)
        self.assertEqual(deferred, 0)

    def test_each_source_is_capped_independently(self):
        items = items_for(self.config, 3) + [
            make_item(9, source_key=self.b.key, source_name=self.b.name)
        ]
        selected, deferred = select_items(self.config, items)
        self.assertEqual(len(selected), 3)      # 源A 2 条 + 源B 1 条
        self.assertEqual(deferred, 1)


class TestCompose(unittest.TestCase):
    def setUp(self):
        self.config = Config(sources=[Source("源A", "https://a.test/1")], max_items=50)

    def test_one_message_per_item(self):
        messages = compose(self.config, items_for(self.config, 3), 1793000000)
        self.assertEqual(len(messages), 3)
        for message in messages:
            self.assertEqual(len(message.keys), 1)

    def test_most_urgent_comes_first(self):
        source = self.config.sources[0]
        items = [
            make_item(1, source_key=source.key, severity=1, published=900),
            make_item(2, source_key=source.key, severity=2, published=800),
            make_item(3, source_key=source.key, severity=3, published=700),
            make_item(4, source_key=source.key, exploited=True, severity=1, published=100),
        ]
        messages = compose(self.config, items, 1793000000)
        self.assertIn("u4", messages[0].keys[0])
        self.assertIn("u3", messages[1].keys[0])
        self.assertIn("u2", messages[2].keys[0])
        self.assertIn("u1", messages[3].keys[0])

    def test_header_shows_severity_icon_and_source(self):
        item = make_item(1, severity=4, cvss=9.8, cves=("CVE-2026-1111",))
        message = compose(self.config, [item], 1793000000)[0]
        self.assertTrue(message.title.startswith("🔴 "))
        self.assertIn("源A", message.subtitle)
        self.assertIn("严重（CVSS 9.8）", message.subtitle)
        self.assertEqual(message.template, "carmine")
        self.assertIn("【编号】CVE-2026-1111", message.body)

    def test_exploited_uses_alarm_icon_and_red(self):
        item = make_item(1, exploited=True, severity=4)
        message = compose(self.config, [item], 1793000000)[0]
        self.assertTrue(message.title.startswith("🚨 "))
        self.assertIn("在野利用", message.subtitle)
        self.assertEqual(message.template, "red")
        self.assertIn("已确认在野利用", message.body)

    def test_message_index_in_subtitle(self):
        messages = compose(self.config, items_for(self.config, 3), 1793000000)
        for index, message in enumerate(messages, 1):
            self.assertIn(f"第 {index}/3 条", message.subtitle)

    def test_max_messages_limits_and_reports_overflow(self):
        messages = compose(self.config, items_for(self.config, 5), 1793000000, max_messages=3)
        self.assertEqual(len(messages), 3)
        self.assertIn("另有 2 条顺延到下一轮", messages[-1].subtitle)
        for message in messages[:-1]:
            self.assertNotIn("顺延", message.subtitle)

    def test_per_source_limit_counts_as_overflow(self):
        config = Config(sources=[Source("源A", "https://a.test/1", limit=2)], max_items=10)
        messages = compose(config, items_for(config, 5), 1793000000)
        self.assertEqual(len(messages), 2)
        self.assertIn("另有 3 条顺延到下一轮", messages[-1].subtitle)

    def test_body_stays_within_budget(self):
        items = items_for(self.config, 60, summary="很长的中文描述" * 20)
        messages = compose(self.config, items, 1793000000, budget=MAX_CARD_BODY_BYTES)
        self.assertTrue(messages)
        for message in messages:
            self.assertLessEqual(len(message.body.encode("utf-8")), MAX_CARD_BODY_BYTES)

    def test_notes_ride_with_the_first_message(self):
        messages = compose(self.config, items_for(self.config, 2), 1793000000,
                           failures=[Failure("坏源", "k", "x")],
                           skipped=[Failure("慢源", "k2", "y")])
        self.assertIn("抓取失败：坏源", messages[0].body)
        self.assertIn("未检查：慢源", messages[0].body)
        self.assertNotIn("抓取失败", messages[1].body)

    def test_status_only_message_when_no_items(self):
        messages = compose(self.config, [], 1793000000,
                           failures=[Failure("坏源", "k", "x")])
        self.assertEqual(len(messages), 1)
        self.assertIn("源状态提示", messages[0].title)
        self.assertIn("抓取失败：坏源", messages[0].body)
        self.assertEqual(messages[0].keys, [])

    def test_empty_items(self):
        self.assertEqual(compose(self.config, [], 1793000000), [])

    def test_markup_toggle(self):
        items = items_for(self.config, 1, severity=4, cvss=9.8)
        self.assertIn("<font", compose(self.config, items, 1793000000)[0].body)
        self.assertNotIn("<font", compose(self.config, items, 1793000000, markup=False)[0].body)

    def test_as_text_contains_title_and_body(self):
        item = make_item(1, title="标题一", severity=4)
        text = compose(self.config, [item], 1793000000, markup=False)[0].as_text()
        self.assertTrue(text.startswith("🔴 标题一 · "))
        self.assertIn("\n【标题原文】标题一", text)


class TestCardTemplate(unittest.TestCase):
    def test_exploited_is_red(self):
        self.assertEqual(card_template(make_item(1, exploited=True)), "red")

    def test_exploited_wins_over_severity(self):
        # 在野利用比"严重"更需要立刻处理，哪怕这条自身只标了低危
        self.assertEqual(card_template(make_item(1, exploited=True, severity=1)), "red")

    def test_critical_is_carmine(self):
        # red 只留给确认在野利用，普通严重用 carmine
        self.assertEqual(card_template(make_item(1, severity=4)), "carmine")

    def test_high_is_orange(self):
        self.assertEqual(card_template(make_item(1, severity=3)), "orange")

    def test_default_is_blue(self):
        self.assertEqual(card_template(make_item(1)), "blue")


class TestMerge(unittest.TestCase):
    def setUp(self):
        self.config = Config(sources=[
            Source("KEV", "https://a.test/1"),
            Source("oss", "https://b.test/2"),
        ])
        self.kev, self.oss = self.config.sources

    def _item(self, source, uid, cve, exploited=False, published=10):
        return Item(source_key=source.key, source_name=source.name, uid=uid,
                    title=uid, link="", published=published, cves=(cve,), exploited=exploited)

    def test_same_cve_across_sources_merges(self):
        kev = self._item(self.kev, "k1", "CVE-2026-1111", exploited=True)
        oss = self._item(self.oss, "o1", "CVE-2026-1111")
        out = merge([oss, kev], self.config)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].uid, "k1")
        self.assertEqual(out[0].also, ("oss",))
        self.assertIn(oss.key, out[0].merged)

    def test_same_source_is_not_merged(self):
        first = self._item(self.oss, "o1", "CVE-2026-1111")
        second = self._item(self.oss, "o2", "CVE-2026-1111", published=20)
        self.assertEqual(len(merge([first, second], self.config)), 2)

    def test_multi_cve_item_left_alone(self):
        kev = self._item(self.kev, "k1", "CVE-2026-1111", exploited=True)
        multi = Item(source_key=self.oss.key, source_name="oss", uid="o1", title="o1",
                     link="", published=5, cves=("CVE-2026-1111", "CVE-2026-2222"))
        self.assertEqual(len(merge([kev, multi], self.config)), 2)

    def test_exploited_wins(self):
        oss = self._item(self.oss, "o1", "CVE-2026-1111", published=99)
        kev = self._item(self.kev, "k1", "CVE-2026-1111", exploited=True, published=1)
        self.assertEqual(merge([oss, kev], self.config)[0].uid, "k1")

    def test_loser_key_rides_into_the_message(self):
        """被合并掉的条目虽然不渲染，但它的 key 必须跟着上消息，否则永远不会被 ack。"""
        kev = self._item(self.kev, "k1", "CVE-2026-1111", exploited=True)
        oss = self._item(self.oss, "o1", "CVE-2026-1111")
        message = compose(self.config, merge([oss, kev], self.config), 1793000000)[0]
        self.assertIn(kev.key, message.keys)
        self.assertIn(oss.key, message.keys)


if __name__ == "__main__":
    unittest.main()
