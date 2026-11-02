"""消息渲染、字节分页与跨源合并。"""
import unittest

from vigil.collect import merge
from vigil.models import MAX_CARD_BODY_BYTES, Config, Failure, Item, Source
from vigil.render import (
    build_sections,
    card_template,
    compose,
    paginate,
    render_item,
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


class TestSections(unittest.TestCase):
    def setUp(self):
        self.config = Config(sources=[
            Source("源A", "https://a.test/1"),
            Source("源B", "https://b.test/2"),
        ], max_items=2)
        self.a, self.b = self.config.sources

    def test_split_exploited_first(self):
        items = [make_item(1, source_key=self.a.key),
                 make_item(2, source_key=self.a.key, exploited=True)]
        labels = [section[0] for section in build_sections(self.config, items)]
        self.assertEqual(labels, ["在野利用", "新披露"])

    def test_severity_before_time(self):
        config = Config(sources=[Source("源A", "https://a.test/1")])
        key = config.sources[0].key
        low = make_item(1, source_key=key, severity=1, published=900)
        critical = make_item(2, source_key=key, severity=4, published=100)
        groups = build_sections(config, [low, critical])[0][1]
        self.assertEqual([i.uid for i in groups[0][1]], ["u2", "u1"])

    def test_hidden_count(self):
        groups = build_sections(self.config, items_for(self.config, 5))[0][1]
        self.assertEqual(len(groups[0][1]), 2)
        self.assertEqual(groups[0][2], 3)

    def test_per_source_limit_overrides_global(self):
        config = Config(sources=[Source("源A", "https://a.test/1", limit=1)], max_items=5)
        groups = build_sections(config, items_for(config, 3))[0][1]
        self.assertEqual(len(groups[0][1]), 1)

    def test_sources_keep_config_order(self):
        items = items_for(self.config, 3) + [
            make_item(9, source_key=self.b.key, source_name=self.b.name)
        ]
        groups = build_sections(self.config, items)[0][1]
        self.assertEqual([group[0] for group in groups], ["源A", "源B"])


class TestPaginate(unittest.TestCase):
    def test_single_page(self):
        pages, overflow = paginate([("x", ["1"])], budget=1000, max_pages=3)
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0], ("x", ["1"]))
        self.assertEqual(overflow, 0)

    def test_budget_is_respected(self):
        blocks = [("条目" * 40, [str(i)]) for i in range(30)]
        pages, overflow = paginate(blocks, budget=600, max_pages=3)
        self.assertEqual(len(pages), 3)
        self.assertGreater(overflow, 0)
        for body, _ in pages:
            self.assertLessEqual(len(body.encode("utf-8")), 600)

    def test_overflow_blocks_are_not_acknowledged(self):
        blocks = [("x" * 400, [str(i)]) for i in range(10)]
        pages, overflow = paginate(blocks, budget=1000, max_pages=2)
        acked = [key for _, keys in pages for key in keys]
        self.assertEqual(len(acked) + overflow, 10)
        self.assertEqual(len(set(acked)), len(acked))

    def test_oversized_block_is_truncated_not_dropped(self):
        pages, overflow = paginate([("x" * 5000, ["k"])], budget=500, max_pages=1)
        self.assertEqual(overflow, 0)
        self.assertEqual(pages[0][1], ["k"])
        self.assertLessEqual(len(pages[0][0].encode("utf-8")), 500)

    def test_zero_pages(self):
        pages, overflow = paginate([("x", ["1"])], budget=500, max_pages=0)
        self.assertEqual(pages, [])
        self.assertEqual(overflow, 1)


class TestCompose(unittest.TestCase):
    def setUp(self):
        self.config = Config(sources=[Source("源A", "https://a.test/1")], max_items=50)

    def test_all_pages_within_budget(self):
        items = items_for(self.config, 60, summary="很长的中文描述" * 20)
        pages = compose(self.config, items, 1793000000, budget=MAX_CARD_BODY_BYTES)
        self.assertTrue(pages)
        for page in pages:
            self.assertLessEqual(len(page.body.encode("utf-8")), MAX_CARD_BODY_BYTES)

    def test_header_and_body_split(self):
        items = items_for(self.config, 1, cves=("CVE-2026-1111",))
        pages = compose(self.config, items, 1793000000)
        page = pages[0]
        self.assertTrue(page.title.startswith("Vigil · "))
        self.assertIn("1 条待送达", page.subtitle)
        self.assertIn("【编号】", page.body)
        self.assertNotIn("Vigil", page.body)

    def test_page_numbers_in_subtitle(self):
        items = items_for(self.config, 60, summary="很长的中文描述" * 20)
        pages = compose(self.config, items, 1793000000, budget=MAX_CARD_BODY_BYTES)
        self.assertGreater(len(pages), 1)
        for index, page in enumerate(pages, 1):
            self.assertIn(f"第 {index}/{len(pages)} 页", page.subtitle)

    def test_exploited_count_in_subtitle(self):
        config = Config(sources=[Source("源A", "https://a.test/1")])
        items = [make_item(1, source_key=config.sources[0].key, exploited=True),
                 make_item(2, source_key=config.sources[0].key)]
        pages = compose(config, items, 1793000000)
        self.assertIn("含 1 条在野利用", pages[0].subtitle)

    def test_notes_appear_in_body(self):
        pages = compose(self.config, items_for(self.config, 1), 1793000000,
                        failures=[Failure("坏源", "k", "x")],
                        skipped=[Failure("慢源", "k2", "y")])
        self.assertIn("抓取失败：坏源", pages[0].body)
        self.assertIn("未检查：慢源", pages[0].body)

    def test_hidden_hint(self):
        config = Config(sources=[Source("源A", "https://a.test/1")], max_items=2)
        pages = compose(config, items_for(config, 5), 1793000000)
        self.assertIn("另有3条未列出", pages[0].body)

    def test_keys_cover_all_items_on_page(self):
        pages = compose(self.config, items_for(self.config, 2), 1793000000)
        self.assertEqual(len(pages[0].keys), 2)

    def test_empty_items(self):
        self.assertEqual(compose(self.config, [], 1793000000), [])

    def test_markup_toggle(self):
        items = items_for(self.config, 1, severity=4, cvss=9.8)
        self.assertIn("<font", compose(self.config, items, 1793000000)[0].body)
        self.assertNotIn("<font", compose(self.config, items, 1793000000, markup=False)[0].body)

    def test_as_text_matches_plain_layout(self):
        text = compose(self.config, items_for(self.config, 1), 1793000000, markup=False)[0].as_text()
        self.assertTrue(text.startswith("Vigil · "))
        self.assertIn("\n【新披露】", text)


class TestCardTemplate(unittest.TestCase):
    def test_exploited_is_red(self):
        self.assertEqual(card_template([make_item(1, exploited=True)]), "red")

    def test_critical_is_carmine(self):
        # red 只留给确认在野利用，普通严重用 carmine
        self.assertEqual(card_template([make_item(1, severity=4)]), "carmine")

    def test_high_is_orange(self):
        self.assertEqual(card_template([make_item(1, severity=3)]), "orange")

    def test_default_is_blue(self):
        self.assertEqual(card_template([make_item(1)]), "blue")


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

    def test_loser_key_rides_into_the_page(self):
        """被合并掉的条目虽然不渲染，但它的 key 必须跟着上页，否则永远不会被 ack。"""
        kev = self._item(self.kev, "k1", "CVE-2026-1111", exploited=True)
        oss = self._item(self.oss, "o1", "CVE-2026-1111")
        page = compose(self.config, merge([oss, kev], self.config), 1793000000)[0]
        self.assertIn(kev.key, page.keys)
        self.assertIn(oss.key, page.keys)


if __name__ == "__main__":
    unittest.main()
