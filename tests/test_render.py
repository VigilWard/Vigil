"""消息渲染：一条公告一条消息、等级排序与顺延。"""
import html
import unittest

from vigil.digest import (
    SUBTITLE_COLUMNS,
    card_template,
    compose,
    display_width,
    merge,
    select_items,
    shorten_display,
)
from vigil.models import MAX_CARD_BODY_BYTES, Config, Failure, Item, Source
from vigil.render import render_item, sanitize_link


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


def field_of(text: str, name: str) -> str | None:
    """按字段名取值，避免测试依赖"第几行"——字段顺序以后还会调整。"""
    prefix = f"【{name}】"
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    return None


class TestRenderItem(unittest.TestCase):
    def test_field_layout(self):
        text = render_item(make_item(1, summary="摘要", cves=("CVE-2026-1111",)), markup=False)
        labels = [line.split("】", 1)[0][1:] for line in text.splitlines()]
        self.assertEqual(labels, ["来源", "编号", "发布时间", "标题原文", "摘要原文", "链接"])
        self.assertEqual(field_of(text, "来源"), "源A")
        self.assertEqual(field_of(text, "编号"), "CVE-2026-1111")
        self.assertEqual(field_of(text, "标题原文"), "标题 1")
        self.assertEqual(field_of(text, "摘要原文"), "摘要")
        self.assertEqual(field_of(text, "链接"), "https://e.test/1")

    def test_published_time_is_cst(self):
        """发布时间统一按东八区展示：同一时间戳在 UTC 下是 07:33，不能跟着 runner 的时区走。"""
        item = Item(source_key="s", source_name="源A", uid="1", title="标题",
                    published=1793000000)
        self.assertEqual(field_of(render_item(item, markup=False), "发布时间"),
                         "2026-10-26 15:33")

    def test_published_line_omitted_when_unknown(self):
        """没有发布时间的源（如 NGINX）不显示空字段。"""
        item = Item(source_key="s", source_name="源A", uid="1", title="标题", published=0)
        self.assertNotIn("【发布时间】", render_item(item, markup=False))

    def test_cve_prefix_stripped_from_title(self):
        item = make_item(1, title="CVE-2026-118636: Apache MINA: Unsafe Deserialization",
                         cves=("CVE-2026-118636",))
        self.assertIn("【标题原文】Apache MINA: Unsafe Deserialization", render_item(item, markup=False))

    def test_title_that_is_only_a_cve_is_kept(self):
        item = make_item(1, title="CVE-2026-1111", cves=("CVE-2026-1111",))
        self.assertIn("【标题原文】CVE-2026-1111", render_item(item, markup=False))

    def test_multiple_cves_on_one_line(self):
        item = make_item(1, cves=("CVE-2026-40001", "CVE-2026-40002"))
        lines = render_item(item, markup=False).splitlines()
        self.assertIn("【编号】CVE-2026-40001、CVE-2026-40002", lines)

    def test_missing_cve_omits_line(self):
        text = render_item(make_item(1, cves=()), markup=False)
        self.assertNotIn("【编号】", text)
        self.assertIn("【标题原文】", text)

    def test_missing_summary_and_link(self):
        item = make_item(1, summary="", cves=("CVE-2026-1111",))
        item.link = ""
        text = render_item(item, markup=False)
        self.assertNotIn("【摘要原文】", text)
        self.assertNotIn("【链接】", text)

    def test_source_line_is_always_present(self):
        """来源要能单独认出来：消息被转发或截图时，源名不能只藏在副标题里。"""
        self.assertEqual(field_of(render_item(make_item(1, source_name="oss-security"), markup=False),
                                  "来源"), "oss-security")

    def test_withdrawn_cve_is_marked(self):
        """内核源的撤稿通知（REJECTED: CVE-…）要单独标出来，别被当成一条新漏洞。"""
        item = make_item(1, title="REJECTED: CVE-2026-99252: io_uring/mpscq: disable preemption",
                         cves=("CVE-2026-99252",))
        self.assertIn("【撤销CVE】该编号已作废，不再是有效 CVE",
                      render_item(item, markup=False).splitlines())

    def test_rejected_prefix_is_case_insensitive(self):
        item = make_item(1, title="rejected: CVE-2026-1111: x", cves=("CVE-2026-1111",))
        self.assertIn("【撤销CVE】", render_item(item, markup=False))

    def test_normal_item_has_no_withdrawn_field(self):
        self.assertNotIn("【撤销CVE】", render_item(make_item(1), markup=False))

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
        self.assertEqual(field_of(render_item(item, markup=False), "标记"),
                         "已知勒索团伙利用")

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
        text = render_item(item, markup=False)
        self.assertEqual(field_of(text, "标题翻译"), "Ivanti Connect Secure 身份认证绕过")
        self.assertEqual(field_of(text, "标题原文"), "Ivanti Connect Secure Authentication Bypass")
        self.assertIn("【摘要翻译】这是一段中文摘要", text.splitlines())
        self.assertIn("【摘要原文】English summary", text.splitlines())

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
        text = render_item(item, markup=False)
        self.assertEqual(field_of(text, "标题原文"), "第一行 第二行")
        self.assertEqual(field_of(text, "摘要原文"), "摘要一 摘要二")

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

    def test_also_is_collapsed_to_one_line(self):
        """also 也来自外部文本：换行不能把正文挤成多行（state 可能被手工改过）。"""
        merged = make_item(1)
        merged.also = ("源B\n【等级】严重（CVSS 10.0）",)
        lines = render_item(merged, markup=False).splitlines()
        self.assertEqual(lines[-1], "【另见】源B 【等级】严重（CVSS 10.0）")
        # 来源 / 发布时间 / 标题原文 / 摘要原文 / 链接 / 另见：都没有被换行拆开
        self.assertEqual(len(lines), 6)

    def test_rejected_prefix_requires_a_colon(self):
        """只有 "REJECTED: CVE-…" 才是撤稿通知；普通标题以 Rejected 开头不算。"""
        normal = make_item(1, title="Rejected packets cause kernel panic",
                           cves=("CVE-2026-1111",))
        self.assertNotIn("【撤销CVE】", render_item(normal, markup=False))
        withdrawn = make_item(2, title="REJECTED: CVE-2026-1111: x", cves=("CVE-2026-1111",))
        self.assertIn("【撤销CVE】", render_item(withdrawn, markup=False))

    def test_cve_list_is_capped(self):
        """批量公告可能带成百上千个 CVE：编号行要收口，别把摘要挤到截断之外。"""
        cves = tuple(f"CVE-2026-{index:05d}" for index in range(40))
        item = make_item(1, cves=cves, summary="摘要")
        text = render_item(item, markup=False)
        line = field_of(text, "编号")
        assert line is not None
        self.assertEqual(line.count("CVE-"), 12)
        self.assertIn("等 40 个", line)
        self.assertIn("【摘要原文】摘要", text)


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

    def test_withdrawn_cve_is_red(self):
        item = make_item(1, title="REJECTED: CVE-2026-99252: x", cves=("CVE-2026-99252",))
        self.assertIn("<font color='red'>该编号已作废，不再是有效 CVE</font>", render_item(item))

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

    def test_source_name_is_escaped_in_body(self):
        """源名同样来自配置，正文里的 * 不能把整行吃掉。"""
        item = make_item(1, source_name="A*B")
        self.assertIn("【来源】A&#42;B", render_item(item))
        self.assertIn("【来源】A*B", render_item(item, markup=False))

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
        messages = compose(self.config, items_for(self.config, 3))
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
        messages = compose(self.config, items)
        self.assertIn("u4", messages[0].keys[0])
        self.assertIn("u3", messages[1].keys[0])
        self.assertIn("u2", messages[2].keys[0])
        self.assertIn("u1", messages[3].keys[0])

    def test_header_keeps_icon_and_source(self):
        """副标题只有一行，只放序号和源名；等级靠图标/配色和正文【等级】表达。"""
        item = make_item(1, severity=4, cvss=9.8, cves=("CVE-2026-1111",))
        message = compose(self.config, [item])[0]
        self.assertTrue(message.title.startswith("🔴 "))
        self.assertIn("源A", message.subtitle)
        self.assertNotIn("CVSS", message.subtitle)
        self.assertEqual(message.template, "carmine")
        self.assertIn("【编号】CVE-2026-1111", message.body)
        self.assertIn("【等级】<font color='red'>严重（CVSS 9.8）</font>", message.body)

    def test_header_prefers_translated_title(self):
        """头部是扫消息时唯一会看的地方，有译文就该用译文。"""
        item = make_item(1, title="Ivanti Connect Secure Authentication Bypass")
        item.title_zh = "Ivanti Connect Secure 身份认证绕过"
        self.assertEqual(compose(self.config, [item])[0].title,
                         "Ivanti Connect Secure 身份认证绕过")

    def test_header_keeps_icon_on_translated_title(self):
        item = make_item(1, exploited=True)
        item.title_zh = "中文标题"
        self.assertEqual(compose(self.config, [item])[0].title, "🚨 中文标题")

    def test_header_falls_back_when_translation_is_identical(self):
        item = make_item(1, title="Same title")
        item.title_zh = "Same title"
        self.assertEqual(compose(self.config, [item])[0].title, "Same title")

    def test_header_strips_cve_prefix_from_translated_title(self):
        item = make_item(1, title="CVE-2026-1111: Foo", cves=("CVE-2026-1111",))
        item.title_zh = "CVE-2026-1111: 中文标题"
        self.assertEqual(compose(self.config, [item])[0].title, "中文标题")

    def test_exploited_uses_alarm_icon_and_red(self):
        item = make_item(1, exploited=True, severity=4)
        message = compose(self.config, [item])[0]
        self.assertTrue(message.title.startswith("🚨 "))
        self.assertNotIn("在野利用", message.subtitle)
        self.assertEqual(message.template, "red")
        self.assertIn("已确认在野利用", message.body)

    def test_message_index_in_subtitle(self):
        messages = compose(self.config, items_for(self.config, 3))
        for index, message in enumerate(messages, 1):
            # 序号必须在最前面：手机端副标题只有一行，被截时先丢末尾的源名
            self.assertTrue(message.subtitle.startswith(f"第 {index}/3 条 · "), message.subtitle)

    def test_max_messages_limits_and_reports_overflow(self):
        messages = compose(self.config, items_for(self.config, 5), max_messages=3)
        self.assertEqual(len(messages), 3)
        self.assertIn("另有 2 条顺延到下一轮", messages[-1].body)
        for message in messages[:-1]:
            self.assertNotIn("顺延", message.body)

    def test_per_source_limit_counts_as_overflow(self):
        config = Config(sources=[Source("源A", "https://a.test/1", limit=2)], max_items=10)
        messages = compose(config, items_for(config, 5))
        self.assertEqual(len(messages), 2)
        self.assertIn("另有 3 条顺延到下一轮", messages[-1].body)

    def test_body_stays_within_budget(self):
        items = items_for(self.config, 60, summary="很长的中文描述" * 20)
        messages = compose(self.config, items, budget=MAX_CARD_BODY_BYTES)
        self.assertTrue(messages)
        for message in messages:
            self.assertLessEqual(len(message.body.encode("utf-8")), MAX_CARD_BODY_BYTES)

    def test_notes_ride_with_the_first_message(self):
        messages = compose(self.config, items_for(self.config, 2),
                           failures=[Failure("坏源", "k", "x")],
                           skipped=[Failure("慢源", "k2", "y")])
        self.assertIn("抓取失败：坏源", messages[0].body)
        self.assertIn("未检查：慢源", messages[0].body)
        self.assertNotIn("抓取失败", messages[1].body)

    def test_empty_items(self):
        self.assertEqual(compose(self.config, []), [])

    def test_markup_toggle(self):
        items = items_for(self.config, 1, severity=4, cvss=9.8)
        self.assertIn("<font", compose(self.config, items)[0].body)
        self.assertNotIn("<font", compose(self.config, items, markup=False)[0].body)

    def test_as_text_contains_title_and_body(self):
        item = make_item(1, title="标题一", severity=4)
        text = compose(self.config, [item], markup=False)[0].as_text()
        self.assertTrue(text.startswith("🔴 标题一 · "))
        self.assertIn("\n【标题原文】标题一", text)


class TestSubtitleWidth(unittest.TestCase):
    """副标题只有一行：序号不能被截断，整行要能排进手机宽度。

    飞书文档只承诺"副标题最多一行，超出用 ... 省略"，没有给像素宽度；
    PC 卡片宽、手机卡片窄，所以这里锁的是"我们自己收口"的行为。
    """

    def test_counter_comes_first_and_line_fits_budget(self):
        source = Source("超长源名" * 10, "https://b.test/2")
        config = Config(sources=[source], max_items=50)
        items = [
            Item(source_key=source.key, source_name=source.name, uid=f"u{i}",
                 title=f"标题 {i}", link="", published=100 - i)
            for i in range(3)
        ]
        for index, message in enumerate(compose(config, items), 1):
            self.assertTrue(message.subtitle.startswith(f"第 {index}/3 条 · "), message.subtitle)
            self.assertLessEqual(display_width(message.subtitle), SUBTITLE_COLUMNS)
            self.assertTrue(message.subtitle.endswith("…"), message.subtitle)

    def test_single_message_shows_source_only(self):
        item = Item(source_key="s1", source_name="源A", uid="u1", title="标题", published=1)
        config = Config(sources=[Source("源A", "https://a.test/1")])
        self.assertEqual(compose(config, [item])[0].subtitle, "源A")

    def test_display_width_counts_cjk_as_two(self):
        self.assertEqual(display_width("ab"), 2)
        self.assertEqual(display_width("中文"), 4)
        self.assertEqual(display_width("第 1/2 条"), 9)

    def test_shorten_display_keeps_whole_chars(self):
        self.assertEqual(shorten_display("", 0), "")
        self.assertEqual(shorten_display("abc", 3), "abc")     # 刚好放得下就不动它
        self.assertEqual(shorten_display("abc", 2), "a…")      # 一个字 + 省略号
        self.assertEqual(shorten_display("中文", 3), "中…")     # 不切半个汉字
        self.assertEqual(shorten_display("中a文b", 4), "中a…")
        # 前导空白把预算吃光时不能留一个孤零零的省略号
        self.assertEqual(shorten_display("  abc", 3), "")


class TestLinkSanitizing(unittest.TestCase):
    def test_markup_entities_are_removed(self):
        """lark_md 会解码实体，&#60; 与 &NewLine; 都能绕过字面剔除。"""
        self.assertNotIn("&#60;", sanitize_link("https://x/?q=&#60;font&#62;"))
        self.assertNotIn("&NewLine;", sanitize_link("https://e.com/a&NewLine;【等级】严重"))

    def test_query_ampersand_survives(self):
        url = "https://e.test/a?x=1&amp;y=2"
        self.assertEqual(sanitize_link(url), url)
        # &AMP; 是 HTML5 里合法的大写实体，解码回来同样是 &，不能编码成 %26
        self.assertEqual(sanitize_link("https://e.test/a?x=1&AMP;y=2"),
                         "https://e.test/a?x=1&amp;y=2")
        for text in (url, "https://e.test/a?x=1&AMP;y=2"):
            self.assertIn("x=1&y=2", html.unescape(sanitize_link(text)))

    def test_numeric_ampersand_is_normalized(self):
        """&#38; / &#x26; 就是 &，不能被当成危险实体删掉（否则查询参数被改坏）。"""
        for token in ("&#38;", "&#x26;", "&#X26;"):
            self.assertEqual(
                sanitize_link(f"https://e.test/?a=1{token}b=2"),
                "https://e.test/?a=1&amp;b=2",
                token,
            )

    def test_bare_markup_chars_are_removed(self):
        self.assertEqual(sanitize_link("https://e.test/a<b>*c*"), "https://e.test/abc")

    def test_tilde_in_url_is_preserved(self):
        """~ 是 RFC 3986 的 unreserved：/~user/ 这类地址不能被改坏。"""
        url = "https://www.cs.cornell.edu/~shmat/advisory.html"
        self.assertEqual(sanitize_link(url), url)

    def test_query_separator_is_preserved(self):
        """普通 & 是查询参数分隔符，不能编码成 %26（否则参数会被合并）。"""
        self.assertEqual(sanitize_link("https://e.test/?a=1&b=2"),
                         "https://e.test/?a=1&b=2")

    def test_removed_entity_cannot_reassemble_markup(self):
        """净化必须对"再解码一次"稳定：删除实体会把两侧拼成新实体。"""
        payloads = (
            "https://v.test/?id=1&#6&x;0;font color=red&#6&x;2;PWN",
            "https://v.test/?id=1&lbrac&z;k;点我&rbrac&z;k;",
            "https://v.test/?x=1&Ne&z;wLine;#【等级】严重",
        )
        for payload in payloads:
            cleaned = sanitize_link(payload)
            decoded = html.unescape(cleaned)
            for marker in ("<font", "[", "\n", "&#60;"):
                self.assertNotIn(marker, decoded, (payload, cleaned, decoded))

    def test_character_reference_without_semicolon_is_neutralized(self):
        """&#60 没有分号也会被 html.unescape 解码成 <，不能只拦带分号的。"""
        cleaned = sanitize_link("https://v.test/?q=&#60font color=red&#62;")
        self.assertNotIn("<", html.unescape(cleaned))

    def test_legacy_entity_prefix_is_neutralized(self):
        """无分号遗留实体按最长前缀解码："&lt0064" → "<0064"，不能只比整段。"""
        for payload in ("https://v.test/?q=&lt0064font", "https://v.test/?q=&lta",
                        "https://v.test/?q=&gt0", "https://v.test/?q=&LTx"):
            decoded = html.unescape(sanitize_link(payload))
            self.assertNotIn("<", decoded, payload)
            self.assertNotIn(">", decoded, payload)

    def test_query_param_named_like_an_entity_is_preserved(self):
        """&notify/&copy 不是危险遗留名：不能为了防注入把查询参数改坏。"""
        url = "https://e.test/?notify=2&copy=3"
        self.assertEqual(sanitize_link(url), url)


class TestUndatedOrder(unittest.TestCase):
    def test_limit_keeps_queue_order_not_alphabetical(self):
        """无日期源（NGINX）不能按标题字母序挑选，否则"最新"变成"字母最靠前"。"""
        source = Source("NGINX", "https://nginx.org/x", limit=2)
        config = Config(sources=[source], max_items=5)
        titles = ["Z 最新", "A 次新", "M 最旧"]
        items = [
            Item(source_key=source.key, source_name=source.name, uid=f"u{index}",
                 title=title, published=0)
            for index, title in enumerate(titles)
        ]
        selected, deferred = select_items(config, items)
        self.assertEqual([item.title for item in selected], ["Z 最新", "A 次新"])
        self.assertEqual(deferred, 1)

    def test_compose_keeps_queue_order(self):
        """端到端再锁一遍：select_items 之后还有 _rank 的排序。"""
        source = Source("NGINX", "https://nginx.org/x", limit=3)
        config = Config(sources=[source], max_items=5)
        titles = ["Z 最新", "A 次新", "M 最旧"]
        items = [
            Item(source_key=source.key, source_name=source.name, uid=f"u{index}",
                 title=title, published=0)
            for index, title in enumerate(titles)
        ]
        self.assertEqual([m.title for m in compose(config, items)], titles)


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
        message = compose(self.config, merge([oss, kev], self.config))[0]
        self.assertIn(kev.key, message.keys)
        self.assertIn(oss.key, message.keys)


if __name__ == "__main__":
    unittest.main()
