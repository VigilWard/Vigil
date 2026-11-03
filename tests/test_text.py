"""文本清洗、时间解析、等级推断与字节截断。"""
import io
import time
import unittest
from datetime import datetime, timezone

from vigil.parse import clean, cvss_of, parse_time, severity_of, shorten
from vigil.render import shorten_bytes


class TestClean(unittest.TestCase):
    def test_entities_and_tags(self):
        self.assertEqual(clean("says &quot;hi&quot; &amp; bye"), 'says "hi" & bye')
        self.assertEqual(clean("<p>foo</p> <b>bar</b>"), "foo bar")

    def test_whitespace_collapsed(self):
        self.assertEqual(clean("a\u00a0 \n\t b"), "a b")

    def test_horizontal_rule_on_own_line(self):
        self.assertEqual(clean("Title\n=====\nbody"), "Title body")

    def test_crlf_line_endings(self):
        # 邮件列表类源大量用 CRLF，行尾的 \r 曾让分隔线规则整条失效
        self.assertEqual(clean("Title\r\n=====\r\nbody"), "Title body")
        self.assertEqual(clean("## Summary\r\n\r\n> quoted"), "Summary quoted")

    def test_inline_rule_is_removed(self):
        # oss-security 的正文形如 "Posted by X on Oct 31 ====...\nCVE-..."，
        # 分隔线不在行首，整行匹配的规则抓不到
        self.assertEqual(clean("标题 ========== 正文"), "标题 正文")

    def test_short_symbol_runs_survive(self):
        for text in ("a --- b", "score === 5", "-----Original Message-----", "CVE-2026-1111"):
            self.assertEqual(clean(text), text)

    def test_markdown_headings_and_quotes(self):
        self.assertEqual(clean("## Summary\n\n> quoted"), "Summary quoted")

    def test_markdown_links_keep_text(self):
        self.assertEqual(clean("见 [公告](https://e.test/a) 详情"), "见 公告 详情")
        self.assertEqual(clean("![图](https://e.test/a.png) 说明"), "图 说明")

    def test_markdown_bold_and_code(self):
        self.assertEqual(clean("The `GET /api` is **vulnerable**"), "The GET /api is vulnerable")

    def test_plain_characters_survive(self):
        # 这条最容易回归：不能把正文里的乘号、下划线、引用编号吃掉
        self.assertEqual(clean("a * b * c"), "a * b * c")
        self.assertEqual(clean("snake_case_name"), "snake_case_name")
        self.assertEqual(clean("见 [1][2] 引用"), "见 [1][2] 引用")

    def test_mailing_list_prefix_removed(self):
        self.assertEqual(clean("Posted by Alan Cooper on Oct 30 正文内容"), "正文内容")
        self.assertEqual(clean("Posted by 张三 on 10月30日 正文"), "Posted by 张三 on 10月30日 正文")

    def test_zero_width_removed(self):
        self.assertEqual(clean("a\u200bb\ufeffc"), "abc")

    def test_none_and_empty(self):
        self.assertEqual(clean(None), "")
        self.assertEqual(clean(""), "")

    def test_tag_like_prose_is_preserved(self):
        """<V2.0>、a<b 且 b>c 是正文，不是 HTML 标签，不能被整段吃掉。"""
        for text in ("升级到 <V2.0> 版本", "如果 a<b 且 b>c 则", "firmware <b and c> d"):
            self.assertEqual(clean(text), text, text)

    def test_script_and_style_content_is_removed(self):
        self.assertEqual(clean("<style>body{color:red}</style><p>公告</p>"), "公告")
        self.assertEqual(clean("<script>var a=1;</script>正文"), "正文")

    def test_style_block_does_not_eat_real_content(self):
        """先剥 script/style 再截断：否则一段 CSS 就能把正文挤出 MAX_CLEAN_CHARS。"""
        text = "<style>" + "body{color:red}" * 3000 + "</style><p>真正的公告</p>"
        self.assertEqual(clean(text), "真正的公告")

    def test_quoted_bracket_inside_tag(self):
        """属性值里的 '>' 不能把标签截断，否则会漏出半截标签。"""
        self.assertEqual(clean('<img src=x alt="a>b">'), "")

    def test_boolean_attribute_is_a_tag(self):
        self.assertEqual(clean('<a href="x" download>PDF</a>'), "PDF")

    def test_escaped_script_and_style_are_removed(self):
        """JSON 源常把 HTML 二次转义：unescape 之后还要再剥一次，否则 CSS 照样占满摘要。"""
        text = "<p>&lt;style&gt;" + "b{color:red}" * 100 + "&lt;/style&gt;正文</p>"
        self.assertEqual(clean(text), "正文")

    def test_malformed_tag_edges_are_kept_as_text(self):
        """属性没有值、结束标签不完整时，宁可留着也不能误删正文。"""
        for text in ("<a href=>x", "</>x", "</ 1>x"):
            self.assertEqual(clean(text), text, text)

    def test_trailing_space_before_tag_end(self):
        self.assertEqual(clean("<a href=x >文本</a>"), "文本")

    def test_removed_block_does_not_glue_words(self):
        """删块要补一个空格，否则 "Critical<script>x</script>Update" 会粘成一个词。"""
        self.assertEqual(clean("Critical<script>x</script>Update"), "Critical Update")

    def test_unclosed_blocks_stay_linear(self):
        """大量未闭合 <script> 时，不能每个都向文末重搜闭合标签（那是 O(n²)）。

        回归锚点：40k 个未闭合 opener（约 312KB）线性实现约 10ms，
        退化成"每个都全文搜索"后要 ~1.9s。
        """
        from vigil.parse import _strip_raw_blocks

        payload = "<script>" * 40000
        started = time.perf_counter()
        self.assertEqual(_strip_raw_blocks(payload), payload)
        self.assertLess(time.perf_counter() - started, 0.5)

    def test_unclosed_script_keeps_content_but_drops_later_blocks(self):
        """未闭合的 <script> 可能只是正文在讨论它，不能把后文整段吞掉；
        但后面成对的 <style> 仍然要剥掉。"""
        self.assertEqual(clean("<script>var a=1; <style>b{c}</style> 正文"), "var a=1; 正文")


class TestShorten(unittest.TestCase):
    def test_char_limit(self):
        self.assertEqual(shorten("abcdef", 4), "abc…")
        self.assertEqual(shorten("abc", 10), "abc")

    def test_byte_limit_keeps_utf8_intact(self):
        text = "中文" * 100
        cut = shorten_bytes(text, 100)
        self.assertLessEqual(len(cut.encode("utf-8")), 100)
        cut.encode("utf-8").decode("utf-8")  # 不能抛异常

    def test_zero_budget(self):
        self.assertEqual(shorten_bytes("abc", 0), "")


class TestTime(unittest.TestCase):
    def test_rfc822(self):
        expected = int(datetime(2026, 10, 30, 17, 2, 45, tzinfo=timezone.utc).timestamp())
        self.assertEqual(parse_time("Fri, 30 Oct 2026 17:02:45 GMT"), expected)

    def test_rfc822_without_comma(self):
        expected = int(datetime(2026, 10, 30, 17, 2, 45, tzinfo=timezone.utc).timestamp())
        self.assertEqual(parse_time("30 Oct 2026 17:02:45 GMT"), expected)

    def test_iso_variants(self):
        expected = int(datetime(2026, 10, 30, tzinfo=timezone.utc).timestamp())
        self.assertEqual(parse_time("2026-10-30T00:00:00Z"), expected)
        self.assertEqual(parse_time("2026-10-30"), expected)
        self.assertEqual(parse_time("2026-10-30T08:00:00+08:00"), expected)

    def test_epoch(self):
        self.assertEqual(parse_time(1793318400), 1793318400)
        self.assertEqual(parse_time(1793318400000), 1793318400)
        self.assertEqual(parse_time("1793318400"), 1793318400)

    def test_garbage(self):
        for value in ("not a date", "", None, "null", 0, -5, True):
            self.assertEqual(parse_time(value), 0, value)

    def test_out_of_range_is_zero(self):
        """ISO / HTTP-date 分支也不能返回 9999 年或负数时间戳。"""
        for text in ("9999-12-31", "0001-01-01", "1970-01-01T00:00:00Z"):
            self.assertEqual(parse_time(text), 0, text)


class TestSeverity(unittest.TestCase):
    def test_words(self):
        self.assertEqual(severity_of("Severity: critical"), 4)
        self.assertEqual(severity_of("Severity: important CVSS 4.0: 8.2"), 3)
        self.assertEqual(severity_of("Severity: medium"), 2)
        self.assertEqual(severity_of("Severity: low"), 1)
        self.assertEqual(severity_of("没有等级信息"), 0)

    def test_cvss_score_not_version(self):
        # 4.0 / 3.1 是 CVSS 版本号，不能被当成 4.0 分 / 3.1 分
        self.assertEqual(severity_of("CVSS 4.0: 8.2"), 3)
        self.assertEqual(severity_of("CVSS 3.1 score 9.8"), 4)
        self.assertEqual(severity_of("CVSS 3.1 9.8"), 4)

    def test_vector_string(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.1"
        self.assertEqual(severity_of(vector), 4)

    def test_score_label(self):
        self.assertEqual(severity_of("Base Score: 7.5"), 3)
        self.assertEqual(severity_of("评分9.8"), 4)

    def test_version_numbers_are_not_scores(self):
        # 回归：发布公告里的版本号曾被当成 CVSS 分数，把整批 PHP 条目标成"高"
        for text in ("PHP 8.1.2 Released", "PHP 8.1.0 RC1 available for testing",
                     "OpenSSL 3.0.13 fixes", "PHP 8.6.0 RC4 available"):
            self.assertEqual(severity_of(text), 0, text)


class TestCvss(unittest.TestCase):
    def test_extracts_number(self):
        self.assertEqual(cvss_of("Severity: critical CVSS 3.1: 9.8"), 9.8)
        self.assertEqual(cvss_of("Base Score: 7.5"), 7.5)
        self.assertEqual(cvss_of("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.1"), 9.1)

    def test_absent_returns_zero(self):
        for text in ("Severity: medium", "PHP 8.1.2 Released", "", "no score here"):
            self.assertEqual(cvss_of(text), 0.0, text)

    def test_out_of_range_ignored(self):
        self.assertEqual(cvss_of("CVSS 3.1: 12.0"), 0.0)

    def test_score_at_end_of_sentence(self):
        """"with a CVSS of 7.5." 是英文正文最常见的写法，句号不能把分数一起吃掉。"""
        self.assertEqual(cvss_of("CVSS 9.8."), 9.8)
        self.assertEqual(cvss_of("with a CVSS of 7.5."), 7.5)
        self.assertEqual(cvss_of("The CVSS is 9.8. Patch now."), 9.8)
        self.assertEqual(cvss_of("CVSS 10."), 10.0)
        self.assertEqual(severity_of("Scored CVSS 9.8."), 4)

    def test_score_over_ten_is_not_truncated(self):
        """百分制评分不是 CVSS：以前只取两位数字，会把 "score 100" 截成 10 分。"""
        for text in ("score 100", "Risk score: 100", "CVSS score 100%"):
            self.assertEqual(cvss_of(text), 0.0, text)

    def test_score_word_must_be_whole(self):
        self.assertEqual(cvss_of("underscore 8 chars"), 0.0)

    def test_cvss_version_with_colon(self):
        """"CVSS:3.1 9.8" 里的 3.1 是版本号，不是分数。"""
        self.assertEqual(cvss_of("CVSS:3.1 9.8"), 9.8)
        self.assertEqual(cvss_of("CVSS 3.1"), 0.0)


class TestSafeWrite(unittest.TestCase):
    """Windows 的 GBK 控制台打印 emoji 会抛 UnicodeEncodeError，不能连日志一起消失。"""

    class GbkStream(io.StringIO):
        encoding = "gbk"

        def write(self, text):
            text.encode("gbk")          # 模拟 GBK 控制台：不可编码的字符会抛异常
            return super().write(text)

    def test_emoji_falls_back_to_encodable_text(self):
        from vigil.models import _write

        stream = self.GbkStream()
        _write("🔴 中文", stream)
        self.assertIn("中文", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
