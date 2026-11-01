"""文本清洗、时间解析、等级推断与字节截断。"""
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


if __name__ == "__main__":
    unittest.main()
