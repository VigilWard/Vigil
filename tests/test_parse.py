"""各源解析器。"""
import json
import time
import unittest
from datetime import datetime, timezone
from email.utils import format_datetime
from unittest import mock

from vigil.models import ParseError, Source
from vigil.parse import parse_json, parse_kev, parse_nginx, parse_rss

SRC = Source("测试源", "https://example.test/feed.xml")


def build_rss(items):
    """items: [(guid, title, description)]"""
    now = format_datetime(datetime.now(timezone.utc))
    body = "".join(
        f"<item><title>{title}</title><link>https://example.test/{guid}</link>"
        f"<guid>{guid}</guid><pubDate>{now}</pubDate><description>{desc}</description></item>"
        for guid, title, desc in items
    )
    return ('<?xml version="1.0" encoding="UTF-8"?><rss version="2.0">'
            f"<channel><title>t</title>{body}</channel></rss>")


ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Atom 标题</title>
    <link rel="self" href="https://example.test/self/1"/>
    <link rel="alternate" href="https://example.test/real/1"/>
    <id>tag:example.test,2026:1</id>
    <updated>2026-10-01T08:00:00Z</updated>
    <summary type="xhtml">
      <div xmlns="http://www.w3.org/1999/xhtml"><p>一段 <b>重要</b> 摘要</p></div>
    </summary>
  </entry>
</feed>"""

RDF = """<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <item rdf:about="https://example.test/1">
    <title>RDF 标题</title>
    <link>https://example.test/1</link>
    <dc:date>2026-10-30T10:00:00Z</dc:date>
    <description>RDF 摘要</description>
  </item>
</rdf:RDF>"""

KEV = json.dumps({
    "title": "CISA Catalog",
    "vulnerabilities": [
        {"cveID": "CVE-2026-1234", "vendorProject": "Ivanti", "product": "Connect Secure",
         "vulnerabilityName": "Ivanti Connect Secure Authentication Bypass Vulnerability",
         "dateAdded": "2026-10-29",
         "shortDescription": "Ivanti Connect Secure contains an auth bypass.",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2026-5678", "vendorProject": "Acme", "product": "Widget",
         "vulnerabilityName": "Path Traversal", "dateAdded": "2026-10-28",
         "shortDescription": "Acme Widget allows ../ traversal.",
         "knownRansomwareCampaignUse": "Unknown"},
        {"vendorProject": "NoCVE", "vulnerabilityName": "没有编号的条目"},
    ],
})


class TestRss(unittest.TestCase):
    def test_basic_fields(self):
        items = parse_rss(build_rss([("g1", "标题一", "描述一")]), SRC)
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item.title, "标题一")
        self.assertEqual(item.link, "https://example.test/g1")
        self.assertEqual(item.uid, "g1")
        self.assertEqual(item.summary, "描述一")
        self.assertGreater(item.published, 0)
        self.assertEqual(item.source_key, SRC.key)

    def test_atom_prefers_alternate_link(self):
        item = parse_rss(ATOM, SRC)[0]
        self.assertEqual(item.link, "https://example.test/real/1")
        self.assertEqual(item.uid, "tag:example.test,2026:1")
        self.assertIn("重要", item.summary)

    def test_rdf(self):
        item = parse_rss(RDF, SRC)[0]
        self.assertEqual(item.title, "RDF 标题")
        self.assertGreater(item.published, 0)

    def test_guid_used_as_link(self):
        rss = ('<?xml version="1.0"?><rss version="2.0"><channel>'
               "<item><guid>https://example.test/post/1</guid><title>只有 guid</title></item>"
               "</channel></rss>")
        self.assertEqual(parse_rss(rss, SRC)[0].link, "https://example.test/post/1")

    def test_duplicate_guid_kept_once(self):
        rss = build_rss([("g1", "第一次", "a"), ("g1", "第二次", "b")])
        self.assertEqual(len(parse_rss(rss, SRC)), 1)

    def test_empty_feed_is_not_an_error(self):
        rss = '<rss version="2.0"><channel><title>空</title></channel></rss>'
        self.assertEqual(parse_rss(rss, SRC), [])

    def test_waf_page_gets_friendly_message(self):
        with self.assertRaises(ParseError) as ctx:
            parse_rss("<!doctype html><html><body>WAF</body></html>", SRC)
        self.assertIn("WAF", str(ctx.exception))

    def test_unknown_root_rejected(self):
        with self.assertRaises(ParseError):
            parse_rss("<foo><bar/></foo>", SRC)

    def test_broken_xml(self):
        with self.assertRaises(ParseError):
            parse_rss("<rss><item>", SRC)

    def test_bom_is_tolerated(self):
        payload = "\ufeff" + build_rss([("g1", "带 BOM", "d")])
        self.assertEqual(len(parse_rss(payload, SRC)), 1)


class TestKev(unittest.TestCase):
    def setUp(self):
        self.src = Source("CISA KEV", "https://example.test/kev.json", kind="kev")

    def test_parse(self):
        items = parse_kev(KEV, self.src)
        self.assertEqual(len(items), 2)  # 没有 cveID 的被丢弃
        self.assertEqual(items[0].uid, "CVE-2026-1234")
        self.assertTrue(all(item.exploited for item in items))

    def test_title_and_link(self):
        item = parse_kev(KEV, self.src)[0]
        self.assertEqual(item.title, "Ivanti Connect Secure Authentication Bypass Vulnerability")
        self.assertEqual(item.link, "https://nvd.nist.gov/vuln/detail/CVE-2026-1234")

    def test_vendor_prefix_added_when_missing(self):
        self.assertEqual(parse_kev(KEV, self.src)[1].title, "Acme Widget：Path Traversal")

    def test_ransomware_flag(self):
        items = parse_kev(KEV, self.src)
        self.assertTrue(items[0].ransomware)
        self.assertFalse(items[1].ransomware)
        # 标记不再塞进摘要，渲染层会单独出一行【标记】
        self.assertNotIn("【已知勒索团伙利用】", items[0].summary)

    def test_structure_change_detected(self):
        with self.assertRaises(ParseError):
            parse_kev("{}", self.src)

    def test_empty_catalog_is_not_an_error(self):
        self.assertEqual(parse_kev('{"vulnerabilities": []}', self.src), [])


class TestJsonSource(unittest.TestCase):
    PAYLOAD = json.dumps({
        "meta": {"page": 1},
        "data": {"items": [
            {"advisory_id": "GHSA-1111", "name": "包 A 存在原型污染",
             "html_url": "https://example.test/a", "detail": {"text": "详细说明 A"},
             "published_at": "2026-10-30T10:00:00Z"},
            {"advisory_id": "GHSA-2222", "name": "包 B 存在命令注入",
             "html_url": "https://example.test/b", "detail": {"text": "详细说明 B"},
             "published_at": "2026-10-29T10:00:00Z"},
            {"name": "没有 id 和 link 的条目"},
        ]},
    })
    MAPPING = {"path": "data.items", "id": "advisory_id", "title": "name",
               "link": "html_url", "summary": "detail.text", "date": "published_at"}

    def _source(self, **kwargs):
        return Source("JSON 源", "https://example.test/api", kind="json",
                      mapping=kwargs.pop("mapping", self.MAPPING), **kwargs)

    def test_mapping(self):
        items = parse_json(self.PAYLOAD, self._source())
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0].uid, "GHSA-1111")
        self.assertEqual(items[0].title, "包 A 存在原型污染")
        self.assertEqual(items[0].link, "https://example.test/a")
        self.assertEqual(items[0].summary, "详细说明 A")
        self.assertGreater(items[0].published, 0)

    def test_title_fallback_when_id_and_link_missing(self):
        items = parse_json(self.PAYLOAD, self._source())
        self.assertEqual(items[2].uid, "没有 id 和 link 的条目")
        self.assertEqual(items[2].link, "")

    def test_default_mapping(self):
        payload = json.dumps([{"id": "1", "title": "默认字段", "link": "https://e.test/1"}])
        self.assertEqual(parse_json(payload, self._source(mapping={}))[0].title, "默认字段")

    def test_cve_field(self):
        payload = json.dumps([{"id": "1", "title": "x", "cve_id": "CVE-2026-9999"}])
        source = Source("s", "https://a.test", kind="json", mapping={"cve": "cve_id"})
        self.assertEqual(parse_json(payload, source)[0].cves, ("CVE-2026-9999",))

    def test_bad_path_reported(self):
        source = self._source(mapping={"path": "nope.items", "title": "name"})
        with self.assertRaises(ParseError) as ctx:
            parse_json(self.PAYLOAD, source)
        self.assertIn("nope.items", str(ctx.exception))

    def test_empty_list_is_not_an_error(self):
        self.assertEqual(parse_json('{"data": {"items": []}}', self._source()), [])

    def test_exploited_flag_carried(self):
        self.assertTrue(all(item.exploited for item in parse_json(self.PAYLOAD, self._source(exploited=True))))


class TestNginx(unittest.TestCase):
    HTML = (
        "<html><body><ul>"
        "<li><p>Buffer overflow when using alias with rewrite<br>Severity: medium<br>"
        '<a href="https://my.f5.com/x">Advisory</a><br>'
        '<a href="https://www.cve.org/CVERecord?id=CVE-2026-15176">CVE-2026-15176</a><br>'
        "Not vulnerable: 1.31.7+<br>Vulnerable: 0.1.29-1.31.6</p></li>"
        "<li><p>Simple notice without CVE<br>Severity: low</p></li>"
        "</ul></body></html>"
    )

    def _src(self):
        return Source("NGINX", "https://nginx.org/en/security_advisories.html", kind="nginx")

    def test_parse(self):
        items = parse_nginx(self.HTML, self._src())
        self.assertEqual(len(items), 2)
        item = items[0]
        self.assertEqual(item.uid, "CVE-2026-15176")
        self.assertEqual(item.title, "Buffer overflow when using alias with rewrite")
        self.assertEqual(item.severity, 2)
        self.assertIn("Vulnerable: 0.1.29-1.31.6", item.summary)
        self.assertNotIn("Advisory", item.summary)
        self.assertEqual(item.published, 0)

    def test_advisory_without_cve_is_kept(self):
        """没有 CVE 的公告也要推；以前直接 continue，最新的公告会被静默漏掉。"""
        item = parse_nginx(self.HTML, self._src())[1]
        self.assertEqual(item.uid, "Simple notice without CVE")
        self.assertEqual(item.severity, 1)
        self.assertEqual(item.cves, ())

    def test_structure_change_detected(self):
        with self.assertRaises(ParseError):
            parse_nginx("<html><body>nothing</body></html>", self._src())


class TestRssEntities(unittest.TestCase):
    def test_entity_text_inside_cdata_is_not_a_bomb(self):
        """安全公告可能在正文里讨论 <!ENTITY 写法，CDATA 里只是文本。"""
        rss = ('<?xml version="1.0"?><rss version="2.0"><channel><item>'
               "<title>XML 实体攻击分析</title><guid>1</guid>"
               "<description><![CDATA[示例 <!ENTITY 写法]]></description>"
               "</item></channel></rss>")
        self.assertEqual(len(parse_rss(rss, SRC)), 1)

    def test_real_entity_declaration_is_still_rejected(self):
        bomb = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]>'
                '<rss version="2.0"><channel><item><title>&a;</title><guid>1</guid>'
                "</item></channel></rss>")
        with self.assertRaises(ParseError):
            parse_rss(bomb, SRC)


class TestJsonDuplicates(unittest.TestCase):
    def test_duplicate_ids_are_deduped(self):
        payload = json.dumps([
            {"id": "1", "title": "第一条"},
            {"id": "1", "title": "第二条"},
        ])
        items = parse_json(payload, Source("J", "https://a.test", kind="json", mapping={}))
        self.assertEqual([item.title for item in items], ["第一条"])

    def test_empty_mapping_value_uses_default_field(self):
        """空映射值不能把整行 JSON 当成标题（配置校验会拦，直接构造也要兜底）。"""
        source = Source("J", "https://a.test", kind="json",
                        mapping={"title": "", "id": "id"})
        payload = json.dumps([{"id": "1", "title": "正常标题"}])
        self.assertEqual(parse_json(payload, source)[0].title, "正常标题")


class TestRssNamespaces(unittest.TestCase):
    """同名元素按命名空间区分：扩展模块不能顶替 RSS/Atom 的核心字段。"""

    def _rss(self, body: str) -> str:
        return ('<?xml version="1.0"?><rss version="2.0" '
                'xmlns:media="http://search.yahoo.com/mrss/"><channel>'
                f"<item><title>T</title><guid>1</guid>{body}</item></channel></rss>")

    def test_media_description_does_not_steal_summary(self):
        """<media:description> 是图片说明，不能替代 <description> 的正文。"""
        items = parse_rss(self._rss(
            "<media:description>图片说明</media:description>"
            "<description>真正的文字摘要</description>"
        ), SRC)
        self.assertEqual(items[0].summary, "真正的文字摘要")

    def test_namespaced_description_is_used_when_it_is_the_only_one(self):
        """只有扩展字段时仍要兜底取到，不要直接丢成空摘要。"""
        items = parse_rss(self._rss("<media:description>只有图片说明</media:description>"), SRC)
        self.assertEqual(items[0].summary, "只有图片说明")

    def test_content_encoded_beats_media_description(self):
        """只有图说 + 正文时，content:encoded 才是摘要，不能被图说顶掉。"""
        rss = ('<?xml version="1.0"?><rss version="2.0" '
               'xmlns:media="http://search.yahoo.com/mrss/" '
               'xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><item>'
               "<title>T</title><guid>1</guid>"
               "<media:description>图片说明</media:description>"
               "<content:encoded><p>完整正文</p></content:encoded>"
               "</item></channel></rss>")
        self.assertEqual(parse_rss(rss, SRC)[0].summary, "完整正文")


class TestEntityScan(unittest.TestCase):
    def test_unclosed_cdata_is_not_an_entity_attack(self):
        """大量未闭合 CDATA 只是畸形输入，不是实体攻击。"""
        from vigil.parse import _has_entity_declaration

        self.assertFalse(_has_entity_declaration("<![CDATA[" * 500))

    def test_scan_stays_linear_on_unclosed_cdata(self):
        """回归锚点：O(n²) 实现对 128KB 要约 5 秒，这里是毫秒级。

        上限给到 0.5s，慢机器也不会误报，同时能挡住退回二次复杂度的改动。
        """
        from vigil.parse import _has_entity_declaration

        payload = "<![CDATA[" * (128 * 1024 // 9)
        started = time.perf_counter()
        self.assertFalse(_has_entity_declaration(payload))
        self.assertLess(time.perf_counter() - started, 0.5)

    def test_unclosed_spans_are_left_alone(self):
        from vigil.parse import _drop_spans

        self.assertEqual(_drop_spans("a<!--b", "<!--", "-->"), "a<!--b")
        self.assertEqual(_drop_spans("a<![CDATA[b]]>c", "<![CDATA[", "]]>"), "ac")


class TestStructureGuards(unittest.TestCase):
    """源站改版时宁可报错（触发告警），也不能静默返回空。"""

    def test_empty_response_is_an_error(self):
        with self.assertRaises(ParseError):
            parse_rss("   ", SRC)

    def test_plain_html_root_is_rejected(self):
        with self.assertRaises(ParseError):
            parse_rss("<html><body>x</body></html>", SRC)

    def test_too_many_items_are_capped(self):
        payload = build_rss([(f"g{i}", f"标题 {i}", "d") for i in range(5)])
        with mock.patch("vigil.parse.MAX_NODES", 2):
            items = parse_rss(payload, SRC)
        self.assertEqual(len(items), 2)

    def test_kev_rows_without_valid_cve_is_an_error(self):
        with self.assertRaises(ParseError):
            parse_kev('{"vulnerabilities": [{"vendorProject": "x"}]}',
                      Source("K", "https://a.test/kev.json", kind="kev"))

    def test_broken_json_is_reported(self):
        with self.assertRaises(ParseError):
            parse_json("{not json", Source("J", "https://a.test", kind="json", mapping={}))

    def test_json_rows_without_titles_is_an_error(self):
        with self.assertRaises(ParseError):
            parse_json('[{"x": 1}]', Source("J", "https://a.test", kind="json", mapping={}))

    def test_truncated_list_item_is_reported(self):
        html = '<ul><li><p>Severity: high<br>CVE-2026-1111'
        with self.assertRaises(ParseError):
            parse_nginx(html, Source("N", "https://nginx.org/x", kind="nginx"))


if __name__ == "__main__":
    unittest.main()
