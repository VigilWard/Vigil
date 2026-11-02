"""HTTP 层：字节上限、编码嗅探、条件请求与重定向策略。"""
import gzip
import io
import time
import unittest
import urllib.error
import urllib.request
import zlib
from email.utils import formatdate
from unittest import mock

from tests.support import FakeResponse, http_error
from vigil import net
from vigil.models import BudgetExceeded, DecodeError, FetchError, NotModified


class TestDecode(unittest.TestCase):
    def test_utf8(self):
        self.assertEqual(net.decode_bytes("中文".encode()), "中文")

    def test_xml_declaration_beats_lying_header(self):
        raw = '<?xml version="1.0" encoding="gbk"?><a>中文公告</a>'.encode("gbk")
        self.assertIn("中文公告", net.decode_bytes(raw, "iso-8859-1"))

    def test_lying_latin1_header_is_ignored(self):
        # latin-1 解码永不失败，如果盲信头就会静默产出乱码
        self.assertEqual(net.decode_bytes("中文".encode(), "iso-8859-1"), "中文")

    def test_utf8_bom(self):
        self.assertEqual(net.decode_bytes("\ufeffabc".encode("utf-8")), "abc")

    def test_gb18030(self):
        self.assertEqual(net.decode_bytes("中文".encode("gb18030")), "中文")


class TestReadLimited(unittest.TestCase):
    def test_rejects_oversized_body(self):
        with self.assertRaises(FetchError):
            net.read_limited(io.BytesIO(b"x" * 100), 50, None)

    def test_reads_exact_limit(self):
        self.assertEqual(net.read_limited(io.BytesIO(b"x" * 50), 50, None), b"x" * 50)


class TestFetch(unittest.TestCase):
    def test_gzip_is_decompressed(self):
        body = gzip.compress("中文内容".encode())
        response = FakeResponse(body, {"Content-Encoding": "gzip", "Content-Type": "text/xml"})
        with mock.patch("vigil.net.open_url", lambda *a, **k: response):
            result = net.fetch("https://a.test/x")
        self.assertEqual(result.text, "中文内容")

    def test_etag_returned(self):
        response = FakeResponse(b"ok", {"ETag": '"abc"', "Last-Modified": "Wed, 21 Oct 2026 07:28:00 GMT"})
        with mock.patch("vigil.net.open_url", lambda *a, **k: response):
            result = net.fetch("https://a.test/x")
        self.assertEqual(result.etag, '"abc"')
        self.assertTrue(result.last_modified.startswith("Wed,"))

    def test_conditional_headers_sent(self):
        seen = {}

        def fake(request, timeout=None):
            seen.update(request.headers)
            return FakeResponse(b"ok")

        with mock.patch("vigil.net.open_url", fake):
            net.fetch("https://a.test/x", etag='"abc"', last_modified="Wed, 21 Oct 2026 07:28:00 GMT")
        self.assertEqual(seen.get("If-none-match"), '"abc"')
        self.assertEqual(seen.get("If-modified-since"), "Wed, 21 Oct 2026 07:28:00 GMT")

    def test_304_raises_not_modified(self):
        with mock.patch("vigil.net.open_url", side_effect=http_error(304)), \
                self.assertRaises(NotModified):
            net.fetch("https://a.test/x")

    def test_client_error_is_not_retried(self):
        with mock.patch("vigil.net.open_url", side_effect=http_error(404)) as opener, \
                self.assertRaises(FetchError):
            net.fetch("https://a.test/x")
        self.assertEqual(opener.call_count, 1)

    def test_server_error_is_retried(self):
        with mock.patch("vigil.net.open_url", side_effect=http_error(503)) as opener, \
                mock.patch("time.sleep"), self.assertRaises(FetchError):
            net.fetch("https://a.test/x")
        self.assertEqual(opener.call_count, net.HTTP_RETRIES)

    def test_retry_after_is_honoured(self):
        waits: list[float] = []
        error = http_error(429, {"Retry-After": "3"})
        with mock.patch("vigil.net.open_url", side_effect=error), \
                mock.patch("time.sleep", side_effect=waits.append), \
                self.assertRaises(FetchError):
            net.fetch("https://a.test/x")
        self.assertEqual(waits, [3.0, 3.0])


class TestRedirectPolicy(unittest.TestCase):
    def setUp(self):
        self.handler = net.SafeRedirectHandler()

    def test_same_origin_keeps_headers(self):
        request = urllib.request.Request("https://a.test/x", headers={"Authorization": "Bearer t"})
        new = self.handler.redirect_request(request, None, 302, "Found", {}, "https://a.test/y")
        self.assertEqual(new.headers.get("Authorization"), "Bearer t")

    def test_cross_origin_get_strips_custom_headers(self):
        request = urllib.request.Request(
            "https://a.test/x",
            headers={"Authorization": "Bearer t", "User-Agent": "test"},
        )
        new = self.handler.redirect_request(request, None, 302, "Found", {}, "https://b.test/y")
        self.assertIsNone(new.headers.get("Authorization"))
        self.assertIsNotNone(new.headers.get("User-agent"))

    def test_https_downgrade_rejected(self):
        request = urllib.request.Request("https://a.test/x")
        with self.assertRaises(urllib.error.HTTPError):
            self.handler.redirect_request(request, None, 302, "Found", {}, "http://a.test/x")

    def test_cross_origin_post_rejected(self):
        request = urllib.request.Request("https://a.test/x", data=b"payload")
        with self.assertRaises(urllib.error.HTTPError):
            self.handler.redirect_request(request, None, 307, "Found", {}, "https://b.test/y")

    def test_http_to_https_upgrade_allowed(self):
        request = urllib.request.Request("http://a.test/x")
        new = self.handler.redirect_request(request, None, 301, "Moved", {}, "https://a.test/x")
        self.assertEqual(new.full_url, "https://a.test/x")


class TestOrigin(unittest.TestCase):
    def test_invalid_port(self):
        with self.assertRaises(FetchError):
            net._origin("https://a.test:99999/x")

    def test_default_ports(self):
        self.assertEqual(net._origin("https://a.test/x"), ("https", "a.test", 443))
        self.assertEqual(net._origin("http://a.test/x"), ("http", "a.test", 80))


class TestDecodeCorruption(unittest.TestCase):
    """一个坏字节不能把整篇 UTF-8 变成另一种编码的乱码。"""

    TEXT = "这是一个包含中文的安全公告标题，用于测试编码嗅探的健壮性。" * 3

    def _corrupted(self) -> bytes:
        raw = self.TEXT.encode("utf-8")
        return raw[:10] + b"\xff" + raw[11:]

    def test_declared_utf8_with_one_bad_byte_stays_readable(self):
        text = net.decode_bytes(self._corrupted(), "utf-8")
        self.assertIn("这是一个", text)
        self.assertIn("健壮性", text)
        self.assertLessEqual(text.count("\ufffd"), 3)

    def test_undeclared_utf8_with_one_bad_byte_stays_readable(self):
        text = net.decode_bytes(self._corrupted())
        self.assertIn("这是一个", text)
        self.assertIn("健壮性", text)
        self.assertLessEqual(text.count("\ufffd"), 3)

    def test_lying_utf8_declaration_falls_back_to_gbk(self):
        """声明 UTF-8、实际是 GBK 时，坏字节很多，必须继续尝试 GBK。"""
        raw = self.TEXT.encode("gbk")
        self.assertEqual(net.decode_bytes(raw, "utf-8"), self.TEXT)


class TestDeflateIntegrity(unittest.TestCase):
    def test_truncated_stream_is_a_decode_error(self):
        raw = zlib.compress(b"abc" * 1000)
        with self.assertRaises(DecodeError):
            net._decompress(raw[:20], "deflate", None)

    def test_trailing_garbage_is_ignored(self):
        raw = zlib.compress(b"abc") + b"garbage"
        self.assertEqual(net._decompress(raw, "deflate", None), b"abc")


class TestRetryAfterDate(unittest.TestCase):
    def test_http_date_is_converted_to_seconds(self):
        value = formatdate(time.time() + 30, usegmt=True)
        wait = net.retry_after({"Retry-After": value})
        assert wait is not None
        self.assertGreater(wait, 20)
        self.assertLessEqual(wait, 30)

    def test_past_http_date_is_zero(self):
        value = formatdate(time.time() - 30, usegmt=True)
        self.assertEqual(net.retry_after({"Retry-After": value}), 0.0)

    def test_garbage_is_none(self):
        self.assertIsNone(net.retry_after({"Retry-After": "soon"}))


class TestRedirectHeaders(unittest.TestCase):
    def test_same_host_https_upgrade_keeps_headers(self):
        handler = net.SafeRedirectHandler()
        request = urllib.request.Request("http://a.test/x", headers={"Authorization": "Bearer t"})
        new = handler.redirect_request(request, None, 301, "Moved", {}, "https://a.test/x")
        self.assertEqual(new.headers.get("Authorization"), "Bearer t")

    def test_cross_host_still_strips_headers(self):
        handler = net.SafeRedirectHandler()
        request = urllib.request.Request("http://a.test/x", headers={"Authorization": "Bearer t"})
        new = handler.redirect_request(request, None, 301, "Moved", {}, "https://b.test/x")
        self.assertIsNone(new.headers.get("Authorization"))


class TestPrivateHost(unittest.TestCase):
    def test_fetch_refuses_private_host(self):
        with mock.patch("vigil.net.open_url") as opener, \
                self.assertRaises(FetchError) as ctx:
            net.fetch("http://127.0.0.1/feed")
        opener.assert_not_called()
        self.assertIn("私网", str(ctx.exception))

    def test_escape_hatch_allows_private_host(self):
        response = FakeResponse(b"ok")
        with mock.patch.dict("os.environ", {"VIGIL_ALLOW_PRIVATE_HOSTS": "1"}), \
                mock.patch("vigil.net.open_url", lambda *a, **k: response):
            self.assertEqual(net.fetch("http://127.0.0.1/feed").text, "ok")


class TestFetchBudget(unittest.TestCase):
    def test_budget_exhausted_during_backoff_is_not_a_failure(self):
        """等不起退避时这一轮没检查完，应报预算跳过，而不是记成抓取失败。"""
        error = http_error(503)
        with mock.patch("vigil.net.open_url", side_effect=error) as opener, \
                self.assertRaises(BudgetExceeded):
            net.fetch("https://a.test/x", deadline=time.monotonic() + 0.5)
        self.assertEqual(opener.call_count, 1)

    def test_error_message_reports_real_attempts(self):
        error = http_error(503)
        with mock.patch("vigil.net.open_url", side_effect=error) as opener, \
                mock.patch("time.sleep"), self.assertRaises(FetchError) as ctx:
            net.fetch("https://a.test/x")
        self.assertIn(f"已尝试 {opener.call_count} 次", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
