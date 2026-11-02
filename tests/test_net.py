"""HTTP 层：字节上限、编码嗅探、条件请求与重定向策略。"""
import gzip
import io
import unittest
import urllib.error
import urllib.request
from typing import Any
from unittest import mock

from vigil import net
from vigil.models import FetchError, NotModified


class FakeResponse:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None, status: int = 200):
        self._body = io.BytesIO(body)
        self.headers: dict[str, str] = headers or {}
        self.status = status

    def read(self, size=None):
        return self._body.read(size)

    def getheaders(self):
        return list(self.headers.items())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(code: int, headers: Any = None) -> urllib.error.HTTPError:
    # 第 4 个参数官方类型是 email.message.Message，但 dict 在运行期一样能用；
    # 用 Any 免掉测试里的类型噪音
    return urllib.error.HTTPError("https://a.test/x", code, "err",
                                  headers or {}, io.BytesIO(b""))  # type: ignore[arg-type]


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


if __name__ == "__main__":
    unittest.main()
