"""config.json 的校验行为。"""
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from vigil.config import load_config
from vigil.models import ConfigError


class ConfigCase(unittest.TestCase):
    def _write(self, payload) -> Path:
        handle = TemporaryDirectory()
        self.addCleanup(handle.cleanup)
        path = Path(handle.name) / "config.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    def _load(self, payload):
        return load_config(self._write(payload))

    def _rejects(self, payload, fragment: str = ""):
        with self.assertRaises(ConfigError) as ctx:
            self._load(payload)
        if fragment:
            self.assertIn(fragment, str(ctx.exception))
        return ctx.exception


class TestTopLevel(ConfigCase):
    def test_minimal(self):
        config = self._load({"sources": [{"name": "a", "url": "https://a.test/1"}]})
        self.assertEqual(len(config.sources), 1)
        self.assertEqual(config.window_hours, 48)
        self.assertEqual(config.max_items, 12)

    def test_sources_required(self):
        self._rejects({"feeds": [{"name": "a", "url": "https://a.test/1"}]}, "未知字段")

    def test_empty_sources(self):
        self._rejects({"sources": []}, "非空")

    def test_unknown_top_key(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test"}], "windw_hours": 1}, "未知字段")

    def test_window_bounds(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test"}], "window_hours": 0})
        self._rejects({"sources": [{"name": "a", "url": "https://a.test"}], "window_hours": "很多"})
        self._rejects({"sources": [{"name": "a", "url": "https://a.test"}], "window_hours": True})

    def test_max_items_bounds(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test"}], "max_items": 51})


class TestSource(ConfigCase):
    def test_name_is_normalized(self):
        config = self._load({"sources": [{"name": "  多  空格  ", "url": "https://a.test"}]})
        self.assertEqual(config.sources[0].name, "多 空格")

    def test_duplicate_name_rejected(self):
        self._rejects({"sources": [
            {"name": "同名", "url": "https://a.test/1"},
            {"name": "同名", "url": "https://b.test/2"},
        ]}, "重复")

    def test_duplicate_identity_rejected(self):
        self._rejects({"sources": [
            {"name": "a", "url": "https://a.test/1", "match": "x"},
            {"name": "b", "url": "https://a.test/1", "match": "x"},
        ]}, "身份相同")

    def test_same_url_different_match_is_allowed(self):
        config = self._load({"sources": [
            {"name": "a", "url": "https://a.test/1", "match": "security"},
            {"name": "b", "url": "https://a.test/1", "match": "release"},
        ]})
        self.assertNotEqual(config.sources[0].key, config.sources[1].key)

    def test_bad_scheme(self):
        self._rejects({"sources": [{"name": "a", "url": "file:///etc/passwd"}]}, "http/https")

    def test_credentials_in_url_rejected(self):
        self._rejects({"sources": [{"name": "a", "url": "https://user:pass@a.test/1"}]}, "用户名")

    def test_invalid_port_rejected_early(self):
        # 以前能通过校验，然后在 fetch 里抛 ValueError
        self._rejects({"sources": [{"name": "a", "url": "https://a.test:99999/1"}]}, "url")

    def test_bad_kind(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test", "kind": "html"}]}, "kind")

    def test_bad_match_regex(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test", "match": "([a-z"}]}, "正则")

    def test_exploited_must_be_bool(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test", "exploited": "true"}]}, "布尔")

    def test_limit_bounds(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test", "limit": 0}], "max_items": 5}, "limit")

    def test_unknown_source_key(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test", "ttl": 1}]}, "未知字段")

    def test_control_chars_in_url_rejected(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test/\nfoo"}]}, "控制字符")

    def test_control_chars_in_name_rejected(self):
        self._rejects({"sources": [{"name": "a\x00b", "url": "https://a.test"}]}, "控制字符")


class TestJsonMapping(ConfigCase):
    def test_json_kind_requires_mapping(self):
        self._rejects({"sources": [{"name": "a", "url": "https://a.test", "kind": "json"}]}, "json")

    def test_json_on_other_kind_rejected(self):
        self._rejects({"sources": [
            {"name": "a", "url": "https://a.test", "kind": "rss", "json": {"title": "x"}}
        ]}, "kind=json")

    def test_unknown_mapping_key(self):
        self._rejects({"sources": [
            {"name": "a", "url": "https://a.test", "kind": "json", "json": {"nmae": "x"}}
        ]}, "未知字段")

    def test_mapping_accepted(self):
        source = self._load({"sources": [
            {"name": "a", "url": "https://a.test", "kind": "json",
             "json": {"path": "data", "title": "name"}}
        ]}).sources[0]
        self.assertEqual(source.mapping["path"], "data")


class TestEnvExpansion(ConfigCase):
    def test_headers_expanded(self):
        payload = {"sources": [{
            "name": "a", "url": "https://a.test/1",
            "headers": {"Authorization": "Bearer ${VIGIL_TEST_VENDOR_TOKEN}"}}]}
        with mock.patch.dict(os.environ, {"VIGIL_TEST_VENDOR_TOKEN": "s3cret"}):
            source = self._load(payload).sources[0]
        self.assertEqual(source.headers["Authorization"], "Bearer s3cret")

    def test_url_expanded(self):
        payload = {"sources": [{"name": "a", "url": "${VIGIL_TEST_FEED_URL}"}]}
        with mock.patch.dict(os.environ, {"VIGIL_TEST_FEED_URL": "https://a.test/1"}):
            self.assertEqual(self._load(payload).sources[0].url, "https://a.test/1")

    def test_missing_env_rejected(self):
        payload = {"sources": [{"name": "a", "url": "https://a.test/1",
                                "headers": {"Authorization": "Bearer ${VIGIL_NOT_SET_ANYWHERE}"}}]}
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VIGIL_NOT_SET_ANYWHERE", None)
            with self.assertRaises(ConfigError):
                self._load(payload)

    def test_other_prefix_is_rejected(self):
        """配置不能引用工具自身的密钥（FEISHU_SECRET / BAIDU_KEY 等）。"""
        payload = {"sources": [{"name": "a", "url": "https://a.test/1",
                                "headers": {"X-Token": "${FEISHU_SECRET}"}}]}
        with mock.patch.dict(os.environ, {"FEISHU_SECRET": "leak"}), \
                self.assertRaises(ConfigError) as ctx:
            self._load(payload)
        self.assertIn("VIGIL_", str(ctx.exception))


class TestFile(unittest.TestCase):
    def test_missing_file(self):
        with self.assertRaises(ConfigError):
            load_config(Path("does-not-exist.json"))

    def test_broken_json(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


class TestPrivateHosts(ConfigCase):
    def test_private_address_is_rejected(self):
        for url in ("http://127.0.0.1/feed", "http://10.0.0.1/feed",
                    "http://localhost/feed"):
            with self.subTest(url=url):
                with self.assertRaises(ConfigError) as ctx:
                    self._load({"sources": [{"name": "a", "url": url}]})
                self.assertIn("私网", str(ctx.exception))

    def test_escape_hatch_allows_private_address(self):
        with mock.patch.dict(os.environ, {"VIGIL_ALLOW_PRIVATE_HOSTS": "1"}):
            config = self._load({"sources": [{"name": "a", "url": "http://127.0.0.1/feed"}]})
        self.assertEqual(len(config.sources), 1)

    def test_metadata_addresses_stay_rejected_with_escape_hatch(self):
        """逃生门是给内网源用的；元数据地址连它也不该放行，提示不能误导。"""
        for url in ("http://169.254.169.254/latest", "http://instance-data/feed",
                    "http://100.100.100.200/latest"):
            with self.subTest(url=url), \
                    mock.patch.dict(os.environ, {"VIGIL_ALLOW_PRIVATE_HOSTS": "1"}):
                self._rejects({"sources": [{"name": "a", "url": url}]}, "云元数据")

    def test_fullwidth_localhost_is_rejected(self):
        """IDNA 会把全角主机名映射成 localhost，配置阶段就要拦住。"""
        self._rejects({"sources": [{"name": "a", "url": "http://ｌｏｃａｌｈｏｓｔ/feed"}]},
                      "私网")


class TestJsonMappingValidation(ConfigCase):
    def test_empty_mapping_value_is_rejected(self):
        """留空会退化成 dig(row, "")，把整行 JSON dump 成标题。"""
        with self.assertRaises(ConfigError) as ctx:
            self._load({"sources": [{
                "name": "a", "url": "https://a.test", "kind": "json",
                "json": {"title": "", "id": "id"},
            }]})
        self.assertIn("json.title", str(ctx.exception))

    def test_empty_path_is_allowed(self):
        config = self._load({"sources": [{
            "name": "a", "url": "https://a.test", "kind": "json",
            "json": {"path": "", "title": "name"},
        }]})
        self.assertEqual(config.sources[0].mapping["path"], "")


if __name__ == "__main__":
    unittest.main()
