"""tools/ 下脚本的行为。"""
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent.parent
CHECK_STDLIB = ROOT / "tools" / "check_stdlib.py"
PREVIEW_CARDS = ROOT / "tools" / "preview_cards.py"


class TestCheckStdlib(unittest.TestCase):
    """依赖检查必须只看项目代码，不能被本地虚拟环境带偏。"""

    def _run(self, files: dict[str, str]) -> subprocess.CompletedProcess:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tools").mkdir()
            (root / "tools" / "check_stdlib.py").write_text(
                CHECK_STDLIB.read_text(encoding="utf-8"), encoding="utf-8")
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return subprocess.run(
                [sys.executable, "tools/check_stdlib.py"],
                cwd=root, capture_output=True, text=True, timeout=60,
            )

    def test_virtualenv_is_ignored(self):
        result = self._run({
            "vigil/a.py": "import os\n",
            ".venv/lib/demo.py": "import requests\n",
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_third_party_import_is_reported(self):
        result = self._run({"vigil/a.py": "import requests\n"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("requests", result.stdout)

    def test_syntax_error_is_reported(self):
        result = self._run({"vigil/a.py": "def broken(:\n"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("语法错误", result.stdout)


class TestPreviewCards(unittest.TestCase):
    """预览脚本不在 CI 的关键路径上，但它 import 了真实的渲染链路，必须能跑通。"""

    def test_preview_generates_html(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "cards.html"
            result = subprocess.run(
                [sys.executable, str(PREVIEW_CARDS), str(out)],
                cwd=ROOT, capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            html = out.read_text(encoding="utf-8")
        self.assertIn("Vigil 推送样式预览", html)
        self.assertIn("Vigil 测试消息", html)     # sample_message 走真实 render_item
        self.assertIn("另有", html)               # 顺延提示确实渲染出来了


if __name__ == "__main__":
    unittest.main()
