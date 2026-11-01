#!/usr/bin/env python3
"""生成推送样式预览：把真实的 compose() 输出渲染成 HTML，看效果而不用真发到群里。

用法：
    python tools/preview_cards.py            # 写到 preview/cards.html
    python tools/preview_cards.py out.html

内容全部走 vigil 的真实代码路径（render.compose / feishu.card_of / app.sample_page），
所以预览里看到什么，飞书里就是什么。颜色值取自飞书客户端的近似值。
"""
from __future__ import annotations

import html as html_mod
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vigil.app import build_alerts, sample_page  # noqa: E402
from vigil.feishu import card_of  # noqa: E402
from vigil.models import (  # noqa: E402
    CST,
    MAX_CARD_BODY_BYTES,
    Config,
    Failure,
    Item,
    Source,
)
from vigil.render import compose  # noqa: E402
from vigil.state import State  # noqa: E402

# 飞书卡片头部模板色的近似值
HEAD_COLORS = {
    "red": "#f54a45",
    "carmine": "#bb1f3a",
    "orange": "#ff8800",
    "blue": "#3370ff",
}

NOW = int(datetime(2026, 11, 1, 22, 30, tzinfo=CST).timestamp())


# ------------------------------------------------------------------ lark_md → HTML

def lark_to_html(text: str) -> str:
    """把卡片正文转成等价 HTML。

    正文里只有我们自己生成的 <font> 和 ** 是真正的标记，用户文本里的
    < > * _ 已经在 escape_md 里换成了 HTML 实体，所以先把标记换成占位符，
    整体转义后再还原。
    """
    text = text.replace("<font color='red'>", "\x01R\x01")
    text = text.replace("<font color='grey'>", "\x01G\x01")
    text = text.replace("</font>", "\x01Z\x01")
    text = re.sub(r"\*\*(.+?)\*\*", "\x01B\x01\\1\x01b\x01", text, flags=re.S)
    text = html_mod.escape(text)
    # 还原飞书风格的实体（&#42; → *），交给浏览器解码
    text = re.sub(r"&amp;#(\d+);", r"&#\1;", text)
    text = text.replace("&amp;amp;", "&amp;").replace("&amp;sim;", "~")
    text = text.replace("\x01R\x01", '<span class="c-red">')
    text = text.replace("\x01G\x01", '<span class="c-grey">')
    text = text.replace("\x01Z\x01", "</span>")
    text = text.replace("\x01B\x01", "<b>").replace("\x01b\x01", "</b>")
    return text


def render_card(page, note: str, code: str) -> str:
    card = card_of(page, page.template)
    head = card["header"]
    title = html_mod.escape(head["title"]["content"])
    subtitle = html_mod.escape(head.get("subtitle", {}).get("content", ""))
    body = "\n".join(
        element["text"]["content"] for element in card["elements"] if element.get("text")
    )
    color = HEAD_COLORS.get(page.template, HEAD_COLORS["blue"])
    sub_html = f'<div class="card-sub">{subtitle}</div>' if subtitle else ""
    body_html = lark_to_html(body) if body else ""
    return f"""
    <figure class="demo">
      <figcaption><b>{note}</b><code>{html_mod.escape(code)}</code></figcaption>
      <div class="card">
        <div class="card-head" style="background:{color}">
          <div class="card-title">{title}</div>
          {sub_html}
        </div>
        <div class="card-body">{body_html}</div>
      </div>
    </figure>"""


def render_text_message(text: str, note: str) -> str:
    return f"""
    <figure class="demo">
      <figcaption><b>{note}</b><code>send(text)</code></figcaption>
      <div class="text-msg">{html_mod.escape(text)}</div>
    </figure>"""


# ------------------------------------------------------------------ 演示数据

def build_demo():
    kev = Source("CISA KEV", "https://www.cisa.gov/kev.json", kind="kev", limit=8)
    oss = Source("oss-security", "https://seclists.org/rss/oss-sec.rss", limit=4)
    debian = Source("Debian DSA", "https://www.debian.org/security/dsa-long", limit=3)
    ubuntu = Source("Ubuntu USN", "https://ubuntu.com/security/notices/rss.xml", limit=3)
    nginx = Source("NGINX", "https://nginx.org/en/security_advisories.html", kind="nginx", limit=2)
    config = Config([kev, oss, debian, ubuntu, nginx], max_items=8)

    def item(source, uid, **kwargs):
        base = {"source_key": source.key, "source_name": source.name, "uid": uid,
                "title": "", "link": "", "published": NOW, "summary": ""}
        base.update(kwargs)
        return Item(**base)

    exploited = item(
        kev, "CVE-2026-11111",
        title="Ivanti Connect Secure Authentication Bypass Vulnerability",
        title_zh="Ivanti Connect Secure 身份认证绕过",
        link="https://nvd.nist.gov/vuln/detail/CVE-2026-11111",
        summary="Ivanti Connect Secure contains an authentication bypass that allows a "
                "remote attacker to access restricted resources.",
        summary_zh="Ivanti Connect Secure 存在身份认证绕过漏洞，远程攻击者无需凭据即可访问受限资源。",
        cves=("CVE-2026-11111",), exploited=True, ransomware=True, severity=4, cvss=9.8,
    )

    critical = item(
        oss, "CVE-2026-118636",
        title="CVE-2026-118636: Apache MINA: Unsafe Deserialization (CWE-502)",
        title_zh="Apache MINA：JavaNativeMessageDecoder 不安全反序列化",
        link="https://seclists.org/oss-sec/2026/q4/457",
        summary="Severity: critical CVSS 3.1: 9.8. Affected versions: Apache MINA 3.0.0-M1 through 3.0.0-M2.",
        summary_zh="严重程度：critical，CVSS 3.1 评分 9.8。受影响版本：Apache MINA 3.0.0-M1 至 3.0.0-M2。",
        cves=("CVE-2026-118636",), severity=4, cvss=9.8,
        also=("CISA KEV",),
    )

    high = item(
        debian, "DSA-6599-1",
        title="DSA-6599-1 nss - security update",
        link="https://lists.debian.org/debian-security-announce/2026/msg00518.html",
        summary="It was discovered that several eMudhra intermediate CA certificates have been compromised.",
        summary_zh="发现多个 eMudhra 中间 CA 证书已被攻破，更新后的 nss 包移除了相关根证书。",
        severity=3, cvss=8.1,
    )

    medium = item(
        nginx, "CVE-2026-15176",
        title="Buffer overflow when using alias with rewrite",
        link="https://my.f5.com/manage/s/article/K000162416",
        summary="Not vulnerable: 1.31.7+；Vulnerable: 0.1.29-1.31.6",
        summary_zh="不受影响：1.31.7+；受影响：0.1.29-1.31.6",
        cves=("CVE-2026-15176",), severity=2, cvss=5.3,
    )

    low = item(
        ubuntu, "USN-7001-1",
        title="USN-7001-1: curl regression",
        link="https://ubuntu.com/security/notices/USN-7001-1",
        summary="A regression was found in the previous curl update.",
        summary_zh="上一次 curl 更新引入了一处回归问题。",
        severity=1, cvss=2.1,
    )

    plain = item(
        ubuntu, "USN-7002-1",
        title="USN-7002-1: tinyproxy update",
        link="https://ubuntu.com/security/notices/USN-7002-1",
        summary="A new tinyproxy version is available.",
        summary_zh="tinyproxy 发布了新版本。",
    )

    minimal = item(
        oss, "no-cve-note",
        title="Moderator note: list downtime on Nov 3",
        link="",
    )

    return config, {"exploited": exploited, "critical": critical, "high": high,
                    "medium": medium, "low": low, "plain": plain, "minimal": minimal}


def build_multipage(config: Config):
    """单独造一个"条目多到要分页"的源，limit 放大会展示 50 条、隐藏 10 条。"""
    source = Source("批量源", "https://example.test/bulk", limit=50)
    bulk_config = Config([source], max_items=50)
    items = []
    for index in range(60):
        items.append(Item(
            source_key=source.key, source_name=source.name, uid=f"bulk-{index}",
            title=f"第 {index + 1} 条批量公告：某组件存在内存越界",
            link=f"https://example.test/advisory/{index}",
            published=NOW - index * 60,
            summary="这段摘要故意写得很长，用来把卡片撑到三页。" * 12,
            cves=(f"CVE-2026-{20000 + index}",), severity=(index % 5),
        ))
    return bulk_config, items


# ------------------------------------------------------------------ HTML

TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigil 推送样式预览</title>
<style>
  :root {{
    --bg:#f2f3f5; --card:#fff; --text:#1f2329; --sub:#646a73; --line:#dee0e3;
    --blue:#3370ff; --red:#f54a45; --grey:#8f959e;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; padding:32px 20px 64px; background:var(--bg); color:var(--text);
    font:14px/1.6 -apple-system, "PingFang SC", "Microsoft YaHei", "Segoe UI", sans-serif;
  }}
  .wrap {{ max-width:860px; margin:0 auto; }}
  h1 {{ font-size:22px; margin:0 0 8px; }}
  .lede {{ color:var(--sub); margin:0 0 24px; }}
  .lede code, figcaption code {{ font:12px/1.4 ui-monospace, Consolas, monospace;
    background:#e9ebef; border-radius:4px; padding:1px 5px; color:#4e5969; }}
  h2 {{ font-size:16px; margin:36px 0 4px; }}
  .h2sub {{ color:var(--sub); font-size:13px; margin:0 0 14px; }}
  .demo {{ margin:0 0 22px; }}
  figcaption {{ font-size:12px; color:var(--sub); margin:0 0 8px; display:flex;
    gap:8px; align-items:center; flex-wrap:wrap; }}
  figcaption b {{ color:var(--text); font-size:13px; }}
  .card {{ background:var(--card); border-radius:12px; overflow:hidden;
    box-shadow:0 1px 3px rgba(31,35,41,.12); }}
  .card-head {{ padding:12px 16px; color:#fff; }}
  .card-title {{ font-size:16px; font-weight:600; line-height:1.4; }}
  .card-sub {{ font-size:12px; opacity:.85; margin-top:2px; }}
  .card-body {{ padding:14px 16px 16px; white-space:pre-wrap; word-break:break-word;
    font-size:14px; line-height:1.75; }}
  .c-red {{ color:var(--red); }}
  .c-grey {{ color:var(--grey); }}
  .text-msg {{ background:var(--card); border-radius:8px; padding:12px 14px;
    white-space:pre-wrap; max-width:560px; box-shadow:0 1px 3px rgba(31,35,41,.12); }}
  table {{ border-collapse:collapse; width:100%; font-size:13px; background:#fff;
    border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(31,35,41,.08); }}
  th, td {{ text-align:left; padding:8px 12px; border-bottom:1px solid var(--line); }}
  th {{ background:#f7f8fa; font-weight:600; }}
  tr:last-child td {{ border-bottom:none; }}
  .swatch {{ display:inline-block; width:10px; height:10px; border-radius:2px;
    margin-right:6px; vertical-align:middle; }}
  .note {{ color:var(--sub); font-size:12px; margin-top:10px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Vigil 推送样式预览</h1>
  <p class="lede">
    下面每一张卡片都是 <code>render.compose()</code> + <code>feishu.card_of()</code> 的真实输出，
    只是把 lark_md 渲染成了等价 HTML。颜色为飞书客户端模板色的近似值。
  </p>

  <h2>一、四种头部配色</h2>
  <p class="h2sub">由本轮最严重的内容决定：在野利用 → 红，严重 → 胭脂红，高危 → 橙，其余 → 蓝。</p>
  {cards}

  <h2>二、分页与顺延</h2>
  <p class="h2sub">单页正文上限 14000 字节，单轮最多 3 页；放不下的条目留在队列，下一轮继续。</p>
  {multipage}

  <h2>三、源异常提示</h2>
  <p class="h2sub">抓取失败、被时间预算跳过的源会写在卡片最上面，不占条目的位置。</p>
  {failures}

  <h2>四、纯文本状态告警</h2>
  <p class="h2sub">源连续 3 轮失败/为空才发，恢复时再发一条。这类消息不走卡片。</p>
  {alerts}

  <h2>五、测试消息</h2>
  <p class="h2sub">Actions 里 <code>mode=test</code> 发出的卡片，用来验证 webhook 与渲染链路。</p>
  {testcard}

  <h2>六、字段规则速查</h2>
  <table>
    <tr><th>字段</th><th>何时出现</th><th>样式</th></tr>
    <tr><td>【编号】</td><td>有条目带 CVE 时</td><td>多个用「、」连接，纯文本</td></tr>
    <tr><td>【标题】</td><td>总是</td><td>加粗；开头重复的 CVE 号会被剥掉</td></tr>
    <tr><td>【原文】</td><td>有译文且与原文不同</td><td>纯文本</td></tr>
    <tr><td>【等级】</td><td>源里能读到等级时</td><td>严重/高危红、低灰、中不着色，有分数时附 CVSS</td></tr>
    <tr><td>【标记】</td><td>仅 KEV 的勒索条目</td><td>红色「已知勒索团伙利用」</td></tr>
    <tr><td>【摘要】</td><td>有摘要时</td><td>最多 300 字，超出以 … 结尾</td></tr>
    <tr><td>【链接】</td><td>有链接时</td><td>最多 600 字</td></tr>
    <tr><td>【另见】</td><td>跨源合并时</td><td>同一 CVE 还被哪些源报了</td></tr>
  </table>
  <p class="note">
    头部四色：<span class="swatch" style="background:#f54a45"></span>red
    <span class="swatch" style="background:#bb1f3a;margin-left:12px"></span>carmine
    <span class="swatch" style="background:#ff8800;margin-left:12px"></span>orange
    <span class="swatch" style="background:#3370ff;margin-left:12px"></span>blue
  </p>
</div>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    out = Path(argv[0]) if argv else Path("preview/cards.html")

    config, demo = build_demo()
    budget = MAX_CARD_BODY_BYTES   # 和 _deliver 用的预算一致，预览才有意义

    cards = []
    cards.append(render_card(
        compose(config, [demo["exploited"]], NOW, budget=budget)[0],
        "在野利用 + 勒索标记", 'card_template() == "red"'))
    cards.append(render_card(
        compose(config, [demo["critical"]], NOW, budget=budget)[0],
        "严重漏洞，跨源合并（含【另见】）", 'card_template() == "carmine"'))
    cards.append(render_card(
        compose(config, [demo["high"]], NOW, budget=budget)[0],
        "高危", 'card_template() == "orange"'))
    cards.append(render_card(
        compose(config, [demo["medium"], demo["low"], demo["plain"], demo["minimal"]],
                NOW, budget=budget)[0],
        "中 / 低 / 无等级 / 只有标题", 'card_template() == "blue"'))

    bulk_config, bulk = build_multipage(config)
    bulk_pages = compose(bulk_config, bulk, NOW, budget=budget)
    multipage = render_card(
        bulk_pages[-1],
        f"共 {len(bulk_pages)} 页，这里看最后一页（含顺延提示）",
        "compose(...)[-1]")

    failures = render_card(
        compose(config, [demo["medium"]], NOW, budget=budget,
                failures=[Failure("oss-security", "k1", "HTTP 403")],
                skipped=[Failure("Ubuntu USN", "k2", "整轮时间预算不足")])[0],
        "有源抓取失败 / 被跳过", "compose(failures=..., skipped=...)")

    state = State()
    broken = state.health(config.sources[1].key)
    broken.fail = 4
    recovered = state.health(config.sources[3].key)
    # 恢复通知只发给"确实收到过告警"的目标，所以预览里也要把记账补上
    recovered.alert = "fail"
    recovered.alert_sent = {"*": "fail"}
    alerts = build_alerts(config, state, NOW)
    alerts_html = render_text_message("\n".join(a.text for a in alerts),
                                      "连续失败 + 已恢复，合并成一条")

    testcard = render_card(sample_page(), "测试消息", "app.sample_page()")

    html = TEMPLATE.format(cards="".join(cards), multipage=multipage,
                           failures=failures, alerts=alerts_html, testcard=testcard)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"已生成 {out}（{len(html)} 字节）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
