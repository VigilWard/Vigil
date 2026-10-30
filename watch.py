#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vigil —— 无服务器版漏洞情报守望

设计前提：本机长期关机。所以这个脚本不常驻，由外部定时器（GitHub Actions
的 cron）每隔几分钟唤醒一次，拉取 - 过滤 - 推送 - 退出。

数据源：
  1. CISA KEV        已被确认在野利用的漏洞（信噪比最高）
  2. oss-security    公开披露主战场
  3. 自定义 RSS/Atom 你关心的项目公告

推送：飞书群机器人 / 钉钉群机器人，二选一或都开。

本地试跑：python watch.py
环境变量：FEISHU_WEBHOOK / FEISHU_SECRET / DINGTALK_WEBHOOK / DINGTALK_SECRET
首次运行只记录基线、不推送，避免把历史条目一次性糊你一脸。
"""

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
STATE_FILE = BASE / "state.json"
CONFIG_FILE = BASE / "config.json"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_ALERTS = "https://www.cisa.gov/cybersecurity-advisories/alerts.xml"
OSS_RSS = "https://seclists.org/rss/oss-sec.rss"
UA = "Vigil/1.0 (personal security feed)"
CST = timezone(timedelta(hours=8))
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def log(msg):
    if sys.stdout is not None:
        try:
            print(time.strftime("[%H:%M:%S] ") + msg, flush=True)
        except Exception:
            pass


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {"boot": False, "kev_since": "", "seen_kev": [], "seen_feed": []}


def save_state(st):
    st["seen_kev"] = st.get("seen_kev", [])[-800:]
    st["seen_feed"] = st.get("seen_feed", [])[-800:]
    STATE_FILE.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {}


def get_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def get_text(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def strip_html(s, limit=220):
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = re.sub(r"[-=_]{4,}", " ", s)   # 去掉 ==== / ---- 这类分隔线
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def parse_feed(xml_text):
    """兼容 RSS 2.0 和 Atom，返回 [(id, title, link, 时间戳, 摘要)]"""
    out = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        log("  XML 解析失败：%s" % e)
        return out

    def text_of(node, tags):
        for tag in tags:
            el = node.find(tag)
            if el is not None and (el.text or "").strip():
                return el.text.strip()
        return ""

    items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")
    for it in items[:40]:
        title = text_of(it, ["title", "{http://www.w3.org/2005/Atom}title"])
        link = text_of(it, ["link"])
        if not link:
            el = it.find("{http://www.w3.org/2005/Atom}link")
            if el is not None:
                link = el.get("href", "")
        guid = text_of(it, ["guid", "{http://www.w3.org/2005/Atom}id"]) or link or title
        desc = strip_html(text_of(it, ["description", "summary",
                                       "{http://www.w3.org/2005/Atom}summary"]))
        # 去掉 "Posted by 某某 on Oct 29" 这类元信息，它占掉三分之一的篇幅
        desc = re.sub(r"^Posted by .{0,80}?\bon\b [A-Z][a-z]{2} \d{1,2}\s*", "", desc)
        date_s = text_of(it, ["pubDate", "published", "updated", "{http://www.w3.org/2005/Atom}updated"])
        ts = 0
        if date_s:
            try:
                dt = parsedate_to_datetime(date_s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ts = int(dt.timestamp())
            except (TypeError, ValueError):
                try:
                    ts = int(datetime.fromisoformat(date_s.replace("Z", "+00:00")).timestamp())
                except ValueError:
                    ts = 0
        out.append((guid, title, link, ts, desc))
    return out


def feishu_sign(secret, timestamp):
    s = "%s\n%s" % (timestamp, secret)
    digest = hmac.new(s.encode("utf-8"), digestmod=hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def dingtalk_sign(secret, timestamp):
    s = "%s\n%s" % (timestamp, secret)
    digest = hmac.new(secret.encode("utf-8"), s.encode("utf-8"), hashlib.sha256).digest()
    return urllib.parse.quote_plus(base64.b64encode(digest))


def post_json(url, payload):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json; charset=utf-8",
                                 "User-Agent": UA}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, r.read(400).decode("utf-8", "replace")


def push(title, lines):
    """返回是否至少有一个通道成功；没有任何通道时打印内容（dry-run）"""
    text = title + "\n" + "\n".join(lines) if lines else title
    ok = False
    sent_any = False

    hook = os.environ.get("FEISHU_WEBHOOK") or os.environ.get("feishu_webhook")
    if hook:
        sent_any = True
        payload = {"msg_type": "text", "content": {"text": text}}
        secret = os.environ.get("FEISHU_SECRET") or os.environ.get("feishu_secret")
        if secret:
            ts = str(int(time.time()))
            payload["timestamp"] = ts
            payload["sign"] = feishu_sign(secret, ts)
        try:
            status, body = post_json(hook, payload)
            ok = status == 200 and '"code":0' in body.replace(" ", "")
            log("  飞书 HTTP %s %s" % (status, body[:120]))
        except Exception as e:
            log("  飞书推送失败：%s" % e)

    hook = os.environ.get("DINGTALK_WEBHOOK") or os.environ.get("dingtalk_webhook")
    if hook:
        sent_any = True
        url = hook
        secret = os.environ.get("DINGTALK_SECRET") or os.environ.get("dingtalk_secret")
        if secret:
            ts = str(round(time.time() * 1000))
            sep = "&" if "?" in url else "?"
            url = "%s%stimestamp=%s&sign=%s" % (url, sep, ts, dingtalk_sign(secret, ts))
        try:
            status, body = post_json(url, {"msgtype": "text", "text": {"content": text}})
            ok = status == 200 and '"errcode":0' in body.replace(" ", "")
            log("  钉钉 HTTP %s %s" % (status, body[:120]))
        except Exception as e:
            log("  钉钉推送失败：%s" % e)

    if not sent_any:
        log("⚠ 没有配置 webhook，下面是把本该发出去的内容：")
        log("--- 8< ---\n%s\n--- 8< ---" % text)
        return True
    return ok


def collect_kev(st, lines, items):
    try:
        data = get_json(KEV_URL)
    except Exception as e:
        log("  KEV 拉取失败：%s" % e)
        return
    vulns = data.get("vulnerabilities", [])
    log("  KEV 共 %d 条，本地基线 %s" % (len(vulns), st.get("kev_since") or "无"))
    seen = set(st.get("seen_kev", []))
    fresh = [v for v in vulns if v.get("dateAdded", "") >= (st.get("kev_since") or "")
             and v.get("cveID") not in seen]
    fresh.sort(key=lambda v: v.get("dateAdded", ""))
    for v in fresh:
        st.setdefault("seen_kev", []).append(v.get("cveID", ""))
    for v in fresh[-10:]:
        cve = v.get("cveID", "")
        tag = "勒索团伙在用" if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else "已确认在野利用"
        lines.append("· %s %s %s（%s）" % (cve, v.get("vendorProject", ""), v.get("product", ""), tag))
        items.append(cve)
    if fresh:
        st["kev_since"] = max(v.get("dateAdded", "") for v in fresh) or st.get("kev_since", "")


def collect_feed(name, url, st, window_hours=48):
    lines, items = [], []
    try:
        raw = get_text(url)
    except Exception as e:
        log("  %s 拉取失败：%s" % (name, e))
        return lines, items
    entries = parse_feed(raw)
    seen = set(st.get("seen_feed", []))
    cutoff = int(time.time()) - window_hours * 3600
    fresh = [e for e in entries if e[0] not in seen and (e[3] == 0 or e[3] >= cutoff)]
    log("  %s 共 %d 条，新增 %d 条" % (name, len(entries), len(fresh)))
    # 全部标记为已见，避免下一轮重复推送；消息里最多列 12 条
    for e in fresh:
        st.setdefault("seen_feed", []).append(e[0])
    shown = fresh[:12]
    for guid, title, link, _, desc in shown:
        # 标题里已有的 CVE 号不再重复加，只把"标题里看不出来"的补到前面
        cves = [c for c in dict.fromkeys(CVE_RE.findall(title + " " + desc))
                if c not in title]
        head = "· " + (" ".join(cves[:4]) + "　" if cves else "") + title[:80]
        if desc and desc.lower()[:40] not in title.lower():
            lines.append("%s\n  %s\n  %s" % (head, desc[:150], link))
        else:
            lines.append("%s\n  %s" % (head, link))
        items.append(guid)
    if len(fresh) > len(shown):
        lines.append("…另有 %d 条，见 %s" % (len(fresh) - len(shown), url))
    return lines, items


def main():
    st = load_state()
    cfg = load_config()
    boot = not st.get("boot")

    lines, items = [], []
    boot_ok = True

    if cfg.get("kev_json", False):
        log("检查 CISA KEV 全量 JSON …")
        if boot:
            try:
                data = get_json(KEV_URL)
                dates = [v.get("dateAdded", "") for v in data.get("vulnerabilities", [])]
                st["kev_since"] = max(dates) if dates else ""
                st["seen_kev"] = [v.get("cveID", "") for v in data.get("vulnerabilities", [])
                                  if v.get("dateAdded", "") == st["kev_since"]]
                log("  建立基线，最新 dateAdded = %s" % st["kev_since"])
            except Exception as e:
                log("  基线建立失败：%s（本轮不标记为已初始化，避免下次全量推送）" % e)
                boot_ok = False
        else:
            collect_kev(st, lines, items)

    feeds = [("CISA 警报", CISA_ALERTS, "kev")]
    if cfg.get("oss_security", True):
        feeds.append(("oss-security", OSS_RSS, "feed"))
    for extra in cfg.get("extra_rss", []):
        if extra.get("name") and extra.get("url"):
            feeds.append((extra["name"], extra["url"], "feed"))

    kev_lines, feed_lines = [], []
    window = int(cfg.get("window_hours", 48))
    for name, url, kind in feeds:
        log("检查 %s …" % name)
        got, _ = collect_feed(name, url, st, window_hours=window)
        (kev_lines if kind == "kev" else feed_lines).extend(got)

    if boot:
        # collect_feed 已把本轮全部条目写进 seen_feed，这里不要再加一遍
        if boot_ok:
            st["boot"] = True
            save_state(st)
            log("首次运行：已记录基线（KEV %d 条 + 信息源 %d 条），本轮不推送。"
                % (len(st.get("seen_kev", [])), len(set(st.get("seen_feed", [])))))
        else:
            save_state(st)
            log("首次运行没跑完（KEV 基线未建立），下次再试。")
        return

    kev_all = lines + kev_lines
    if not kev_all and not feed_lines:
        save_state(st)
        log("没有新增，退出。")
        return

    blocks = []
    if kev_all:
        blocks.append("【已确认在野利用】\n" + "\n".join(kev_all))
    if feed_lines:
        blocks.append("【新披露】\n" + "\n".join(feed_lines))

    title = "Vigil｜%s" % datetime.now(CST).strftime("%m-%d %H:%M")
    ok = push(title, blocks)
    save_state(st)
    log("推送%s，本轮 在野利用 %d 条 + 披露 %d 条。"
        % ("成功" if ok else "失败", len(kev_all), len(feed_lines)))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        push("Vigil｜连通性测试", ["如果你在手机上看到这条，说明 webhook 配对了。"])
    else:
        main()
