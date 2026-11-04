# Vigil

把安全公告源的新条目定时推送到飞书。零第三方依赖，跑在 GitHub Actions 上，不需要服务器。

## 特性

- **多源聚合**：RSS / Atom / RDF、任意 JSON API、CISA KEV 目录、nginx 公告页；源全部写在 `config.json`，代码不含内置源
- **只推新的**：`state.json` 记录已送达条目的**内容指纹**，标题/链接/等级变了会当作新版本再推一次
  （摘要不计入指纹——有些源会在摘要里塞浏览量、更新时间，算进去会无限重推）
- **不会丢消息**：推送失败不写基线，条目留在待送达队列，下一轮自动补发；只有飞书确认收到才记账
- **条件请求**：带 `If-None-Match` / `If-Modified-Since`，源没变时走 304，几乎不耗流量
- **一条公告一条消息**：不再把多条塞进同一张卡片。每条按自己的等级上色、带图标和序号，
  高危条目不会被普通条目夹在中间；单轮单目标最多 30 条，超出的留在队列里下一轮优先补发
- **抗折腾**：抓取和推送都有指数退避重试，`Retry-After` 会被尊重（单次等待超过 30 秒就本轮放弃）；
  字符集自动嗅探；状态原子写；整轮有时间预算；单个源的解析器出意外只算这个源失败，不影响其它源
- **按严重度排序**：在野利用 → 严重 → 高危 → 其余，再按时间。先发最要紧的，
  真撞上限流或时间预算时，被截掉的是排在后面的普通条目
- **跨源去重**：同一个 CVE 被不同源同时报到时合并成一条，标注「另见」
- **中文翻译**：英文标题和摘要自动翻成中文，原文各留一行（`【标题原文】` / `【摘要原文】`）；Google 挂了会自动切到 MyMemory，都不需要密钥
- **坏源会主动告警**：连续 3 轮抓取失败/被预算跳过/解析出 0 条会单独推一条状态消息，
  恢复时再通知一次；新接入的源如果一直解析不出条目也会告警，不会静默
- **卡片转义按飞书规范**：动态文本里的 `*` `_` `[` 等换成 HTML 实体（lark_md 不认反斜杠转义），标题不会被吃掉

## 快速开始

1. **Fork / 新建仓库**，把本目录推上去（`config.json` 要一起提交，Actions 需要它）
   - `.github/workflows/watch.yml` 已经带好，不用自己写
2. **开启写权限**：Settings → Actions → General → Workflow permissions → 选 **Read and write permissions**
   - **这一步最容易漏**。新仓库默认是只读，`permissions: contents: write` 也救不回来，
     回写 `state` 分支时会 403
3. **建飞书机器人**：群设置 → 群机器人 → 添加自定义机器人，复制 webhook
   - 如果开了「签名校验」，把密钥也记下来
4. **配 Secrets**：仓库 Settings → Secrets and variables → Actions

   | Secret | 必填 | 说明 |
   | --- | --- | --- |
   | `FEISHU_WEBHOOK` | 是（或 `FEISHU_WEBHOOKS`） | 机器人 webhook 地址 |
   | `FEISHU_SECRET` | 否 | 开启签名校验时才需要 |
   | `FEISHU_WEBHOOKS` | 否 | 要推多个群时用，见下文「推送到多个群」 |

   > 出于安全考虑，webhook 默认只接受 `feishu.cn` / `larksuite.com` 域名。
   > 如果确实要走自建代理，设仓库变量（或本地环境变量）`FEISHU_ALLOW_ANY_HOST=1`。

5. **手动跑一次**：Actions → Vigil → Run workflow，`mode` 选 `test`
   收到测试卡片就说明 webhook、签名和卡片渲染都对了
6. 再跑一次 `run`：这一轮**只建基线不推送**，之后每 10 分钟增量推送

### 上线前自查

- [ ] Workflow permissions 是 **Read and write**（否则第一次回写基线就 403）
- [ ] `FEISHU_WEBHOOK` 配好了，`mode=test` 能收到卡片
- [ ] 第一次 `mode=run` 的日志里有「首次接入，记录基线 N 条（本轮不推送）」
- [ ] 第二轮之后能看到「目标 xxx 第 1/1 条已确认送达」
- [ ] 仓库没给 `state` 分支设分支保护（它靠 force push 覆盖）
- [ ] 跑过旧版本的话，先用 `mode=reset` 重建基线（state v2 与 v1 不兼容）
- [ ] `tests` workflow 的 ruff / mypy / 依赖检查三个 job 都是绿的
- [ ] 想省钱/不想把内容发给第三方的话，把仓库变量 `TRANSLATE` 设成 `0`

## GitHub Actions

仓库里有两个 workflow：

| 文件 | 触发 | 作用 |
| --- | --- | --- |
| `.github/workflows/watch.yml` | 每 10 分钟 + 手动 | 抓取并推送，把基线写回 `state` 分支 |
| `.github/workflows/tests.yml` | push / PR | 在 3.10~3.13 上跑单元测试、检查零第三方依赖、跑 ruff + mypy |

手动运行时 `mode` 有四个选项：`run`（正常一轮）、`test`（只发测试卡片）、
`reset`（清空基线）、`probe`（按线上顺序探测各个翻译源是否可达）。

几个刻意的设计：

- **`permissions: contents: write`**：回写 `state` 分支需要写权限，其他权限一律不开。
- **取回基线失败就中止**：`git ls-remote` 先判断 `state` 分支到底存不存在。真的拉取失败时
  直接让这一步红掉，而不是当成「还没有分支」——否则会拿空基线跑一轮，再由回写步骤覆盖，
  待送达队列就永久没了。
- **`concurrency: vigil-state`**：同一时刻只允许一轮在跑。两轮并发会互相覆盖 `state.json`，
  结果就是同一条消息推两遍。
- **基线回写用 `if: always()`**：推送失败（退出码 1）时也要把队列写回去，否则待送达条目会丢。
  但 `取回基线` 失败时这一步会被跳过（`steps.fetch_state.outcome == 'success'`），不会误覆盖。
- **`state` 分支是孤立提交 + force push**：分支上永远只有一个快照，不随运行次数膨胀。
- **每周心跳**：公开仓库连续 60 天没有提交会被停掉定时任务。即使这段时间没有任何新条目，
  每 7 天也会强制写一次 `state.json`，保证 cron 不被回收。
- **消息间隔 0.25 秒**：飞书自定义机器人限流 5 次/秒，一条一条连续发 + 多群很容易撞上 `11232`。

> `state` 分支是**公开可读**的。待送达条目会带着标题和摘要存在里面，
> 已送达条目的 `seen` 键里也可能带 uid（没有 guid/id 时会退化成链接或标题），
> 加了内部/付费源的话，请注意这一点。

## 配置

```json
{
  "window_hours": 48,
  "max_items": 8,
  "sources": [
    {
      "name": "CISA KEV",
      "kind": "kev",
      "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      "limit": 8
    },
    {
      "name": "oss-security",
      "url": "https://seclists.org/rss/oss-sec.rss",
      "limit": 4
    }
  ]
}
```

顶层字段：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `window_hours` | 48 | 只关心这个时间窗内的新条目，避免补推远古内容 |
| `max_items` | 12 | 每个源每轮最多推几条；超出的留在队列里顺延到下一轮 |

每个源：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `name` | 是 | 消息里显示的名字，不能重复；最多 80 个字符 |
| `url` | 是 | 仅支持 `http` / `https`，不能带用户名密码；默认拒绝本机/私网地址 |
| `kind` | 否 | `rss`（默认，含 Atom / RDF）/ `kev` / `json` / `nginx` |
| `exploited` | 否 | 标记该源条目为「已确认在野利用」。**只有你能确认时才开** |
| `limit` | 否 | 覆盖全局 `max_items`（1~50） |
| `headers` | 否 | 自定义请求头，值支持 `${VIGIL_环境变量}` |
| `match` | 否 | 正则，只保留**标题**命中的条目 |
| `json` | `kind=json` 时必填 | 字段映射，见下文；除 `path` 外不能留空 |

> 新增的源第一次运行只记录基线、不推送，避免刚接入就被历史条目刷屏。

> `kev` 类型的条目天然带「在野利用」标记，不需要再写 `exploited`。

> 默认拒绝 `127.0.0.1`、`10.0.0.0/8` 这类本机/私网地址，避免配置误指内网。
> 确实要抓内网源时设 `VIGIL_ALLOW_PRIVATE_HOSTS=1`。
> 云元数据地址（`169.254.0.0/16`、`100.100.100.200`、`fd00:ec2::254`、
> `metadata.google.internal` 等）是例外：**不受这个开关影响，始终拒绝**。
> 这个开关只对"本来就在内网"的源生效：内网源自己的跳转（http→https、换 canonical 主机名）
> 会放行；公网源试图跳到内网仍然一律拦截。

### 关于 CISA

别用 `cisa.gov/cybersecurity-advisories/alerts.xml` 这个 RSS：标题几乎全是
"CISA Adds Two Known Exploited Vulnerabilities to Catalog"，真正受影响的厂商和产品都在正文里，
推出来是一堆看起来一模一样的消息。用 KEV 的 JSON 目录，每条都能精确到 `厂商 产品：漏洞名`。

## 加一个新的数据源

分三档，绝大多数情况落在前两档，**不用改代码**。

### 一、RSS / Atom —— 只加配置

90% 的安全站都提供 RSS：

```json
{ "name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "limit": 6 }
```

实测可直接用：SANS ISC、MSRC 更新指南、CISA 全部公告、oss-security。

常用的官方源：

| 目标 | 订阅地址 | kind | 备注 |
| --- | --- | --- | --- |
| PHP | `https://www.php.net/feed.atom` | `rss` | 混着版本发布，用 `"match": "advisory|security"` 过滤 |
| Linux 内核 | `https://lore.kernel.org/linux-cve-announce/new.atom` | `rss` | 标题形如 `CVE-xxxx: 子系统: 描述` |
| Debian | `https://www.debian.org/security/dsa-long` | `rss` | 名字像纯文本，其实是 RSS 1.0 (RDF) |
| Ubuntu | `https://ubuntu.com/security/notices/rss.xml` | `rss` | 必须带 `.xml` |
| NGINX | `https://nginx.org/en/security_advisories.html` | `nginx` | 没有 RSS，走专用解析 |

### 二、JSON API —— 加配置 + 字段映射

`kind` 填 `json`，用 `json` 描述字段怎么取。键支持 `a.b.c` 路径和数组下标：

```json
{
  "name": "GitHub 安全公告",
  "kind": "json",
  "url": "https://api.github.com/advisories?per_page=20",
  "json": {
    "path": "",
    "id": "ghsa_id",
    "title": "summary",
    "link": "html_url",
    "summary": "description",
    "date": "published_at",
    "cve": "cve_id"
  }
}
```

| 映射键 | 默认 | 说明 |
| --- | --- | --- |
| `path` | 空=根节点 | 指向数组的路径，如 `data.items`；根节点本身就是数组时留空 |
| `id` | `id` | 唯一标识，没写会退回 `link`、再退回 `title` |
| `title` | `title` | 标题 |
| `link` | `link` | 详情页地址 |
| `summary` | `summary` | 摘要，会自动截断 |
| `date` | `date` | 时间，RFC822 / ISO8601 / `YYYY-MM-DD` / 时间戳都能认 |
| `cve` | 空 | 专门放 CVE 号的字段，会和标题摘要里抓到的合并去重 |

需要鉴权的接口把 token 放仓库 Secrets，配置里用 `${VIGIL_变量名}` 引用，**不会出现在公开的 config.json 里**：

```json
{
  "name": "厂商私有 API",
  "kind": "json",
  "url": "https://vendor.example/api/advisories",
  "headers": { "Authorization": "Bearer ${VIGIL_VENDOR_TOKEN}" },
  "json": { "title": "name", "link": "url", "date": "published" }
}
```

> **只允许 `${VIGIL_*}` 前缀。** `config.json` 是公开提交的，如果任意变量都能引用，
> 一个"新增数据源"的 PR 就能用 `${FEISHU_SECRET}` 把机器人密钥拼进 URL 或请求头。
> 变量名不带 `VIGIL_` 前缀会直接报配置错误。记得同时在 workflow 的 `env:` 里把它暴露出来，
> 例如 `VIGIL_VENDOR_TOKEN: ${{ secrets.VIGIL_VENDOR_TOKEN }}`。

### 三、特殊格式 —— 加一个解析函数

既不是 RSS 也不是规整 JSON 时，才需要动代码。在 `vigil/parse.py` 里加函数并注册：

```python
def parse_mysource(text, source):
    items = []
    for row in text.splitlines():
        ...
        item = build_item(source, uid=..., title=..., link=..., published=parse_time(...),
                          summary=..., cves=_cves(...))
        if item:
            items.append(item)
    return items

PARSERS = {"rss": parse_rss, "kev": parse_kev, "json": parse_json,
           "nginx": parse_nginx, "mysource": parse_mysource}   # ← 加这一行
```

`build_item()` 会统一做清洗、截断、CVE 抽取和等级推断。结构不对时抛 `ParseError`，
源名会出现在飞书消息头，详细错误在 CI 日志里，而不是静默吞掉。

### 加源之前先自测

```bash
python watch.py --dry-run
```

它会按你的真实基线算出「下一轮会推什么」并完整打印，不发送、不改基线。
队列里上一轮没送达的条目也会一起列出来（会额外打一行提示）。
源抓取失败或被预算跳过时，预览也会逐条打印「⚠ …」；即使本轮没有可推送条目，
这些提示也不会被省略。

判断标准很简单：如果标题看起来都一样、或者没有链接，这个源就不值得加。

### 踩过的坑

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `HTTP 403` | 站点按 UA 拦爬虫 | 在 `headers` 里换成常见浏览器 UA |
| 订阅地址 404 | 官方地址改名了 | Debian 用 `dsa-long`；Ubuntu 要带 `rss.xml` |
| `返回的是网页而不是订阅源` | 被 WAF 拦 | 换官方 API，或放弃该源 |
| 标题全是同一句话 | 「汇总型」公告不适合直接推 | 换结构化源（CISA 用 KEV JSON） |
| feed 里混着版本发布 | 官方把发布和安全放在同一个 feed | 用 `match` 只留 `advisory|security` |
| 新加的源推了一堆历史条目 | 该源在你的基线里是全新的 | 已自动处理：首次接入只记基线 |

## 推送到多个群

在 Secrets 里加 `FEISHU_WEBHOOKS`，支持 JSON 数组或逗号/换行分隔：

```json
[
  "https://open.feishu.cn/open-apis/bot/v2/hook/aaa",
  { "webhook": "https://open.feishu.cn/open-apis/bot/v2/hook/bbb", "secret": "签名密钥" }
]
```

每条消息会分别推给每个群，并**按群分别记账**：A 群收到了、B 群失败，下一轮只会补发 B 群。
源状态告警同样按群记账——B 群漏掉的那条告警会在下一轮单独补给它，A 群不会重复收到。

只配了 `FEISHU_WEBHOOK`（单个群）也完全等价；两个都配时 `FEISHU_WEBHOOKS` 优先，
但如果它解析出 0 个目标（例如留了个 `[]`），会自动回落到 `FEISHU_WEBHOOK`。

## 中文翻译

英文源的标题和摘要会自动翻成中文，原文各保留一行（`【标题原文】` / `【摘要原文】`）。
默认两个源都**不需要 key、不需要账号、不需要任何配置**，可选加一个百度：

| 顺序 | 源 | 说明 |
| --- | --- | --- |
| 1 | Google `translate_a/single` | 译文最准；但从数据中心 IP（GitHub runner 就在 Azure 机房）请求时经常被 429。超时特意只给 3 秒，不通时每轮只白等 6 秒左右 |
| 2 | 百度通用翻译 | **可选**，配了 `BAIDU_APPID` / `BAIDU_KEY` 才启用。不会被机房 IP 挡，中文质量也稳；标准版 QPS=1，所以两次请求间隔 1.2 秒 |
| 3 | MyMemory `api.mymemory.translated.net` | 社区翻译记忆库，质量一般但很稳；单次上限 500 字符 |

不配百度也能跑（自动跳过），配了就夹在 Google 和 MyMemory 之间；只配一半（只有 APPID 没有密钥）会被忽略。

**自动降级**：某个源连续失败 2 次，本轮就不再碰它，直接用下一个。全部失败时退化成英文原文，
绝不阻塞推送。日志里会写明切换过程：

```
⚠ 翻译源 google 失败：<urlopen error timed out>
   翻译源：mymemory
```

> **隐私提醒**：开了翻译，所有标题和摘要都会发往第三方。源里可能有内部/付费内容时，
> 把 `TRANSLATE` 设成 `0` 可以彻底关掉——消息照发，只是保持英文原文。

- 一条标题 + 一条摘要 = 2 个请求；两次请求间隔 0.3 秒，每轮最多 100 次
- 只翻**新条目**，没有新条目就不发请求；待送达队列里缺译文的条目会在后续轮次补齐一次
- CVE 编号、产品名、版本号一般会保留原文（机器翻译对专有名词弱，看到翻歪的属正常）
- **翻译失败不影响推送**：拿不到译文就用英文原文照发；连续 2 条翻不出来会放弃本轮
- `--dry-run` 也会翻译，方便先看效果

这些免费接口随时可能改参数、限流或关掉。所以接法是"可选、可关、可换"：

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `TRANSLATE` | `1` | 设成 `0` 关闭翻译 |
| `BAIDU_APPID` / `BAIDU_KEY` | 空 | 百度通用翻译的凭据，放 **Secrets**；配了会排在 Google 之后、MyMemory 之前 |
| `TRANSLATE_ENDPOINT` | `https://translate.googleapis.com/translate_a/single` | 换 Google 的镜像或代理时用 |
| `TRANSLATE_EMAIL` | 空 | 传给 MyMemory 的 `de` 参数，把匿名配额从 5 千提到 5 万字符/天 |

### 探测翻译链路

想确认这些接口在你的网络里能不能用：

```bash
python tools/check_translate.py            # 按线上顺序逐个探测
python tools/check_translate.py "some text"
```

或者在 Actions 里 Run workflow、`mode` 选 `probe`——这一步从 GitHub 的 runner 发起，
能反映**线上真实网络**的情况（你本地被墙不代表线上不通，反之亦然）。

脚本会逐个源打印译文、耗时、CVE 编号是否保留，以及失败原因（网络阻断 / 限流 / 返回格式变了），
最后给出「线上会用哪个源」的结论。`tools/` 里三个脚本各有用途：`check_translate.py` 是诊断、
`preview_cards.py` 生成样式预览、`check_stdlib.py` 是 CI 的依赖守卫（删了会让 CI 红）。

## 运行行为

**退出码**

| 码 | 含义 |
| --- | --- |
| 0 | 这一轮该做的都做完了（个别源抖动、已成功告警的持续故障也算完成） |
| 1 | 有消息没送达 / 没配 webhook 但有待送达 / 状态告警没发出去 |
| 2 | 配置或状态文件不合法 |

也就是说：**Actions 变红代表"有人需要看一眼"**，而不是"某个源抖了一下"。
源持续故障会通过飞书告警（首次 + 每 6 小时一次 + 恢复通知），不会让 CI 红三天。
故障类型切换（例如「抓取失败」变成「持续空内容」）有 1 小时的最小间隔。源在两种故障之间
反复横跳时，每次切换都能绕过 6 小时节流，实测能刷到 2 条/小时；加闸后降到 0.7 条/小时。

**时间预算**

整轮最多 520 秒，抓取部分最多 300 秒。超过就跳过剩余源，并在消息头写明「本轮未检查：X、Y」。
workflow 的硬超时是 12 分钟，留足了余量。

**推送节奏**

飞书自定义机器人限流是 100 次/分钟、5 次/秒。因为一条公告就是一条消息，消息与消息之间会停 0.25 秒，
限流（业务码 `11232` / `9499`）按指数退避重试；源站或飞书给了 `Retry-After` 就按它等，
但单次等待超过 30 秒时当场放弃这一次请求（没发出去的消息留在队列里下一轮补发，
抓取的源下一轮重新抓取），免得一个慢源吃掉整轮预算。
等不起（超出本轮剩余预算）时同样当场放弃：推送会留下队列，抓取则记成「本轮跳过」，
不会累积成源故障、触发假告警。

> 配了多个群时，飞书收到的请求数是「条数 × 群数」。超过 4 个群的话，把 `max_items`
> 或各源的 `limit` 调小一些，别让一轮的请求数顶到 100 次/分钟。

**消息长什么样**

一条公告一张**飞书消息卡片**。头部标题就是公告标题（太长会截断），副标题写源、时间、等级和序号：

```
┌──────────────────────────────────────────────────────┐
│ 🚨 Ivanti Connect Secure Authentication Bypass       │  ← 标题（🚨 = 在野利用）
│ CISA KEV · 10-31 21:50 · 在野利用 · 严重（CVSS 9.8） │  ← 副标题：源 · 时间 · 等级
│ · 第 1/2 条                                          │     序号（多条时才有）
├──────────────────────────────────────────────────────┤
│ 【来源】CISA KEV                                     │
│ 【编号】CVE-2026-11111                               │
│ 【发布时间】2026-11-01 09:15                         │
│ 【标题翻译】**Ivanti Connect Secure 身份认证绕过**   │
│ 【标题原文】Ivanti Connect Secure Auth Bypass        │
│ 【等级】严重（CVSS 9.8）                             │
│ 【标记】已确认在野利用、已知勒索团伙利用             │
│ 【摘要翻译】Ivanti Connect Secure 存在认证绕过…      │
│ 【摘要原文】Ivanti Connect Secure contains an…       │
│ 【链接】https://nvd.nist.gov/vuln/detail/...         │
└──────────────────────────────────────────────────────┘
```

标题前的图标和卡片头部颜色都由**这一条自己的等级**决定，所以普通条目再多也盖不住高危那条：

| 情况 | 标题图标 | 头部颜色 |
| --- | --- | --- |
| 已确认在野利用 | 🚨 | `red` |
| 严重（CVSS 9.0+） | 🔴 | `carmine` |
| 高危 | 🟠 | `orange` |
| 中危 | 🟡 | `blue` |
| 低危 | ⚪ | `blue` |
| 没有等级 | 无 | `blue` |

配色规则（只在三处）：

| 位置 | 颜色 |
| --- | --- |
| 卡片头部 | 见上表，一条一色 |
| `【等级】` | 严重/高危红、低灰、中不着色（飞书卡片只稳定支持红/绿/灰） |
| `【标记】` | 红色 |
| `【标题翻译】` | 加粗 |

字段说明：

| 字段 | 是否总有 | 说明 |
| --- | --- | --- |
| `【来源】` | 总是 | 源名，来自 `config.json` 里的 `name`；转发或截图时也能看出是哪家源 |
| `【编号】` | 有 CVE 时 | 多个编号用「、」连接 |
| `【发布时间】` | 源里能读到发布时间时 | 公告自身的发布时间，统一按**东八区**显示（`YYYY-MM-DD HH:MM`） |
| `【标题翻译】` | 有译文且与原文不同时 | 中文标题，加粗；开头重复的 CVE 号会被剥掉 |
| `【标题原文】` | 总是 | 源里的原标题；没有译文时由它加粗，充当主标题 |
| `【等级】` | 源里能读到等级时 | 「低/中/高/严重」，原文有 CVSS 分数时附带 `（CVSS 9.8）` |
| `【标记】` | 在野利用 / 勒索条目 | 「已确认在野利用」「已知勒索团伙利用」，同时出现时用「、」连接 |
| `【摘要翻译】` | 有译文且与原文不同时 | 最多 300 字，超出以 … 结尾 |
| `【摘要原文】` | 有摘要时 | 最多 300 字，超出以 … 结尾 |
| `【链接】` | 有链接时 | 原文地址，最多 600 字；会剔除 `<` `>` `*` 等能构造标记的字符（`_` `&` 保留，否则链接点不动） |
| `【另见】` | 仅跨源合并时 | 同一个 CVE 还被哪些源报了 |

> 卡片正文预算是 14000 字节（不是 18000）：飞书自定义机器人的请求体上限是 20KB，
> JSON 外壳、字段名和换行转义还要占几 KB。
>
> 源状态告警（`⚠ 某源连续 3 轮失败`）仍然是纯文本消息，不走卡片——它只是提示，不需要排版。
>
> 「等级」只从源自己给出的文字里读（`Severity: high`、`CVSS 3.1: 9.8`），**不会**去查 NVD。
> KEV、Debian、Ubuntu、PHP 这些源本身不带等级，所以它们的条目不会有这一行；
> 等级只用于全局排序（严重的排前面），不影响是否推送。

**消息条数与顺延**

一条公告一条消息，所以一轮里收到几条消息，就是有几条新公告。副标题里的「第 3/12 条」
表示这一轮一共 12 条、这是第 3 条；最后一条如果还有没发完的，会写「另有 N 条顺延到下一轮」。

单轮单目标最多发 30 条（飞书限流兜底）。超过上限、或被每个源的 `limit` 截断的条目
都不会被确认送达，下一轮会重新进入候选——所以只会晚一点，不会丢。

源状态提示（抓取失败 / 本轮未检查）写在**第一条消息的正文最上面**，不额外占一条消息。

## 基线存在哪

`state.json` 存在仓库的 **`state` 分支**里。每次只在内容真的变化时提交，且永远是**一个孤立提交**
（用 `git hash-object` + `mktree` + `commit-tree` 生成），force push 覆盖，所以：

- 主分支始终干净；
- `state` 分支只有一份快照，不会随运行次数膨胀；
- 不需要第二次 clone，也不会把 token 写进 URL。

唯一例外是**每周心跳**：连续 7 天没有任何变化时，会强制写一次 `state.json`，
避免公开仓库因为「60 天无提交」被停掉定时任务。

state 里存的是条目指纹、健康计数和待送达队列。注意 `seen` 的键是 `源标识:uid`：
uid 在源没有 guid/id 时会退化成链接或标题，所以**已送达条目也可能留下链接或标题**，
不是"只留指纹"。待送达条目则会完整保留标题和摘要（否则进程重启后没法补发）。
请记住 `state` 分支是公开的：如果你加了内部/付费源，待送达条目和 uid 都会出现在这个分支上。
内部源建议用 `kind=json` 并指定一个不含敏感信息的 `id` 字段。

> 格式版本是 **v2**。`alert_sent`（按群记账的告警进度）是 v2 里新增的可选字段，
> 缺这个字段的 v2 state 也能正常加载，只是升级后第一轮会重发一次状态告警
>（v1 state 会被版本检查拒绝，需要 reset，见下文）。
> pending 记录里的 `seq`（入队序号）同样是可选字段：无日期源（NGINX）靠它保持
> 队列顺序，缺省为 0，不影响加载。

需要重置时：Actions 里 Run workflow，`mode` 选 `reset`，或在本地 `python watch.py --reset`。
下一轮会逐源重建基线，不会补推历史条目。

## 常见问题

**第一次跑没收到消息？**
正常。第一轮只记基线，第二轮开始才推增量。

**消息里出现「另有 N 条顺延到下一轮」？**
该源超过 `limit`（或全局 `max_items`），或这一轮超过了 30 条的上限。调大即可；
不调也会在后续轮次慢慢发完，而且下一轮会优先发没发出去的那批。

**收到「⚠ 某源抓取失败」？**
这一行出现在**当轮第一条消息的正文最上面**，只在本来就有条目要发时才会带上——没有内容可发时
不会单独为一次失败推一张空卡片（否则一个抖动的源会让你每 10 分钟收一条）。
偶发一次交给重试机制；连续 3 轮都失败会单独推一条状态消息，
之后每 6 小时提醒一次，恢复时再发一条「已恢复」。说明地址变了或被 WAF 拦了。

**收到「⚠ 某源返回空内容」？**
这个源以前有内容，最近连续 3 轮解析出 0 条，通常意味着页面改版了。修好解析后会自动收到「已恢复」。
如果是刚加的新源、一次都没解析出条目，文案会写「接入后连续 3 轮没有解析出任何条目」——
多半是地址写错，或者该源的 `kind` / `match` 配错了。

> 只有**解析出内容**才算「已恢复」：连续失败之后哪怕来了一轮"200 + 0 条"，也不会发恢复通知。

**为什么某条 CVE 显示「另见：oss-security」？**
同一个 CVE 被两个源同时报到，工具合并成了一条，避免你收到两遍。

**为什么高危的总是先收到？**
消息按「在野利用 → 等级 → 时间」排序发出。先发要紧的不只是为了好找：真撞上限流或时间预算，
被截掉的是排在后面的普通条目。

**能不能同一个地址配两个源？**
可以。源的身份由 `url + kind + match` 决定，同一个 feed 用不同的 `match` 就是两个独立的流。

**Actions 定时任务会不会被停用？**
公开仓库连续 60 天无提交会被停掉定时任务。`state` 分支每 7 天会强制留一次心跳提交，
所以通常不会触发；真被停了，手动 Run 一次即可恢复。

**日志里出现「飞书限流：frequency limited」？**
飞书返回业务码 `11232`（或 `9499`）表示限流。工具会退避重试，消息之间也留了间隔；
连续失败时没发出去的消息会留在队列里，下一轮自动补发，不会丢消息。

**为什么消息里看到 `&#42;` 之类的东西？**
正常情况下飞书会把它渲染成 `*`。如果原样显示，说明客户端版本太老——这是飞书官方的转义方式，
`lark_md` 不认反斜杠转义。

**从旧版本升级？**
state 格式与旧版不兼容（只支持一个 `state.json`）。第一次运行会提示版本不兼容，
在 Actions 里用 `reset` 模式跑一次即可，之后会重新建基线（不会补推历史条目）。

当前是 **state v2**：内容指纹的输入变了（摘要不再计入指纹、NGINX 条目改用原始公告链接），
旧指纹会整体失效。所以从 v1 升上来**必须 reset 一次**——否则第一轮会把窗口内的历史条目、
以及全部 NGINX 条目当成新条目重推一遍。

> 从更早的版本升到当前代码时，NGINX 源里以前被跳过的「没有 CVE 的公告」会被当成新条目，
> 按 `limit` 每轮补推几条。不想要这批历史内容的话，升级前先跑一次 `mode=reset` 重建基线。

## 目录结构

```
watch.py                 CLI 入口
vigil/
  models.py              常量、数据类型、异常、日志
  config.py              config.json 校验
  net.py                 HTTP：重试、条件请求、字节上限、安全重定向、编码嗅探
  parse.py               文本清洗 + RSS/KEV/JSON/nginx 解析器
  state.py               基线、内容指纹、待送达队列、原子写
  render.py              消息渲染：一条公告一条消息、等级排序与顺延
  feishu.py              飞书签名、卡片封装与推送
  collect.py             抓取编排与跨源合并
  translate.py           标题/摘要英译中（Google / 百度 / MyMemory 自动降级，可选）
  app.py                 命令行与一轮运行的编排
tests/                   单元测试 + 端到端状态机测试
  test_regressions.py    按缺陷归档的回归用例（编码损坏、预算耗尽、多群记账等）
  test_tools.py          tools/ 脚本的行为（依赖检查忽略虚拟环境等）
  support.py             测试共用的小工具（FakeResponse / http_error）
tools/
  check_translate.py     诊断：按顺序探测每个翻译源
  check_stdlib.py        CI 守卫：确认没有引入第三方依赖
  preview_cards.py       生成样式预览（preview/cards.html，不发送任何消息）
.github/workflows/
  watch.yml              定时抓取 + 回写 state 分支
  tests.yml              单元测试 + 依赖检查 + ruff/mypy
config.json              实际使用的源配置（会公开提交）
config.example.json      配置模板
pyproject.toml           ruff / mypy 配置（CI 会跑，不属于运行时依赖）
state.json               Actions 运行时生成，勿提交（已在 .gitignore）
```

## 本地运行

```bash
python watch.py --dry-run     # 抓一遍并打印消息，不发、不改基线
python watch.py --test        # 只发一条测试消息
python watch.py               # 正常跑一轮
python watch.py --reset       # 清空基线，下一轮重新建基线
python -m unittest discover -s tests -v

python tools/preview_cards.py # 生成样式预览：preview/cards.html
```

需要 Python 3.10+，**运行时**零第三方依赖。`FEISHU_WEBHOOK` / `FEISHU_SECRET` 从环境变量读，
本地可以直接 export。

想在本地复现 CI 的静态检查（这两样只是开发期工具，不进运行时）：

```bash
pip install "ruff==0.17.3" "mypy==2.4.1"
python -m ruff check .
python -m mypy
```

## License

MIT
