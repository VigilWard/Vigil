"""Vigil：安全公告增量抓取与飞书推送。

模块地图（这里刻意不做 re-export：项目是应用而不是库，没人 `from vigil import Item`，
再维护一份 __all__ 只会让"改了模块忘了改导出"变成新的故障点）：

    models.py     常量、共享数据类型（Item/Source/Message 等）、异常、日志
    config.py     config.json 校验
    net.py        HTTP：重试、条件请求、字节上限、安全重定向、编码嗅探、URL 安全校验
    parse.py      文本清洗 + RSS/KEV/JSON/nginx 解析器
    scoring.py    CVSS 分数与严重等级提取
    state.py      基线、内容指纹、待送达队列、原子写
    render.py     单条公告 → 消息正文（字段排版、转义、链接净化）
    digest.py     跨源合并、排序限额、副标题与头部配色（若干条目 → 若干消息）
    feishu.py     飞书签名、卡片封装与推送
    alerts.py     源健康告警的判定、分块与按目标记账
    targets.py    飞书 webhook 目标解析与校验
    collect.py    抓取编排：逐源调度、健康记账、去重、翻译、入队
    translate.py  标题/摘要英译中（Google / 百度 / MyMemory 自动降级，可选）
    app.py        命令行、一轮运行的编排与送达

用法：`python watch.py [--dry-run|--test|--reset]`，或直接 `from vigil.app import main`。
"""
