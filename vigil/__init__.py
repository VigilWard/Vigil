"""Vigil：安全公告增量抓取与飞书推送。

模块地图（这里刻意不做 re-export：项目是应用而不是库，没人 `from vigil import Item`，
再维护一份 __all__ 只会让"改了模块忘了改导出"变成新的故障点）：

    models.py     常量、数据类型、异常、日志
    config.py     config.json 校验
    net.py        HTTP：重试、条件请求、字节上限、安全重定向、编码嗅探
    parse.py      文本清洗 + RSS/KEV/JSON/nginx 解析器
    state.py      基线、内容指纹、待送达队列、原子写
    render.py     消息渲染与字节分页
    feishu.py     飞书签名、卡片封装与推送
    collect.py    抓取编排与跨源合并
    translate.py  标题/摘要英译中（Google 免费接口，可选）
    app.py        命令行与一轮运行的编排

用法：`python watch.py [--dry-run|--test|--reset]`，或直接 `from vigil.app import main`。
"""
