# 三个 GitHub 事故的隔离机制复现

本目录使用虚构数据和确定性代码，复刻三个公开事故的关键状态转换。它不会安装或运行 OpenViking、Hermes Agent、systemd、真实模型或任何生产系统。

## 运行

```bash
python3 -m unittest discover -s tests -p 'test_incident_reproductions.py' -v
python3 -m incident_reproductions.run_all
```

第二条命令只在临时目录中创建虚构 Git 仓库，结束后自动清理。

## 来源事实与模拟边界

### OpenViking #4193

- 原始来源：[Issue #4193](https://github.com/volcengine/OpenViking/issues/4193)、[修复 PR #4206](https://github.com/volcengine/OpenViking/pull/4206)
- 来源事实：已有 `REPLACE` 字段在更新前被旧值覆盖；Markdown 已更新而结构字段仍旧；提交成功且不报错；此前不存在的 `REPLACE` 字段仍可新增。
- 本地复现：同一 page_id、旧值与新值、四种 merge op、事故结果和修复结果。
- 未声称复现：OpenViking 的抽取模型、存储后端与完整调用栈。

### Hermes Agent #2670

- 原始来源：[Issue #2670](https://github.com/NousResearch/hermes-agent/issues/2670)、[修复 PR #2687](https://github.com/NousResearch/hermes-agent/pull/2687)
- 来源事实：会话重置、过期或网关重启会触发临时 flush agent；旧对话可能覆盖较新的 MEMORY.md；合并修复跳过 cron 会话，并把当前 MEMORY.md/USER.md 注入 flush prompt。
- 本地复现：三个触发器、旧对话快照、新记忆、canary 丢失、上游提示级修复，以及本项目提出的硬 revision 门禁。
- 未声称复现：真实 gateway、Telegram/Discord、两机并发和具体模型随机行为。

### Hermes Agent #17164

- 原始来源：[Issue #17164](https://github.com/NousResearch/hermes-agent/issues/17164)、[相关修复 PR #28583](https://github.com/NousResearch/hermes-agent/pull/28583)
- 来源事实：陈旧 recall 被当作权威，导致错误项目状态、无依据的损坏判断和基线核验前写文件；期望流程要求 Git、磁盘、测试优先并标注来源。
- 本地复现：独立临时 Git 仓库、已完成代码与测试、相冲突的旧记忆、不安全写入路径、强制基线与 fail-closed 路径。
- 未声称复现：原私有项目内容、Hermes 模型推理或真实运行时文件。

## 三类输出必须区分

- `source fact`：GitHub issue 或已合并 PR 明确记载的事实。
- `controlled simulation`：为本项目构造的虚构状态和确定性行为。
- `firewall proposal`：硬 revision 门禁、来源排序与 fail-closed 等本项目设计，不冒充上游已经实现。

