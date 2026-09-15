# 三个 GitHub 事故机制复现报告 v0.1

## 结论

已在隔离环境中完成三个事故的确定性机制复现。11 项回归检查全部通过；测试只使用虚构数据和临时目录，没有安装或运行原项目，也没有接触生产系统或真实隐私数据。

这份结果证明：本地夹具能够稳定重现三个事故的关键状态转换，并能区分事故行为、上游修复行为和本项目提出的额外门禁。它不证明原项目在当前版本中仍有缺陷，也不证明知识污染防火墙已经安全。

## 范围决定

| 决定 | 来源 | 状态 |
|---|---|---|
| 不运行原项目，改做隔离环境中的机制级忠实复刻 | 用户选择 | 人工确认 |
| 使用虚构状态、临时 Git 仓库和确定性 Agent 替身 | AI实现方案 | 已实现，待用户评审 |
| 保留原 Gold Set，不用新复现覆盖旧版本 | AI风险控制 | 已执行 |

## 复现结果

### 1. OpenViking #4193：同一记忆出现两个版本

原始依据：[Issue #4193](https://github.com/volcengine/OpenViking/issues/4193)、[修复 PR #4206](https://github.com/volcengine/OpenViking/pull/4206)

已复现：

- 使用同一 `page_id` 更新已有记忆；
- Markdown 显示 `Bob / completed / 2026-09-10`；
- 结构字段仍保存 `Alice / open / 2026-09-08`；
- 提交成功且没有异常；
- 之前不存在的 `REPLACE` 字段仍可新增；
- 错误筛选同时影响 `REPLACE` 和 `SUM`，但不影响 `PATCH`；
- 修复后只有 `IMMUTABLE` 保留旧值，结构字段与 Markdown 恢复一致。

关键判断：这不是普通“旧知识没删除”，而是**同一条记忆内部的展示层与结构层分裂**。

### 2. Hermes Agent #2670：旧会话在后台覆盖当前记忆

原始依据：[Issue #2670](https://github.com/NousResearch/hermes-agent/issues/2670)、[修复 PR #2687](https://github.com/NousResearch/hermes-agent/pull/2687)

已复现：

- 旧会话快照记录 revision 1：负责人 Alice；
- 当前记忆 revision 2：负责人 Bob，并含新 canary；
- `session_reset`、`inactivity_timeout`、`gateway_restart` 三种触发器均让旧快照覆盖当前记忆；
- 覆盖静默完成，Bob 被回退为 Alice，canary 消失；
- 上游合并方案的两个行为被单独复刻：cron 会话跳过 flush、当前 MEMORY/USER 状态注入 prompt；
- 本项目额外实现硬 revision 门禁：候选基于 revision 1、当前为 revision 2 时直接拒绝写入。

关键判断：上游修复主要增加模型可见上下文，仍属于**提示级缓解**；硬 revision 校验是本项目方案，不能冒充上游已经实现。

### 3. Hermes Agent #17164：陈旧记忆压过 Git 与磁盘事实

原始依据：[Issue #17164](https://github.com/NousResearch/hermes-agent/issues/17164)、[相关修复 PR #28583](https://github.com/NousResearch/hermes-agent/pull/28583)

已复现：

- 临时 Git 仓库中的代码、状态文档和测试结果证明 Phase A 已完成；
- 较旧 session recall 声称 Phase A 未开始、项目约完成 90%、bridge 文件损坏；
- 不安全路径先相信 recall，错误报告状态，并在核验基线前改写 `STATUS.md` 和 `hermes_bridge.py`；
- 安全路径依次检查 Git、磁盘、代码和测试，将旧 recall 标为陈旧来源；
- 状态发现阶段文件哈希完全不变；确认基线后，继续工作从 Phase B 开始；
- 当测试失败或工作区状态未解决时，写入门禁保持关闭；
- `0xe3` 被解析为 code tag 加 reference flag，因此仅凭首字节不能证明损坏。

关键判断：相关上游 PR 主要把 recalled memory 从“权威”降为“可能过期的信息”，并补充部分测试；它不等于 issue 中提出的完整强制基线协议。

## 自动检查结果

```text
OpenViking #4193                    3/3 通过
Hermes Agent #2670                 4/4 通过
Hermes Agent #17164                4/4 通过
合计                              11/11 通过
原有 20 条 Gold Set 本地校验          通过
```

## 忠实度边界

### 原始来源事实

只把 GitHub issue 与已合并 PR 明确记载的行为称为来源事实。

### AI构造的受控模拟

- Alice、Bob、日期、Phase A/B 和所有文件内容均为虚构；
- Agent 行为由确定性代码代替真实模型，以保证每次都能复现；
- Git 仓库只存在于系统临时目录，运行结束自动清理；
- `0xe3` 测试只证明“首字节本身不足以判定损坏”，没有伪装成真实 `.pyc` 跨版本加载测试。

### 未复现内容

- OpenViking 的真实抽取模型、数据库和完整 Memory V2 调用链；
- Hermes Gateway、systemd、Telegram/Discord、两机并发和真实模型随机性；
- #17164 涉及的真实私有项目、真实路径和生产文件。

## 可重复运行

```bash
python3 -m unittest discover -s tests -p 'test_incident_reproductions.py' -v
python3 -m incident_reproductions.run_all
```

实现说明位于 `incident_reproductions/README.md`。三项复现相互隔离，失败夹具不会污染安全夹具；运行输出可作为后续 Baseline、Single-Agent、Multi-Agent 的统一事故输入。

## 重新打开条件

以下任一情况出现时建立 v0.2，不覆盖本版本：

- GitHub issue 或修复 PR 出现新的官方证据；
- 当前模拟漏掉了影响事故成立的必要触发条件；
- 实际模型接入后无法产生与确定性夹具等价的写入候选；
- 回归测试无法稳定复现事故行为或修复行为；
- 用户决定转为安装原项目、锁定原版本的产品级复现。
