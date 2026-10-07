# 受控对比 v0.3

本目录实现 `outputs/评测协议_v0.3_个人AI长期记忆.md` 的产品轨。
v0.1、v0.2、冻结结果和 Gold 标签均未修改。

## 本版边界

- Baseline：确定性规则，0 次模型调用。
- Single：1 次结构化模型调用，规则持有最终写入权。
- Multi：明确 `deny` 先规则短路（0 次模型调用）；其余先复用 Single，只有命中升级条件时才增加 2 个审查者和 1 个仲裁者，单候选最多 4 次调用。
- 只保存一份不可变 `patch`；规则设置 `destination=none/sandbox/production`。
- 测试 `permit` 只写入 `test-only/<case_id>` 内存沙盒，永不进入生产记忆。
- 网络、超时、模型缺失或合同错误默认 `hold`。
- 每次模型调用发送前先预留输入估算与最大输出；已发出但无可靠用量回执的调用记为费用未知，不视为免费。
- v0.3 百炼传输层每次只发一次 HTTP 请求，禁止适配器内部隐藏重试。
- 每个运行单元完成后立即追加检查点；续跑只重试缺失项和基础设施失败项。

## 文件

- `firewall_v0_3.py`：三态状态机、确定性规则、动作包、不可变 Patch、执行路由、内存事务与回滚证明。
- `compare_v0_3.py`：三架构运行器、条件 Multi、Token 门、检查点、续跑、评分和报告数据。
- `call_budget_v0_3.py`：候选级调用/Token/截止时间预留账本。
- `bailian_adapter_v0_3.py`：单 HTTP 尝试的百炼传输层；旧 v0.2 适配器不改动。
- `config_v0_3.json`：模型、预算、延迟目标和质量门。
- `tests/test_controlled_compare_v0_3.py`：v0.3 免费安全与回归测试。

## v0.4 起点：审计 Trace

v0.4 的第一步是在每个 `run_arm` 结果中新增 `audit_trace`。它不改变
防火墙决策、Patch 准入或执行路由，只把已有运行材料压缩成一个便于调试、
人审和报告展示的观察层。

`audit_trace` 目前汇总：

- 决策链路：规则基线、最终决定、决策权威、审计状态；
- 失败归类：`none / infrastructure / model_contract /
  policy_budget_or_deadline / execution_route`，并标记是否适合续跑；
- Patch 与路由：来源、操作、scope、target、哈希、计划和实际执行结果；
- 模型调用：stage、tokens、latency、cost、request_id；
- 运行成本：成功调用数、总 tokens、费用是否已知、预算账本摘要。

CLI 会同时写完整结果 JSON 和轻量审计 JSONL。也可以显式指定审计输出：

```bash
python3 -m controlled_compare.compare_v0_3 \
  --adapter dry-run \
  --dataset semantic-gold \
  --smoke \
  --audit-output outputs/audit_trace_smoke.jsonl
```

JSONL 每行对应一个 run，只包含 case、arm、可用性和 `audit_trace`，
不会复制完整 `firewall`、模型原始输出或完整调用记录。

这一步对应岗位能力中的 observability / debugging / auditability：真实
AI 系统不能只给出最后答案，还要能解释每一步为什么发生。

## 免费本地验证

运行全部测试：

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

运行 11 个已审查的开发／回归案例：

```bash
python3 -m controlled_compare.compare_v0_3 \
  --adapter dry-run \
  --dataset system-dev
```

运行 20 个语义 Gold 的免费流程验证：

```bash
python3 -m controlled_compare.compare_v0_3 \
  --adapter dry-run \
  --dataset semantic-gold
```

Dry-run 只证明规则、路由和记录流程可运行，不能当作模型成绩或架构选择依据。

## 检查点与续跑

默认检查点按适配器和数据集分开保存到 `outputs/checkpoints/`。如果检查点已存在，运行器会拒绝覆盖；续跑时显式加入：

```bash
python3 -m controlled_compare.compare_v0_3 \
  --adapter dry-run \
  --dataset semantic-gold \
  --resume
```

检查点键包含协议、规则、Prompt、模型和温度，避免把旧模型或 dry-run 记录误当成当前付费结果。

本次白名单修订的规则与 Prompt 版本为 `0.3.1-scope-target`，旧 `0.3`
记录不会复用为新规则的成绩。历史报告保持原样，当前边界验收见
`outputs/v0.3_target_scope_边界回归_2026-09-15.md`。

## 付费保护

Bailian 路径必须显式使用 `--adapter bailian --confirm-paid-run`。首次付费验证应先用 `--smoke`，并使用独立的 v0.3 检查点；本地测试不会读取、显示或保存 API Key。

## Patch 与执行路由

当前安全门只批准或拦截，不改写 Patch，因此使用一个字段：

- `patch`：唯一内容，执行前后用 SHA-256 校验值绑定，防止漂移；
- `destination=none`：不执行；
- `destination=sandbox`：只在隔离内存命名空间执行；
- `destination=production`：仅真实候选满足全部写入条件时才允许。

### target/scope 白名单（用户定义的 A–F 工程边界）

唯一规则定义位于 `firewall_v0_3.py` 的 `SCOPE_TARGET_WHITELIST`：

```python
SCOPE_TARGET_WHITELIST = {
    "personal_long_term_memory": [
        "/fields/summary", "/fields/tags", "/fields/confidence",
    ],
    "test-only": ["/"],
}
```

准入严格按 `scope → target → patch_sha256` 顺序。精确匹配，不接受前缀、
路径归一化、跨 scope 查找或默认 scope。失败立即返回失败步骤并阻止事务。
`validate_patch_admission(patch, expected_sha256)` 返回 `allowed`、`failed_step`、
`reason`、`trace` 和 `hash_verified`；它通过后仍需原有决策、授权和路由条件。
非法位置在防火墙中进入 `hold`（已有 `deny` 保持拒绝），拒绝执行不等于
重新给知识内容标注永久 `deny`。

哈希仍在 `execution.patch_sha256`，由现有 `patch_digest(patch)` 计算；
不把哈希加进 Patch 本体，避免自引用。执行前使用同一份内容快照完成检查与事务。

冻结 Gold 的旧值对象通过适配器显式生成 `scope=test-only, target=/`。
这不是为缺字段的模型输出补值；AI Patch 的缺失或非法字段仍原样阻断。
真实候选的旧值对象适配入口须在 `input.write_context` 明确提供
`patch_scope` 与 `patch_target`；缺失时保留 `None` 并拦截。
`test-only` scope 永远不能取得生产资格。当前评测器也拒绝任何生产执行。

内存沙盒支持根对象 add/replace 和白名单内三个字段的 add/replace/delete。
根 replace 真正替换整个隔离对象；字段操作只改指定字段。字段父对象必须存在，
replace/delete 的目标必须已存在，失败恢复完整快照。

A–F 在 `tests/test_controlled_compare_v0_3.py` 的
`PatchWhitelistBoundaryTests`，与 Gold 第 8/9/11 行无关。
从项目目录单独运行本组边界测试：

```bash
cd "/Users/fyn/Documents/ChatGPT/知识污染防火墙"
python3 -B -m unittest tests.test_controlled_compare_v0_3.PatchWhitelistBoundaryTests -v
```

本组为 A–F 六项加八项相关回归，共 14 项；全项目当前共 79 项。

Gold=`allow` 的测试 Patch 会在沙盒执行并检查内容与落点；拦截案例必须
保持 `none`。若未来安全门开始清洗或改写内容，再增加由规则生成的
`transformed_patch`。

生产路由分三档：低风险满足条件可直接写入；敏感但可存内容必须有独立的
二次人工确认，并绑定 Patch 校验值、字段范围、用途与期限；禁止存储类
始终路由 `none`，人工确认不能绕过。

`hold` 默认保留 30 天。到期不会自动写入，Patch 内容、AI 原始推断、
用户反馈正文和人工确认详情会被清除，只留下最小审计摘要。当前实现提供
“检查到期—生成摘要—清除原记录”三个操作，不引入新状态机。摘要采用
可查询的结构化 JSONL，保留 90 天后删除逐条记录，仅留下聚合计数增量。
当前实现不包含后台定时器。

真实生产候选一旦 `deny`，原 Patch、AI 原文、反馈和确认详情立即清除；
结构化审计摘要保留 90 天后删除逐条记录，仅留下聚合计数增量。虚构评测
输出可保留模型诊断用于失败审查，这一例外不适用于真实用户内容。

重开 `hold/deny` 时必须创建不同 ID 的新候选，引用新的证据 ID，并用旧
摘要 SHA-256 建立审计链接。旧 Patch、决策和人工确认一律不继承；摘要
已删除后只能创建不关联历史的全新候选。
