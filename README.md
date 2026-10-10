# 知识污染防火墙

**一个以评测驱动的 RAG / 长期记忆安全门项目**：解决错误、过期或恶意反馈持续混入个人 AI 知识库的问题。核心设计原则是 **AI 不掌握最终写入权限**——AI 只负责理解候选内容、提出结构化建议、说明不确定性；是否真正写入长期记忆，由确定性规则和安全门（firewall）决定，不依赖模型输出的可靠性。

个人项目，本人主导**评测方案设计、安全验收与迭代决策**（与 AI 辅助开发工具协作：人定义每一版做什么、不做什么、接受什么代价，结论以评测证据为准）。

## 评测体系（本项目的核心）

验收关注点不是模型回答是否流畅，而是**评测结果可信、稳定、可复现**：

- **三方案对比评测（semantic-gold 20 条虚构用例、真实付费模型）**：
  - **Baseline**：不调用模型，纯规则判断；
  - **Single**：每个候选调用模型一次；
  - **Multi**：默认与 Single 相同，仅在高风险信号出现时增加独立审查者（provenance auditor / write-risk auditor）与仲裁者，最多 4 次调用。
  - 明确可判定拒绝的候选直接由规则短路处理，不产生任何模型调用（省钱，也避免不必要的模型幻觉风险）。
- **验收线**：污染内容**零误放**、测试内容**零流入生产**、拦截动作完整可追溯、预算与调用次数可审计。测试环境下允许写入的内容只进入隔离沙盒（`test-only/` 命名空间），永不进入正式知识库或长期记忆。
- **实测结果**：最新一轮全量复测 multi 方案 **20/20**；single 方案 18/20，另 2 条因网络失败未完成，成功完成的 18 条全部正确（此前一轮 single 由 0.6 提升至 1.0）。本地测试 **65→84 项**全部通过。
- **bad case 归因机制**：区分系统防护生效（不计为缺陷）、模型行为偏差（记为 bad case）、Prompt / 输出契约问题（迭代修复）；针对 Patch 越权、Evidence ID 重复、模型输出契约错误逐一设计修复方案。
- **评测成本与统计稳定性的显式权衡**：repetitions 3→1，并如实记录稳定性指标统计意义下降这一局限。
- **已知问题如实记录**：一条已知 bad case 重复验证 7 次中 6 次符合预期，部分改善、未完全修复。

## 快速开始

### 单元测试（不调用模型，免费）

```
python3 -m unittest discover -s tests -v
```

### 干跑评测管线（dry-run，不调用真实模型）

```
python3 -m controlled_compare.compare_v0_3 --adapter dry-run --dataset semantic-gold --smoke
```

### 接入真实模型（阿里云百炼 / Bailian，产生真实费用）

需要设置以下环境变量：

```
export DASHSCOPE_API_KEY="你的按量付费 workspace API key（不能是 sk-sp- 开头的套餐 key）"
export DASHSCOPE_BASE_URL="https://你的workspace.ap-northeast-1.maas.aliyuncs.com/compatible-mode/v1"
```

`DASHSCOPE_BASE_URL` 需要是「OpenAI 兼容模式」的东京（ap-northeast-1）区域 endpoint，不是 Anthropic 兼容模式（`/apps/anthropic`）的地址。请到阿里云百炼控制台的 workspace 详情页确认。

**Mac 用户注意**：如果使用 python.org 官网安装的 Python，首次运行前需要执行一次证书修复（否则会报 SSL 证书验证失败）：

```
/Applications/Python\ 3.x/Install\ Certificates.command
```

正式运行（会产生真实费用，需要显式确认）：

```
python3 -m controlled_compare.compare_v0_3 \
  --adapter bailian \
  --dataset semantic-gold \
  --confirm-paid-run
```

传输层内置最多 3 次网络错误重试（间隔 2 秒），契约类错误（如 API key 类型不对）不会重试。

## 当前版本：v0.3

v0.3 是当前维护的版本，位于 `controlled_compare/compare_v0_3.py` 与 `controlled_compare/firewall_v0_3.py`。v0.1（`compare.py`）、v0.2（`compare_v0_2.py`）为更早的迭代版本，v0.3 会从 v0.1 中复用少量通用工具函数（`CallResult`、`_estimate_tokens`），三者是否会继续并行维护尚未最终确定，请以本仓库最新提交为准。

## v0.4 审计数据层

审计 JSONL 导入时，`import_jsonl` 返回本次实际新增的行数。唯一键
（`protocol_version`、`dataset`、`case_id`、`repetition`、`arm`）重复时会覆盖旧记录，
并通过警告和命令行提示“覆盖了 N 条重复记录”；同一文件再次导入同一个数据库时返回 `0`。

## 目录结构

- `controlled_compare/` — 核心评测与防火墙逻辑（v0.1/v0.2/v0.3 三代并存）
- `tests/` — 单元测试与历史事故复现回归测试
- `gold_set/`、`controlled_compare/semantic_gold_v0_1.jsonl` — 虚构测试用例集
- `data/` — 辅助知识数据（如版本化知识样例）
- `incident_reproductions/` — 已知 AI 记忆系统事故的最小复现脚本
- `outputs/` — 评测报告、验收记录（含 v0.3 安全验收记录）

## 安全说明

- 本仓库中的所有测试用例、评测数据均为虚构或脱敏内容，不含真实用户信息。
- API key、密钥等敏感信息不会出现在本仓库任何文件中，运行时通过环境变量注入，请勿将其硬编码或提交至版本控制。
- 详细的安全验收过程与结论见 `outputs/v0.3_安全验收记录_2026-09-15.md`。
