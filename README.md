# 知识污染防火墙 (Knowledge Contamination Firewall)

面向个人 AI 使用者的知识污染防火墙，解决错误、过期或恶意反馈持续混入 RAG 与长期记忆的问题。

## 核心设计原则

**AI 不掌握最终写入权限。** AI 只负责理解候选内容、提出结构化建议、说明不确定性；是否真正写入长期记忆，由确定性规则和安全门（firewall）决定，不依赖模型输出的可靠性。

## 三种评测方案

- **Baseline**：不调用模型，纯规则判断。
- **Single**：每个候选调用模型一次。
- **Multi**：默认与 Single 相同，仅在高风险信号出现时增加独立审查者（provenance auditor / write-risk auditor）与仲裁者，最多 4 次调用。
- 明确可判定拒绝的候选直接由规则短路处理，不产生任何模型调用（省钱、也避免不必要的模型幻觉风险）。

## 验收标准

验收关注点不是模型回答是否流畅，而是：
- 污染内容是否**零误放**
- 测试内容是否**零流入生产**
- 拦截动作是否完整可追溯
- 预算与调用次数是否可审计

本项目仅使用虚构或脱敏数据；测试环境下允许写入的内容只进入隔离沙盒（`test-only/` 命名空间），永不进入正式知识库或长期记忆。

## 当前版本：v0.3

v0.3 是当前维护的版本，位于 `controlled_compare/compare_v0_3.py` 与 `controlled_compare/firewall_v0_3.py`。v0.1（`compare.py`）、v0.2（`compare_v0_2.py`）为历史迭代，仅保留用于事故复现回归测试（见 `tests/test_incident_reproductions.py`），不建议作为新接入的起点。

### 快速开始（不调用模型，免费）

```bash
python3 -m unittest discover -s tests -v
```

### 干跑评测管线（dry-run，不调用真实模型）

```bash
python3 -m controlled_compare.compare_v0_3 --adapter dry-run --dataset semantic-gold --smoke
```

### 接入真实模型（阿里云百炼 / Bailian，产生真实费用）

需要设置以下环境变量：

```bash
export DASHSCOPE_API_KEY="你的按量付费 workspace API key（不能是 sk-sp- 开头的套餐 key）"
export DASHSCOPE_BASE_URL="https://你的workspace.ap-northeast-1.maas.aliyuncs.com/compatible-mode/v1"
```

`DASHSCOPE_BASE_URL` 需要是「OpenAI 兼容模式」的东京（ap-northeast-1）区域 endpoint，不是 Anthropic 兼容模式（`/apps/anthropic`）的地址。请到阿里云百炼控制台的 workspace 详情页确认。

**Mac 用户注意**：如果使用 python.org 官网安装的 Python，首次运行前需要执行一次证书修复（否则会报 SSL 证书验证失败）：

```bash
/Applications/Python\ 3.x/Install\ Certificates.command
```

正式运行（会产生真实费用，需要显式确认）：

```bash
python3 -m controlled_compare.compare_v0_3 \
  --adapter bailian \
  --dataset semantic-gold \
  --confirm-paid-run
```

传输层内置最多 3 次网络错误重试（间隔 2 秒），契约类错误（如 API key 类型不对）不会重试。

## 目录结构

- `controlled_compare/` — 核心评测与防火墙逻辑（v0.1/v0.2/v0.3 三代并存）
- `tests/` — 单元测试与历史事故复现回归测试
- `gold_set/`、`controlled_compare/semantic_gold_v0_1.jsonl` — 虚构测试用例集
- `data/` — 辅助知识数据（如版本化知识样例）
- `incident_reproductions/` — 已知 AI 记忆系统事故的最小复现脚本
- `outputs/` — 评测报告、验收记录（含本次 v0.3 安全验收记录）

## 安全说明

- 本仓库中的所有测试用例、评测数据均为虚构或脱敏内容，不含真实用户信息。
- API key、密钥等敏感信息不会出现在本仓库任何文件中，运行时通过环境变量注入，请勿将其硬编码或提交至版本控制。
- 详细的安全验收过程与结论见 `outputs/v0.3_安全验收记录_2026-09-15.md`。
