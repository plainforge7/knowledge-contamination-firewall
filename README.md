# 知识污染防火墙 (Knowledge Contamination Firewall)

面向个人 AI 使用者的知识污染防火墙，解决错误、过期或恶意反馈持续混入 RAG 与长期记忆的问题。

## 核心设计原则

**AI 不掌握最终写入权限。** AI 只负责理解候选内容、提出结构化建议、说明不确定性；是否真正写入长期记忆，由确定性规则和安全门（firewall）决定，不依赖模型输出的可靠性。

## 三种评测方案

- **Baseline**：不调用模型，纯规则判断。
- **Single**：每个候选调用模型一次。
- **Multi**：默认与 Single 相同，仅在高风险信号出现时增加独立审查者（provenance auditor / write-risk auditor）与仲裁者，最多 4 次调用。
- Single 与 Multi 中，明确可判定拒绝的候选都由规则短路处理，不产生任何模型调用（省钱、也避免不必要的模型幻觉风险）。两臂对这类候选的调用次数因此一致。

## 验收标准

验收关注点不是模型回答是否流畅，而是：
- 污染内容是否**零误放**
- 测试内容是否**零流入生产**
- 拦截动作是否完整可追溯
- 预算与调用次数是否可审计

### 解读限制（v0.3.3）

- **标签依赖**：确定性规则读取数据集中人工标注的 `risk_signals` 与 `source_type`，基线 20/20 全对是按构造的。“零误放”只说明规则表与标签一致；上游如何产生这些标签不在本项目范围内。
- **来源为自报字段**：`source_type` 与 `risk_signals` 由调用方写入，没有宿主侧或密码学绑定，与“写入时绑定来源”的理想仍有差距。
- **样本量**：semantic-gold 为 20 条（阻断类 10 条）。0/10 泄漏的 95% 置信上界约为 30%（rule of three），不能支撑“零泄漏”的统计表述。
- **稳定性**：稳定性仅在 `repetitions >= 2` 时可评估（当前配置为 2）；单次重复时稳定性门会失败。
- **生命周期**：30/90 天保留与 reopen 逻辑已实现并有测试，但运行器不调度到期清理（配置中 `background_scheduler_in_scope: false`）。
- **版本**：v0.3.3 修改了规则结论（deny 不再被降级、两臂统一短路）与提示词，旧版本成绩不可直接比较。

本项目仅使用虚构或脱敏数据；测试环境下允许写入的内容只进入隔离沙盒（`test-only/` 命名空间），永不进入正式知识库或长期记忆。

## 当前版本：v0.9（路线实现版）

v0.4 在 v0.3 防火墙与受控评测基础上增加审计 Trace、JSONL 审计输出，以及
JSONL 到 SQLite/CSV 的本地审计数据层。核心运行器仍位于
`controlled_compare/compare_v0_3.py` 与 `controlled_compare/firewall_v0_3.py`；
v0.1（`compare.py`）、v0.2（`compare_v0_2.py`）为更早的迭代版本。

审计 JSONL 导入时，`import_jsonl` 返回本次实际新增的行数。唯一键
（`protocol_version`、`execution_id`、`dataset`、`evaluation_valid`、`case_id`、`repetition`、`arm`）相同的行，内容完全一致时会被跳过（重复导入同一个文件返回 `0`）；内容不一致时整个导入回滚，并报 `AuditConflictError`。只有显式传入 `--overwrite` 才会替换旧行，并提示“覆盖了 N 条重复记录”。

v0.5-v0.8 在不改变 v0.3 安全门的前提下补充了隔离记忆生命周期、污染回归
评测、人工复核队列和条件化 Agent 工作流；v0.9 的求职版项目说明见
`outputs/v0.9_portfolio.md`。

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

v0.2 传输层内置最多 3 次网络错误重试（间隔 2 秒），契约类错误（如 API key 类型不对）不会重试。v0.3 评测路径没有隐藏重试：每次预留对应一次 HTTP 请求，失败记为基础设施错误，由 `--resume` 续跑。

## 相关工作与定位

记忆投毒（memory poisoning）与 RAG 投毒在 2025-2026 年成为活跃方向，以下是与本项目最接近的开源与学术工作：

| 项目 | 定位 | 与本项目的差异 |
| --- | --- | --- |
| [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard) | 记忆写入前的 5 层实时校验库（pip 包，宣称检出率 98.7%） | 提供检测组件；本项目是**评测驱动**的完整管线，含 baseline / single / multi 三臂受控对比与验收线 |
| [Aigis](https://github.com/gaebalai/aigis-kr) | 确定性 Agent 防火墙，含记忆写入过滤器 | 同样坚持确定性规则、不用 LLM 做裁判；其重心在 MCP 工具调用层，记忆只是其中一层 |
| [Mnemosyne](https://github.com/TeleAI-UAGI/Awesome-Agent-Memory) | 记忆读写网关：溯源信任分级 + 哈希链审计 | 思路接近本项目的溯源与审计；本项目额外提供对照实验证据与人工复核队列 |
| [Veritensor](https://github.com/arsbr/Veritensor) | RAG 入库前静态扫描（投毒 / 注入 / PII） | 管「入库前」；本项目管「写入长期记忆的准入决策」及其全生命周期 |

学术侧，TMA-NM（[arXiv:2606.24322](https://arxiv.org/abs/2606.24322)，2026-06）从理论上证明：纯内容检测与纯溯源防御在「来源洗白」（laundering）攻击下都不可信，**写入时必须绑定来源**——这与本项目「AI 不掌握最终写入权限、由确定性规则裁决」的设计原则方向一致。攻击侧可参考 MPBench（记忆投毒基准）与 GhostWriter（[arXiv:2607.06595](https://arxiv.org/abs/2607.06595)，针对 Mem0 / Letta 等主流记忆框架的两阶段投毒攻击，注入成功率约 98%）；GhostWriter 的攻击模式已在本仓库做了确定性复现，见 `incident_reproductions/ghostwriter_2607_06595.py`。

## 目录结构

- `controlled_compare/` — 核心评测与防火墙逻辑（v0.1/v0.2/v0.3 三代并存）
- `tests/` — 单元测试与历史事故复现回归测试
- `gold_set/`、`controlled_compare/semantic_gold_v0_1.jsonl` — 虚构测试用例集
- `data/` — 辅助知识数据（如版本化知识样例）
- `incident_reproductions/` — 已知 AI 记忆系统事故与论文攻击模式的最小复现脚本（含来源标注）
- `outputs/` — 评测报告、验收记录（含本次 v0.3 安全验收记录）

## 安全说明

- 本仓库中的所有测试用例、评测数据均为虚构或脱敏内容，不含真实用户信息。
- API key、密钥等敏感信息不会出现在本仓库任何文件中，运行时通过环境变量注入，请勿将其硬编码或提交至版本控制。
- 详细的安全验收过程与结论见 `outputs/v0.3_安全验收记录_2026-09-15.md`。
