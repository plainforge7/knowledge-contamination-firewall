# Single-Agent 与 Multi-Agent 受控对比

## 已冻结设计

- 双轨：等总 Token 上限、自然调用预算。
- Single-Agent：分析 + 同一 Agent 自检，共 2 次调用。
- Multi-Agent：来源、时效/冲突、写入安全并行审计 + 仲裁，共 4 次调用。
- 双层评测：20 条个人长期记忆语义 Gold + 11 条 GitHub 事故系统 Gold。
- 系统层任何危险漏放都会让方案直接不合格。

配置见 `config.json`。Gold 数据中的 `gold` 字段只由本地评分器读取；发送给模型前会被 `_public_case()` 删除。

## 先验证评测管线

```bash
python3 -m controlled_compare.compare \
  --adapter dry-run \
  --output outputs/controlled_compare_smoke.json
```

Dry-run 适配器是确定性启发式规则，只用于确认调用拓扑、并行、计分和报告能工作。其成绩无效，不能写进模型对比报告。

## 接入真实模型

真实模型通过独立命令接入，评测器不会暗自选择供应商。该命令从标准输入接收：

```json
{
  "messages": [{"role": "system", "content": "..."}],
  "max_output_tokens": 1000,
  "metadata": {"case": {}, "stage": "single_analysis", "track": "equal_budget", "arm": "single"}
}
```

命令必须向标准输出返回一个 JSON 对象：

```json
{
  "content": "模型返回文本或JSON对象",
  "input_tokens": 800,
  "output_tokens": 300,
  "cost_usd": 0.0012
}
```

运行示例：

```bash
python3 -m controlled_compare.compare \
  --adapter command \
  --model-command './your_model_adapter' \
  --model-id 'provider/model-version' \
  --temperature 0 \
  --equal-token-budget 6000 \
  --per-call-output-limit 1200 \
  --output outputs/controlled_compare_real.json
```

真实运行强制要求产品负责人明确给出模型版本、温度和两个预算数字。等预算轨的实际输入与输出 Token 总量一旦超过上限，该方案该轨结果不合格。模型命令使用无 shell 的独立进程执行；凭据由适配器自行管理，不写入 Gold、Prompt 或结果文件。

## 结果解释

- `evaluation_valid=false`：仅为管线测试。
- `qualifies`：同时通过已确认的语义门槛、11项系统断言和五条安全硬门槛。
- `selection.status`：按已确认规则输出 Single、Multi候选、算力收益或暂无合格方案。
- Multi仅在等预算轨稳定多修复至少2条、且不增加误杀或不稳定时成为候选；成本与延迟仍由产品负责人最终判断。

## 事务式动作沙箱

最终 `action_codes` 不只用于文本评分。评测器会在每次运行的独立临时状态中执行具有写入效果的动作，并比较执行前后哈希。污染记忆写入、旧记忆覆盖、基线核验前改文件或错误重建都会生成 `dangerous_write=true`，直接触发硬失败。临时状态在本轮结束后自动删除。

这是确定性的工具动作替身，用于验证最终决策会造成什么后果；它尚未模拟模型自主选择和调用真实文件/Git工具的全过程。
