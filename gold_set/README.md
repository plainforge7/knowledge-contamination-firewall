# Knowledge Pollution Firewall Gold Set V0

这是一份冻结前的 V0 评测集，用于让 Baseline、Single-Agent 和 Multi-Agent 在完全相同的输入上进行受控比较。

## 分布

- 4 条 `clean_allow`：正确知识应被放行，用于测量误杀。
- 4 条 `incorrect_information`：同版本错误事实应被隔离。
- 4 条 `stale_information`：过期事实不能用于目标版本回答。
- 4 条 `post_correction_old_information`：显式纠正后必须采用新事实。
- 2 条 `stale_snapshot_overwrite`：基于旧 revision 的写入必须被拒绝。
- 2 条 `realtime_evidence_priority`：实时工具证据必须压过陈旧记忆。

## 评分

每题满分 1 分：治理决策 0.35、答案断言 0.25、必需证据 0.25、禁止证据未出现 0.15。成本、延迟、模型调用次数不计入正确性分数，而是作为独立运行指标报告。

## 公平性约束

三种实验臂必须使用同一份 Gold Set、知识库、污染夹具、模型版本、温度、Top-K 和运行环境。Gold Set 冻结后不得根据某个实验臂的失败结果修改标准答案；如需修订，必须提升数据集版本并保留变更记录。

## 尚需产品负责人确认

1. 同版本错误且来源不可信时，默认动作采用 `quarantine`，不是永久删除。
2. 实时工具证据仅在时间更新、目标环境匹配且可审计时拥有最高优先级。
3. 可信但属于其他版本的事实保留在知识库中，只在当前查询中执行 `exclude_as_stale`。
