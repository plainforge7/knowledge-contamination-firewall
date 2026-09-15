# 百炼首次真实对比 v0.2

本版只跑三个 GitHub 事故对应的 11 项系统断言。原有 `compare.py`、
`config.json`、Gold Set 和事故复现模块保持不变。

## 冻结的实验条件

- 平台：阿里云百炼按量付费 API。
- 地域：日本（东京）`ap-northeast-1`。
- 模型：`qwen3.7-max-2026-05-20` 快照（东京、全球部署范围）。
- 记录价格：输入 1.65 元/百万 Token，输出 4.951 元/百万 Token；
  控制台优惠可能不同。
- 思考开启，`temperature=0.2`，不回传思考，不启用联网工具。
- 等预算轨：每案例、每方案实际总 Token 不超过 16,384；生成预算
  Single 为 `4096×2`，Multi 为 `2048×4`。
- 自然预算轨：每次调用最多输出 2,048 Token。
- 11 项断言×3 次×2 轨×Single/Multi，完整运行预期 396 次模型调用。

## API Key 边界

使用按量付费的业务空间 Key。`sk-sp-` 开头的 Token Plan Key 不得用于
这个自定义评测脚本，适配器会主动拒绝。

Key 只从 `DASHSCOPE_API_KEY` 环境变量读取，不会进入 Prompt、代码或结果文件。
东京地域还需要控制台中该业务空间的 API Host。
适配器对 429/5xx、URL 网络错误和远端断连最多尝试 3 次。

```zsh
read -s 'DASHSCOPE_API_KEY?API Key: '
export DASHSCOPE_API_KEY
read 'DASHSCOPE_BASE_URL?Tokyo API Host: '
export DASHSCOPE_BASE_URL
```

`DASHSCOPE_BASE_URL` 应形如：

```text
https://llm-xxx.ap-northeast-1.maas.aliyuncs.com/compatible-mode/v1
```

## 免费管线测试

```zsh
python3 -m controlled_compare.compare_v0_2 --adapter dry-run
```

## 付费连通测试

只跑 1 个断言、1 次重复、2 条轨，共 12 次模型调用；结果不能解读为模型成绩。

```zsh
python3 -m controlled_compare.compare_v0_2 \
  --adapter bailian \
  --smoke \
  --confirm-paid-run
```

## 完整付费对比

只在连通测试通过后运行：

```zsh
python3 -m controlled_compare.compare_v0_2 \
  --adapter bailian \
  --confirm-paid-run
```

运行后立即清除当前终端中的 Key：

```zsh
unset DASHSCOPE_API_KEY
```

正式知识库和长期记忆始终不会被写入。所有动作只在每次运行的临时事务
沙箱中执行，沙箱结束后自动删除。
