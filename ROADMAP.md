# 004AI-Code-Audit · ROADMAP

核对日期：2026-10-16。适用远端 `agent/ai-codeguard-fusion`；该分支与默认 main 存在独立业务历史。本项目已选为当前主线，纯文档提交不合并两条业务线。

| 顺序 | 可审阅成果 | 验收方式 |
| --- | --- | --- |
| 基线 | 固定目标分支 SHA、Python 与 TypeScript CLI 的输入和报告契约 | 按 [技术规范](docs/tech-spec.md) 和 [任务清单](docs/TODO.md) 核对范围，分别记录两套入口的环境、命令与退出码 |
| 离线演示 | 扫描授权样例，输出 JSON/SARIF，再用只读本地缓存进行漏洞情报增强 | 输入只解析，不导入或执行；无情报时如实标注 skipped/partial，不把缓存失败写成“无漏洞” |
| 交付 | 干净环境复跑适用单元/模块集成检查并保留脱敏结果 | 真实 AI 和集成模块另有授权及环境要求；本分支未因此继承较新本地交付的测试结论 |

工程命令以本分支清单为准：

- TypeScript：`npm run test:run`、`npm run typecheck`、`npm run lint`、`npm run build`，定义见 [package.json](package.json)。`npm test` 是交互入口，自动检查使用 test:run。
- Python：使用实际解释器路径调用 `scripts/run_python_tests.py --scope unit`；集成检查使用 `--scope integration` 并提供唯一漏洞模块，缺失即失败。参考 [README](README.md)，不在此复用历史通过数。
- Python 依赖包含相邻 `000shared-llm-core`；单独克隆本仓不等于套件依赖齐全，见 [pyproject.toml](pyproject.toml)。

后续 Web/毕业设计交付若尚不在目标分支，应单独审阅源码变更与测试后再更新主线，不通过文档 PR 带入业务代码。
