# 毕业设计基线审计（2026-10-09）

本报告以现场源码和测试为依据；当前尚未通过毕业设计版本验收。

## 仓库、结构和保护措施

唯一开发根目录为 `002AI-Code-Audit`。独立 Git 仓库，分支
`agent/ai-codeguard-fusion`，初始 HEAD `cd50e9c`；远程为 longyuanai/004AI-Code-Audit。
开始时 README.md、docs/TODO.md、src/ai_code_audit/cli.py 已修改，另有两份
local-delivery 文档及 test_output_atomic.py、test_scan_result_contract.py 未跟踪。
全部保留。既有修改的补丁和待修改文件备份位于
`artifacts/graduation-20261009/backup/`，回滚前必须比较后续差异。

Python 3.11+（本机 3.14.6）、Tree-sitter、共享 LLM 路由；TypeScript CLI、
Tree-sitter、Vitest；两个实现并存，不能混用其历史准确率。
Python 包版本 0.6.0，npm 包 0.5.0。modules/vulnerability-analysis 和同级
shared-llm-core 为独立仓库，本轮不修改这些仓库；不复制第二套开发源码。

## 功能审计矩阵（初始状态）

| 功能 | 实际状态 | 源码 / 验证方式 |
|---|---|---|
| 本地目录、远程仓库输入 | CLI 已实现；毕业设计安全上传未实现 | hybrid_cli.py、cli.py；CLI/API 输入测试 |
| 静态规则 | 已实现，Python 默认仅输入/sink 共现启发式；五类覆盖不足 | scanner.py、taint.py、backends/opengrep.py；规则正反例和 C3 评测 |
| AI 复核与解释 | 已实现，保留静态证据；真实模型本轮未配置 | triage.py、triage_context.py、explain.py；stub、错误、注入测试 |
| 位置/风险展示 | CLI JSON/SARIF 已实现；Web 未实现 | output/sarif.py、postprocess.py；报告契约测试 |
| 任务/历史 | 未实现毕业设计任务存储 | 需增加项目和任务关系、重启恢复测试 |
| 数据库 | 现有 SQLite 仅情报缓存，不能替代任务库 | cve_intel/cache.py；需独立业务库 |
| 导出报告 | JSON/SARIF/Markdown 已实现；HTML 未实现 | output/；原子写入已有用户修复及测试 |
| Web 界面 | 本产品无 Web 服务；套件 web-ui 是独立仓 | 本轮增加产品内本地演示入口，不动套件界面 |
| 异常处理 | CLI 已有降级和输出保护；Web 生命周期缺失 | cli.py；后台超时、重启、失败状态需补齐 |
| 测试/部署 | 大量单元/集成测试；既有安装依赖同级共享源码 | scripts/run_python_tests.py、pyproject.toml；需 wheel 和隔离部署验证 |
| 公网、多用户、企业权限 | 不属于本地毕业设计第一版 | 仅监听回环地址，明确不宣称具备多租户权限 |

## 代码质量、安全与差距

优势：现有稳定 Finding 来源 `004`，报告契约、差异/基线、注入防护、脱敏、
静态证据保全已有测试。风险：默认启发式不证明数据流；路径导入必须拒绝
穿越/链接；新的后台扫描要限制文件、任务、队列、体积和进程时间。
AI 不能把 confirmed 字段当成人工验证；模型错误不得让静态扫描丢失。
HTML/前端必须按文本渲染。共享路由默认会审计提示词，Web 入口需关闭原文审计。
独立部署必须提供共享依赖 wheel，不能依赖开发 PYTHONPATH。

## 最小实施计划和阶段验收

1. 现场运行 Python/TS 基线并保存失败/成功日志；本报告固定初始状态。
2. 保留现有 CLI，补充 Python AST 规则；正反例验证五类风险，不执行样本。
3. 增加标准库本地 Web、SQLite 任务库、安全 Python/ZIP 快照导入及 HTML 报告；
   扫描子进程有硬超时，任务状态与 AI 状态分离，保留原始发现。
4. 验证 API、安全边界、完整浏览器流程、重启和独立 wheel 安装；记录实验口径。
5. 以真实证据生成通用技术/论文/答辩草稿。真实模型成功、最终提交及版本验收
   未满足前，不打毕业设计标签、不创建正式交付快照、不宣称验收通过。

## 现场基线

首次 Python 命令使用沙箱重映射的 LOCALAPPDATA，解释器定位失败；改用已确认
的绝对解释器路径继续测试。首次 TS 因沙箱 realpath EPERM 无法收集；正常权限
重跑 `npm run test:run`：593 passed、2 skipped，exit 0。两项真实模型测试跳过。
Python 完整结果和后续修改验证见 [测试报告](../tests/graduation-test-report.md)。
日志均位于 artifacts/，不以历史文档中的测试数字替代现场结果。
