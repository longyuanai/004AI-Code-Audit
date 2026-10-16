# 004AI-Code-Audit · SECURITY

核对日期：2026-10-16。适用 `agent/ai-codeguard-fusion` 的现有 CLI 与 Python 离线增强边界。

- 仅扫描自有、授权、靶场或 CTF 代码。输入源码只解析，不通过导入、运行或包安装执行被审代码。
- 静态 evidence 与可选 AI 判断分开；没有真实漏洞情报或增强失败时保留阶段状态，不推断“安全”。
- 不提交真实 API Key、Token、私钥、客户源码、运行数据库和原始模型日志。演示使用脱敏夹具。
- TypeScript CLI 不带 `--dry-run` 时可进入外部 LLM 阶段；未获明确授权时使用静态模式，避免发送源码到提供商。真实模型回归不作为默认离线测试。
- 模块各有独立历史；不要把 `modules/` 中另一仓库或本地配置混入当前提交。相邻套件依赖需按 README 单独准备。

敏感问题先联系[维护者 longyuanai](https://github.com/longyuanai)，确认私下报告渠道。公开复现应脱敏，记录影响、固定 SHA、修复和回归证据；文档更新不表示产品通过全面安全审计。

依据：[README](README.md)、[能力归属](CAPABILITIES.md)、[技术规范](docs/tech-spec.md)。
