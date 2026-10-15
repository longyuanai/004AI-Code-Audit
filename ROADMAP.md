# 004AI-Code-Audit · ROADMAP

核实日期：2026-10-15。依据本地README、构建清单和实际入口；本文件不把文档计划当成运行时验收。

## 目标与范围

保留原CLI与004来源兼容性，提供本地受限Python代码导入、AST风险规则和可选AI复核。

GitHub：[longyuanai/004AI-Code-Audit](https://github.com/longyuanai/004AI-Code-Audit)。知识笔记：Vault内 `03_Projects/AI-Network-Security/004AI-Code-Audit - Git关联.md`。

## 可验收的推进顺序

| 阶段 | 交付物 | 验收标准 | 当前定位 |
| --- | --- | --- | --- |
| 基线 | 固定Git SHA、环境和最小样例 | 代码输入只解析不执行；验证SQLite临时历史、报告契约和只读漏洞缓存桥接。本轮18项模块集成已通过。 | 按实际日志验收，不重用历史计数 |
| 边界 | 权限、异常输入与失败处理证据 | 授权/越界/空输入/外部服务不可用均有可复现结果 | 验收待核实 |
| 交付 | 可复现命令、产物及回滚点 | 干净环境复跑适用检查，记录退出码；真实服务另获授权 | 审阅后交付 |

## 本项目的验证重点

代码输入只解析不执行；验证SQLite临时历史、报告契约和只读漏洞缓存桥接。本轮18项模块集成已通过。

## 工程命令依据

- `package.json` / `test`：`vitest`。
- `package.json` / `typecheck`：`tsc --noEmit`。
- `package.json` / `lint`：`eslint src/`。
- `package.json` / `build`：`tsup`。

未列出脚本时使用README及现行技术规范的命令。文档更新不等于本轮业务验证通过。项目未统一排期，登记不将其自动设为活跃主线；进行中项目原则上不超过3个。

## 现行依据

- [README.md](README.md)
- [CAPABILITIES.md](CAPABILITIES.md)
- [docs/tech-spec.md](docs/tech-spec.md)
- [docs/graduation/system-design.md](docs/graduation/system-design.md)
- [docs/TODO.md](docs/TODO.md)
