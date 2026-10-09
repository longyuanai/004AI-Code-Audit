# 毕业设计软件验收与交付记录

2026-10-09，本机毕业设计软件范围通过实际验收，正式材料已生成并核验。
学校模板、个人信息、独立学术和标签复核仍待本人办理。

## 固定版本

- 软件提交：`1ef74c96a7082e104ebebc7d8e3fd4677a394e8e`。
- 本地注释标签：`v1.0.0-graduation`，指向上述软件提交。
- Python 包保留 `ai-codeguard-upgrade 0.6.0`；原 TypeScript CLI 保留 0.5.0。
- 共享核心：0.6.0，干净提交 `8dd1bbd5e855d68e5476540f7e533af596f1cf46`。
- 原有 CLI 修改单独保存于 `bdcd1ed3e539fe4278312fc3c10d15afa138f577`，没有丢弃用户修改。
- 后续验收文档同步为独立提交，不移动软件标签或替换已验证的源码 ZIP。
  本轮没有远程推送、合并主分支或发布。

## 实际修改与范围

| 主要文件 | 变更 |
|---|---|
| src/ai_code_audit/python_security.py | 复用原扫描器，补齐 Python AST 五类潜在风险 |
| src/ai_code_audit/web/imports.py | 安全文件/ZIP 导入、路径及资源校验 |
| src/ai_code_audit/web/store.py | SQLite 四表、事务和任务/发现/AI 关联 |
| src/ai_code_audit/web/service.py | 快照、队列、可信进程硬超时、导出、失败回滚 |
| src/ai_code_audit/web/server.py 与 static/ | 本机 HTTP、来源与 token 校验、完整 Web 业务 |
| src/ai_code_audit/web/worker.py | 隔离静态扫描与可选 AI；不执行上传代码 |
| src/ai_code_audit/triage_context.py | 补齐常见凭据形式的上下文脱敏 |
| pyproject.toml、.env.example | 新增 Web 入口与占位配置，没有新增生产依赖 |
| tests/test_graduation_security.py 与 test_graduation_workflow.py | 新增安全、数据库、API、故障及真实进程回归 |
| scripts/graduation_eval.py、graduation_ai_eval.py、graduation_smoke.py | 标注实验、真实模型对照、安装版双路径验证 |
| scripts/prepare_graduation_wheels.py 与 packaging/ | 便携产物元数据规范化、锁定安装与启动脚本 |
| scripts/graduation_materials.py、graduation_defense.mjs | 可复现材料作者工具，不属于生产依赖 |
| benchmarks/graduation/、docs/audits/、docs/tests/、docs/graduation/ | 标注、基线、真实证据、论文与答辩草稿 |
| AGENTS.md、README.md、docs/README.md、TODO.md、tech-spec.md | 本仓规则、能力边界、最新入口与验收状态 |

完整软件变更名单可用 `git show --stat 1ef74c9` 读取，共 43 个文件。
只新增本地单用户毕业设计业务，未改其他能力仓、原接口来源编号或技术栈。

## 最终验证

| 检查 | 结果 |
|---|---|
| 全量 Python 集成 | 427 passed，1 项既有 pytest cache_dir warning；exit 0 |
| TypeScript | 593 passed / 2 skipped；typecheck、build、lint 通过 |
| Python 质量 | Ruff 通过；strict mypy 12 个源文件通过 |
| 浏览器 | 实际导入、扫描、详情、AI 降级与成功、HTML 下载 |
| 同样本实验 | 20 例三次静态/三次 AI，30 次实际调用成功；P/R 均 80%，无提升 |
| Git 导出 | 457 项（含目录），排除 .git、.env、运行环境、缓存、数据库和模型 |
| 安装一致性 | 71 个产品源码/资源文件与 Git 导出逐字节一致 |
| 离线安装 | 导出脚本创建新 venv，30 包正常解析、--require-hashes、pip check；exit 0 |
| 安装版流程 | 清空 PYTHONPATH、源码目录外 python -I；AI 成功/降级各 13/13 true |
| 启动脚本 | 导出脚本分配回环端口，HTTP 200；验证实例已结束 |
| 材料 | PDF 17 页、PPT 11 页、3 张可编辑表格；全页复核与文件检查通过 |
| 正式目录 | 10 个目录、74 个文件；只读脚本核验 73 个哈希，文档链接无缺失 |

原始 wheel 的同级 shared 路径缺失警告保留，独立产物只将该 file URL 改为
已随包提供的版本约束，重新生成 RECORD；没有删依赖或跳过依赖解析。
启动测试由操作者 Ctrl+C 结束 PTY，外层退出 1，确认无残留测试进程；
不把人工终止状态当成新增自动化通过计数。

本机模型为 `qwen2.5:3b-instruct-q4_K_M`，Ollama 0.40.0，摘要
`357c53fb659c5076de1d65ccb0b397446227b71a42be9d1603d46168015c9e4b`。
模型曾产生不适用的修复建议，证据保留，系统没有执行建议的入口。

过程记录在 `artifacts/graduation-20261009/accepted/`；正式可机读收据见交付目录。
失败与修复事实见 [测试报告](../tests/graduation-test-report.md)，不以本记录覆盖历史失败。

## 交付入口与哈希

正式目录：`E:\001项目\000开发\毕业设计\AI代码安全检测系统`。

- [交付总览](E:/001项目/000开发/毕业设计/AI代码安全检测系统/README.md)
- [交付清单](E:/001项目/000开发/毕业设计/AI代码安全检测系统/10-交付清单/交付清单.md)
- [论文 PDF](E:/001项目/000开发/毕业设计/AI代码安全检测系统/07-毕业设计论文/毕业设计论文通用初稿.pdf)
- [答辩 PPT](E:/001项目/000开发/毕业设计/AI代码安全检测系统/08-答辩材料/毕业设计答辩通用草稿.pptx)

源码 ZIP SHA-256：
`4ee0fcc7654367a68d09c0cd7ef70ffe61cd5d8d7a59c7a026c24fb1ef3f6680`。
`10-交付清单/manifest.json` 包含 72 个内容文件的大小与哈希；SHA256SUMS.txt 还
包含 manifest 自身，共 73 项，校验清单自身不自校验。随包只读
verify-delivery.ps1 已实测通过。清单未数字签名，不代表来源认证。

论文 Markdown 只调整交付截图相对路径；需求/设计拆分为互相链接的章节，
没有为凑数量重复数据库和 API 文档。最终 PDF/PPT 与已排版验证的产物哈希一致。
PowerPoint 桌面播放未实测，不将结构检查等同于桌面软件验证。

## 剩余风险与下一步

当前仅验证 Windows x64 / CPython 3.14.6、本机回环、单用户和受控合成样例。
AST 缺少完整变量/作用域/跨文件数据流，存在两项误报与两项漏报；AI 只复核候选。
本轮未验证 Linux/Docker/远程 CI、公网多用户授权、操作系统出站与内存硬限制、
在线依赖漏洞审计。标签尚无独立人类签署，不能外推真实项目总体准确率。

下一步按 [部署手册](deployment.md) 安装并演练答辩，补学校模板、本人/导师信息
与致谢，独立复核标签并完成学校学术审核。唯一开发源码仍在原仓库。
