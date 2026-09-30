# 开工环境与失败记录

日期 2026-09-27；工作区 `<SUITE_ROOT>`。

- 根 HEAD `4235350fbd4d8858fbaac23f380e6cce87688d61`，status 空，无 remote。
- Code HEAD `0fb5b18d32006c8db08997bbeb383ffcf2bc6ede`，开工 status 空；origin `https://github.com/longyuanai/004AI-Code-Audit.git`。只读 remote 查询，未联网。
- shared-llm-core HEAD `aecaa9ea827f49fe986eec4c7ba8f23c163c9552`；origin `https://github.com/longyuanai/000shared-llm-core.git`。以下既有修改全部保留：

```text
 M AUDIT/012-STRUCT-DEBT.md
 M README.md
 M docs/dispatches/INDEX.md
 M tests/integration/test_cli_envelope_smoke.py
 M tests/test_eval_coverage.py
?? AUDIT/015-OBSERVABILITY.md
?? AUDIT/020-RELEASE-GATE.md
?? docs/adr/ADR-005-web-hosting-carrier-oidc.md
?? docs/dispatches/016-OIDC-DEPLOY.md
?? docs/dispatches/017-RELEASE-WINDOW.md
?? docs/dispatches/020-RELEASE-GATE.md
?? docs/dispatches/021-GATE-UNBLOCK.md
```

解释器 `%LOCALAPPDATA%\Programs\Python\Python314\python.exe`，Python 3.14.6；不在 PATH。首次沙箱启动拒绝访问（未启动，无进程退出码），获准沙箱外运行后 `--version` 及根 `scripts/repair_links.py --check` 均 exit 0，11 个链接 state=ok。没有递归复制 junction 或修改链接。

Git 沙箱只读状态命令提示无法读取 `<USER_HOME>/.config/git/ignore`（Permission denied），status/HEAD 仍成功；未更改权限或 Git 配置。读取命令一次误用 Bash 花括号路径列表，在 PowerShell 解析失败 exit 1，已改正；不是扫描故障。

扫描入口所有正式执行均成功。评测单测另用假工具/异常测试 hash 不符、运行版本不符、第二次扫描失败和输出保护，不能混同真实后端失败。初版 Lint 的失败日志 `c3-2-ruff.log` 与 probe import 排序失败日志 `c3-2-ruff-final.log` 保留；最终日志另存。

类型检查实际运行 `python.exe -m mypy --strict --follow-imports silent benchmarks/c3/realworld.py`，exit 1：No module named mypy。未下载或新增依赖。工具包版本见 `tool-versions.json`；本机依赖不等于可复现的干净安装环境。

> 公开前脱敏（2026-10-01）：本目录及报告中的本机绝对路径已替换为占位符（`<SUITE_ROOT>` = 套件根目录，`<USER_HOME>` = 用户目录，`%LOCALAPPDATA%\Programs\Python\Python314\python.exe` = 当时的解释器），其余字段保持原样；因此文件字节与运行当时不同，`run.json` 中的源码/样本哈希不受影响。
