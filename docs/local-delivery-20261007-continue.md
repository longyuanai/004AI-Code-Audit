# AI代码审计：2026-10-07 续轮验证

本次只完善 Python CLI 的扫描阶段边界，不改变引擎规则、后端选择、门禁或发现 ID。

## 修改与依据

- 原 CLI 对 summary/findings/warnings 直接索引，strict mypy 实测11处错误。新增 `_scan_result_parts`，要求 summary 为对象、files_scanned 为非负整数（拒绝bool）、findings 为对象列表、warnings 为字符串列表。
- 后端、后处理和最终导出边界逐次检查。非法发现不再流入会过滤非对象项的后处理；拒绝输入并退出2，既有报告不会被写成“零发现”。
- 整理导入。两个广义异常捕获只在可选provider初始化/清理边界保留，并逐行说明原因与BLE001豁免；不收窄成会破坏静态报告保全契约的异常列表。已有初始化失败测试与新增清理失败测试验证此行为。
- 新增 `tests/test_scan_result_contract.py` 共10项：8项后端结构拒绝、1项后处理错误保留旧报告、1项provider清理失败保留发现与复核统计。

## 实际验证

- Python integration：370 passed，1条既有cache_dir配置警告；耗时127.90秒。
- 修改CLI与两份新测试：Ruff通过；CLI strict mypy通过（follow-imports silent，未声称全项目类型通过）。
- 既有干净测试环境离线重装最新产品；30个包依赖一致性通过。Windows跨盘硬链接不可用时uv使用复制，无安装失败。
- 安装版 `python -I` 在源码目录外运行：真实自有36文件快照0发现，JSON和SARIF导出通过；合成input→eval为1发现/退出1，literal_eval后0发现/退出0。
- 首次续轮验收辅助脚本默认GBK读取UTF-8结果失败，原证据保留。显式UTF-8后在新目录installed-check-2重跑全部5项安装版验收通过；不是产品扫描失败。
- git diff --check通过。TS本轮未改/未重跑；上一轮593 passed、2 skipped以及lint/typecheck/build结果仍标明为历史验证。

## 证据与限制

证据目录 `artifacts/delivery-20261007-continue/`，最终安装验收 `installed-check-2/delivery-result.json`。
备份在其backup/，回滚须先比较用户后续修改，不能直接覆盖。
真实召回率未知；0发现不代表安全。Opengrep安装规则、远程CI、原生网络隔离、真实客户和独立人类签署尚未补验。本轮没有发布或推送。
