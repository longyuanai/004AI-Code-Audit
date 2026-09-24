> 当前主目录编号：001 Agent / 002 Code / 003 Firmware。旧产品 API 来源编号保持兼容。

# 能力归属（2026-09-23）

本产品接收 `vulnerability-analysis` 能力，代码位于 `modules/vulnerability-analysis`，保留独立 Git 历史和依赖。
产品主仓提交不会携带该模块；须分别在模块仓提交，克隆时按根目录仓库清单恢复。
根目录 `suite.py` 提供产品级能力入口，模块仍使用原 CLI 与 Finding 契约。
本次是代码目录归属和调用入口合并，尚未把不同分析结果自动汇总为一次扫描。
固件的 vulnerability 能力使用 Code Audit 所拥有的同一份模块，不维护分叉副本。
原 README 的产品编号、独立产品描述及历史测试数仅作历史说明；本文件和根 README 为新布局入口。
