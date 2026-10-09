# AI-Code-Audit 项目约定

沿用父目录和用户全局约定。本仓是唯一开发源码；modules/ 下能力仓有独立历史，
不要混入本仓提交。原 Python 包、TypeScript CLI 和 FindingSource=004 保持兼容。

修改前读 README、CAPABILITIES 和相关代码。毕业设计本地业务以
docs/graduation/system-design.md、deployment.md 和 docs/tests/graduation-test-report.md
为准；原 CLI 与历史发布记录仍有各自范围。正式交付是从已验证提交导出的快照，
不作为第二套活跃开发仓库。

上传代码只解析，不导入、不执行。AI 为明确同意后的辅助步骤，静态 evidence
和 ai_results 分开保存。Web 保持回环监听与现有资源上限，不能直接扩成公网服务。
真实密钥、.env、源码客户数据、运行数据库和原始模型日志不得进入提交。

Python 测试用已确认的解释器绝对路径调用 scripts/run_python_tests.py，选择
--scope unit 或 integration，沿用独立 basetemp 和 -o addopts=；不要用历史计数替代
本轮执行。修改后跑适用测试、Ruff、类型和前端检查。毕业设计材料构建的运行时
依赖属于作者工具，不增加到产品生产依赖。

交付清单记录实际源码哈希、依赖哈希、测试与已知限制。任何远程推送、合并或
发布需要用户明确授权；本地 Git 固定不表示学校或商用验收通过。
