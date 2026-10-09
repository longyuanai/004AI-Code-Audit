# 毕业设计真实测试报告 2026-10-09

结论：本机软件核心流程、关键导入安全、真实模型复核和同样本 AI 实验通过。
最终回归 427 passed。固定源码及导出安装版已经复核，详见最终版本记录。
学校模板尚未提供，草稿不能替代学校验收。

## 环境与命令约定

Windows 11 x64，CPython 3.14.6；新代码 strict mypy 使用已有 Python 3.12.14 /
mypy 1.20.2，静态分析目标为原包声明的 Python 3.11+。Ruff 0.16.1。
测试工作目录为唯一 Code 仓库。以下 `$pythonExe` 是已现场确认的
`C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe`，所有 pytest
调用通过现有脚本使用独立系统 basetemp、`-o addopts=` 和显式 scope。
日志在 artifacts/，项目内不存真实密钥、客户代码或模型原始日志。

## 实际执行与证据

| 检查 | 实际命令 / 操作 | 结果 / 退出状态 | 日志 |
|---|---|---|---|
| Python 初始基线 | `& $pythonExe scripts/run_python_tests.py --scope integration tests -q` | 370 passed，exit 0 | graduation-baseline-python-normal.log |
| TS 初始基线 | `npm run test:run` | 593 passed、2 skipped，exit 0 | graduation-baseline-ts-unsandboxed.log |
| 新功能首轮 | `--scope unit tests/test_graduation_security.py tests/test_graduation_workflow.py -q` | 48 passed、2 failed、2 errors，exit 1 | graduation-new-tests-1.log（已脱敏） |
| 首轮修复回归 | 同上，增加 `--tb=short` | 51 passed，exit 0 | graduation-new-tests-2.log |
| 全量 Python 集成 | `--scope integration tests -q --tb=short` | 426 passed，exit 0 | graduation-regression-python.log |
| 数据库回滚后最终集成 | 同上 | 427 passed，exit 0；115.77 秒 | graduation-regression-final-v2.log |
| 最终受影响检查 | `--scope unit tests/test_graduation_security.py tests/test_graduation_workflow.py tests/test_triage_context.py -q --tb=short` | 63 passed，exit 0 | graduation-targeted-final.log |
| Python Lint | `-m ruff check` 新增模块、脚本、测试及 triage_context.py | exit 0 | graduation-ruff-final.log |
| 类型检查 | 既有 Firmware Python `-m mypy --strict --follow-imports silent` 新模块/脚本及上下文，共 11 源文件 | exit 0 | graduation-mypy-final.log |
| 最终类型检查 | 同上，MYPYPATH 仅产品与共享 src，共 12 源文件 | exit 0 | graduation-mypy-v4.log |
| TS 类型/构建 | `npm run typecheck`、`npm run build` | 均 exit 0 | graduation-ts-typecheck.log、graduation-ts-build.log |
| 前端 Lint | `npm run lint` | 修复后 exit 0 | graduation-ts-lint-final.log |
| 浏览器 JS | `node --check src/ai_code_audit/web/static/app.js` | exit 0 | 本轮工具输出 |
| 合成标注实验 | `scripts/graduation_eval.py --output docs/tests/graduation-evaluation.json --repeat 3` | 三次一致，exit 0 | graduation-evaluation.json |
| 独立安装 | `uv build --offline --wheel`；prepare_graduation_wheels；`uv pip install --no-index --no-cache --find-links ... --require-hashes -r .../requirements.txt` | 30 包离线安装，exit 0 | graduation-install.log、wheel-build-final.log |
| 安装版验证 | 源码目录外，清空 PYTHONPATH，以安装版 `python -I scripts/graduation_smoke.py --data-dir ...` | 13/13 检查 true，exit 0 | graduation-standalone-smoke.log、standalone-smoke/smoke-result.json |
| 依赖一致性 | `uv pip check --python .../standalone-env/Scripts/python.exe` | 30 包兼容，exit 0 | graduation-dependency-check.log |

最终全量 427 = 原有 370 + 新增 57；此前 426 和受影响 63 是阶段记录，不能相加。
TS 两项 skip 为真实 provider 验收/triage，不能计入通过。Python 有一项既有
cache_dir 配置 warning：测试脚本禁用 cacheprovider 时 pytest 报 unknown config；
不影响退出状态，未通过删除警告或测试掩盖问题。

## 失败事实和修复

第一次 Python 使用沙箱映射的 LOCALAPPDATA 找不到解释器，改为绝对路径。
沙箱仍不能解析解释器/原生依赖真实路径，产生大量环境错误，该轮已停止；正常
权限基线 370 passed。TS 第一次沙箱 realpath EPERM，无法收集，正常权限重跑通过。
这些是环境故障，未记为产品通过或测试正确率。

新增测试首轮：SARIF 导出函数实际接收 findings 而非 envelope，已修正并验证
HTML/JSON/SARIF。HTTP 提前拒绝请求但不消费小请求体，在 Windows 上触发连接
中断，已增加有界读取和关闭响应，正常/错误输入复测通过。超大 bytes 参数被
pytest 用作测试名，超过 Windows 环境变量长度，已设置短测试 ID。
该工具失败日志出现进程环境信息，已删除环境值并压缩超长参数展示，保留堆栈、
失败原因和退出状态；没有提交原始日志。后续使用短堆栈输出。

首次新增严格类型检查发现 HTML escape lambda 无类型、HTTP override 参数过窄；
改成有类型函数和与基类兼容的签名。脚本再发现三处类型诊断，均修复。
第一次 ESLint 不认识浏览器全局变量，静态 JS 已明确声明只读全局；未关闭 Lint。
凭据上下文复核发现 secret/passwd/private_key/auth_token 未覆盖，补齐脱敏和四项
回归；Web 仍显式关闭原始模型审计。最后令牌非 ASCII 情况也有 HTTP 回归。
最终复核还补上数据库插入失败后的快照回滚，避免导入失败留下孤立源码目录；
真实 SQLite 错误注入回归检查了数据库、项目目录和临时目录均没有残留。
最后一次类型检查曾因只设置 PYTHONPATH 而读到无类型安装包，改为 MYPYPATH 后
又读到旧 .python-deps 第三方桩的六项诊断；最终只使用产品与共享源码路径，沿用
既有类型检查环境，12 源文件 strict 检查通过，没有关闭产品类型规则。

论文 PDF 和答辩 PPT 构建属于作者工具。本机自带 ReportLab/Poppler 已生成并逐页
检查论文；答辩 PPT 首轮缺少表格校验声明，第二轮字体字段不正确，第三轮首方
导入检查缺运行时环境；分别修正后第四轮结构、字体、布局、首方导入均通过。
相关候选与失败日志保留在 artifacts/graduation-20261009/materials-build 和
graduation-materials-ppt*.log，不冒充产品故障或学校模板验收。

## 测试范围

规则：五类正反例、别名导入、注释/字符串排除、潜在风险标签与凭据不泄露。
上传：路径穿越/绝对路径/反斜杠/保留名/ADS/隐藏目录、大小写重复、文件目录
冲突、非法 Base64、UTF-8/空字节、文件大小、数量、ZIP 链接/特殊文件/高压缩比。
工作流：真实扫描工作进程、SQLite 关联、HTML/JSON/SARIF、代码不执行的 marker
验证、真实 0.001 秒工作进程超时、语法错误、快照篡改、数据目录单实例锁、队列
上限、重启恢复、AI 协议成功和不可用保留证据、HTML 恶意名称/代码转义。
HTTP：真实本机 socket，Host/Origin/token、非 ASCII token、超大请求、AI consent。
协议成功使用 stub，仅证明应用如何接收和保存响应，不是模型能力证明。

## 浏览器端到端记录

使用内置真实浏览器，不用直接 API 请求代替界面操作：

1. 输入“毕业设计演示”，选择受控 `benchmarks/c3/demo_project/before/app/calculator.py`。
2. 界面显示 1 文件/168 字节，点击导入后项目列表出现。
3. 点击开始扫描，任务由运行中变为完成；1 文件、1 发现、1.123 秒。
4. 展开详情，显示 `CG-PY-004`、calculator.py:6、eval(expression) 和修复建议。
5. 明确同意后请求 AI，返回不可用；静态任务仍完成，发现仍为 1。
6. 点击导出 HTML，浏览器实际下载报告；HTTP/API 检查另验证 JSON 和 SARIF。
7. 页面已切换到独立安装的服务进程；同一已完成历史仍保留。
8. 找到本机 Ollama 后，在独立安装服务进程环境配置 Qwen 3B，重试该任务。
   界面显示 AI 完成、实际模型名和中文解释，静态证据仍为 calculator.py:6。
9. 展开 AI 推断并再次导出 HTML，真实浏览器下载成功。

截图为真实页面：[完整流程截图](screenshots/graduation-browser-flow.jpg)。原报告
下载保存于本机 Downloads，任务 ID aa9fdcdc56f74cc8ab6248505cf3e857；不把下载路径
或页面状态当作最终版本提交证据。
真实 AI 截图：[模型复核与证据](screenshots/graduation-real-ai-flow.jpg)。

## 毕业设计实验数据

数据集为 `benchmarks/graduation/labels.json`，版本 graduation-python-synthetic-20261009，
20 个手工合成样例（10 阳性/10 阴性），逐例包含来源和标注理由。标注由实现者
准备，尚未经独立人员签署。SHA-256、逐例输出和三次运行在
[机器记录](graduation-evaluation.json)。按样例的目标规则是否命中计 TP/FP/FN/TN；
不是按整仓库“有没有任何发现”计，也不是漏洞可利用性真值。

| 次数 | TP | FP | FN | TN | Precision | Recall | 平均静态引擎秒/样例 |
|---|---|---|---|---|---|---|---|
| 1 | 8 | 2 | 2 | 8 | 0.80 | 0.80 | 0.001694 |
| 2、3 | 8 | 2 | 2 | 8 | 0.80 | 0.80 | 详见原始 JSON |

Precision=TP/(TP+FP)，Recall=TP/(TP+FN)。FP 为固定 os.system 命令和常量 eval；
FN 为先赋值再执行的 SQL 和字典硬编码凭据。实验不为提高数字移除这四项。
静态引擎计时不含文件写入、进程启动、HTTP 与 SQLite；安装版两个真实任务耗时
分别 0.675869 和 0.689073 秒（包含工作进程启动和结果处理），不能混为同一指标。
随后找到用户本机 Ollama 0.40.0，模型 qwen2.5:3b-instruct-q4_K_M，摘要
357c53fb659c5076de1d65ccb0b397446227b71a42be9d1603d46168015c9e4b。
用独立安装解释器执行 `scripts/graduation_ai_eval.py --repeat 3 --model-digest
<上述完整摘要> --server-version 0.40.0 --output docs/tests/graduation-ai-evaluation.json`，
exit 0。模型环境为回环 11434、timeout 60、retries 0；实际请求温度 0、max_tokens
500、json_object。逐例结果、时长与参数见 [AI 机器记录](graduation-ai-evaluation.json)，
日志 graduation-real-ai-evaluation.log。三次分别 10 个 reviewed、0 个 error，共 30 次
真实请求；无候选样例不调用模型。AI 没有修改静态 envelope。

| 方式（三次均一致） | TP | FP | FN | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| 静态 | 8 | 2 | 2 | 8 | 0.80 | 0.80 |
| 静态 + AI 评价过滤 | 8 | 2 | 2 | 8 | 0.80 | 0.80 |

过滤口径：仅 reviewed 且 confirmed=false 时排除候选，错误保留，静态漏报不新增。
过滤只用于实验，产品保留所有静态发现。本轮 **没有观测到指标提升**。模型曾对
eval 给出参数化查询建议，这是语义不准确的建议；保留此证据，不执行该建议。
首次独立模型证明耗时 4.354614 秒，结果文件 artifacts/graduation-20261009/real-ai-proof.json。

## 验收状态与剩余风险

| 原验收项 | 状态 |
|---|---|
| 按手册启动、真实文件输入、静态输出、存储查询、导出、Web 核心业务 | 本机候选版通过 |
| 关键上传/路径/超时/XSS 安全测试 | 本轮覆盖项通过；不代表完整渗透或依赖漏洞审计 |
| AI 成功运行且失败合理降级 | 协议成功、真实 Qwen 成功、真实降级通过 |
| 无已知阻断性故障 | 已验证本地范围没有发现阻断；其他平台仍待实测 |
| 固定 Git 提交、最终导出版本、正式材料 | 软件提交 1ef74c9；Git 导出与独立安装通过，通用材料已交付 |

最终提交、标签和 Git 导出安装必须在完整状态复核后记录；本报告不代替交付清单。
学校论文/PPT 模板、个人信息和独立学术审核仍待补充。
未验证公网多用户权限、原生出站网络隔离/内存硬限制、Linux/容器、第三方依赖
在线漏洞审计。AST 已知误报/漏报属于披露的检测局限，不当作全部漏洞覆盖。

## 最终版本记录

软件提交 `1ef74c96a7082e104ebebc7d8e3fd4677a394e8e`，本地标签
`v1.0.0-graduation` 指向该提交；Python 包沿用 0.6.0。标签未推送、未远程发布。
共享核心固定提交 `8dd1bbd5e855d68e5476540f7e533af596f1cf46`，版本 0.6.0。

Git archive 导出 457 项（含目录），未携带 .git、.env、虚拟环境、缓存或运行数据库。
从导出源码离线构建产品 wheel，29 个其余固定 wheel 与其组成 30 包 wheelhouse。
导出的 install-graduation.ps1 实际创建新 venv、正常依赖解析、--require-hashes
安装及 pip check，exit 0。构建时 shared 路径缺失的警告保留，安装产物只将该
file URL 改为随包 shared-core 的 0.6.0 约束并重新生成 RECORD，没有删依赖。
安装版 71 个源码及静态文件与 Git 导出逐字节一致。

清空 PYTHONPATH，从源码目录外以安装版 python -I 调用导出 smoke 脚本：
无模型/真实 Qwen 成功两条路径分别 13/13 true、exit 0；原静态证据不被覆盖。
最终实际完整任务耗时见两份 smoke-result JSON，不将其与 AST 引擎计时混用。
导出的 start-graduation.ps1 -Port 0 -UseVerifiedLocalModel 实际分配端口 8118，
HTTP GET / 返回 200；操作者 Ctrl+C 结束 PTY，外层会话返回 1，已确认无残留
验证进程。这是启动/人工终止记录，不当成新增自动化测试通过计数。

论文 PDF 17 页、PPT 11 页，最终全页排版复核；PPT 3 张原生可编辑表格，
结构、字体策略、布局与首方工具导入检查通过。最终修正图中箭头方向，并以
真实浏览器 AI 详情截图替换过小的完整页面缩图。未实际使用桌面 PowerPoint
播放，不把文件结构检查等同于桌面应用验证。作者工具的一次重试因旧验证
收据 EEXIST 失败，改用新构建目录后通过；旧稿及失败日志保留在开发 artifacts。

可机读收据、最终 SHA-256 与实际材料以交付目录 10-交付清单 为准。
学校模板、本人信息与独立学术/标签复核仍待学生补充。
