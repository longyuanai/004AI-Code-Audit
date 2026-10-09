# 部署与使用手册

已验证平台：Windows x64、CPython 3.14.6，本机回环 Web、SQLite、builtin/AST
扫描。Python 3.11+ 是原包声明范围，本轮未实跑其他 Python、Linux、Docker 或
远程 CI。第一版作为本地单用户毕业设计演示使用。

## 已安装版本启动

本轮全新离线环境位于 `artifacts/graduation-20261009/standalone-env`，可以从任意
目录运行以下命令（PowerShell，将项目根路径替换为你的检出目录）：

```powershell
$projectRoot = 'E:\001项目\000开发\Longyuan AI Security Suite\002AI-Code-Audit'
$pythonExe = Join-Path $projectRoot 'artifacts/graduation-20261009/standalone-env/Scripts/python.exe'
& $pythonExe -I -m ai_code_audit.web.server --port 8765 --data-dir (Join-Path $projectRoot 'artifacts/web-data')
```

启动后访问终端打印的本机地址。端口占用时换一个端口，或 `--port 0` 让系统分配；
不得为演示关闭安全软件或改为公网监听。数据目录正被其他实例使用时，启动失败；
先正常结束原实例。Ctrl+C 结束服务会等当前受限任务完成后退出。

## 可复现离线安装

本轮部署候选包 `artifacts/graduation-20261009/portable-wheels-final` 包含 30 个
wheel、requirements.txt（每包版本及 SHA-256）和 manifest.json。包内已包含 HTML/
CSS/JS；product 与 shared-llm-core 从 site-packages 导入，不使用开发 PYTHONPATH。

```powershell
$wheelhouse = 'D:\交付验证\portable-wheels-final' # 搬到与源码无关的目录亦可
$pythonExe = 'C:\你的Python路径\python.exe'        # 使用实际绝对路径
& $pythonExe -m venv 'D:\交付验证\runtime'
$runtimePython = 'D:\交付验证\runtime\Scripts\python.exe'
& $runtimePython -m pip install --no-index --find-links $wheelhouse --require-hashes -r (Join-Path $wheelhouse 'requirements.txt')
& $runtimePython -m pip check
& $runtimePython -I -m ai_code_audit.web.server --port 8765 --data-dir 'D:\交付验证\data'
```

如果使用 uv 创建的环境默认未带 pip，可用已有 uv 替代安装命令：
`uv pip install --python <runtimePython> --no-index --find-links <wheelhouse> --require-hashes -r <requirements.txt>`，
然后 `uv pip check --python <runtimePython>`。本轮实际采用 uv，完整命令/退出码见测试报告。
wheelhouse 当前原生轮子针对 Windows x64/CPython 3.14；换平台应按目标平台重新
收集并锁定 wheel，不应直接复制该虚拟环境。

开发 pyproject 继续使用同级 shared-llm-core 路径依赖。Poetry 构建的原始 wheel
会把它写成开发机器文件 URL。`scripts/prepare_graduation_wheels.py` 仅对独立安装
产物把这一项改成随包提供的版本约束，并重新生成 RECORD；原始 wheel 保留。
这不是删依赖或跳过解析，最终安装使用完整哈希锁和正常依赖解析。复现构建：

```powershell
uv build --offline --wheel --out-dir artifacts/my-build-wheels
uv build ../000shared-llm-core --offline --wheel --out-dir artifacts/my-build-wheels
# 联网获取当前锁定的既有依赖；离线构建本身需要 poetry-core 已可用
& $pythonExe -m pip download --only-binary=:all: -r packaging/requirements-graduation.txt -d artifacts/my-build-wheels
& $pythonExe scripts/prepare_graduation_wheels.py --source artifacts/my-build-wheels --destination artifacts/my-portable-wheels
```

独立产物目录必须新建；脚本拒绝覆盖旧目录。共享源码只读构建，不复制为第二套
活跃源码。当前 wheel 基于工作区候选代码而非最终验收提交；不可将其当成已经
发布的 v1.0.0-graduation。

正式交付包会另从固定 Git 提交构建，并用随包的
`packaging/install-graduation.ps1` 在新环境安装。安装脚本检查 Windows x64 /
CPython 3.14，执行 venv、完整哈希校验和 pip check，拒绝覆盖旧环境。
交付目录中两份脚本放在 `06-部署与运行/`，同级为 wheelhouse：

```powershell
# 在 06-部署与运行 目录执行，填写本机已安装 Python 的实际绝对路径
.\install-graduation.ps1 -PythonExecutable 'C:\你的Python路径\python.exe'
.\start-graduation.ps1
# 用户已有该本机模型时显式启用，否则模型不可用时保留静态结果
.\start-graduation.ps1 -UseVerifiedLocalModel
```

脚本仅调用已经安装的可信服务；启动默认回环端口 8765，可用 `-Port 0`。
模型参数不下载模型，不代表其他机器也已部署 Ollama。最终安装结果和源码版本
以交付验收记录为准，候选环境仅保留为过程证据。

## 开发环境启动

继续按原仓说明安装 Python 包及同级 shared-llm-core，或在完整套件源码环境配置
src、共享 src 和已有 .python-deps 为 PYTHONPATH，再运行
`python -m ai_code_audit.web.server`。本轮干净安装验证没有依赖这种路径配置。
保留 `ai-code-audit` 原 CLI；新增 `ai-code-audit-web` 安装入口。

## 可选模型配置

参考 `.env.example`。这里不自带模型，不自动下载模型，不收集或保存浏览器 API Key。
使用现有共享网关环境变量：LLM_PROVIDERS、LLM_<NAME>_BASE_URL、
LLM_<NAME>_DEFAULT_MODEL、LLM_<NAME>_API_KEY、LLM_<NAME>_TIMEOUT_S 和
LLM_<NAME>_MAX_RETRIES。真实值只放未跟踪的 .env 或进程环境，不提交 Git。
使用隔离启动时推荐在服务进程环境设置它们；不要依赖 .env 的目录自动发现。
Web 的 AUDIT_WEB_PORT/AUDIT_WEB_DATA_DIR 也可用环境设置，命令行覆盖默认值。

用户勾选同意后才请求 AI；未配置/连接失败/格式错误时 AI 状态不可用，原扫描
仍完成并可导出。建议单调用 timeout 15 秒、max_retries 0，整项 AI 作业默认硬超时
90 秒。`--scan-timeout` 和 `--ai-timeout` 接受大于 0 至 300 秒；不允许无限等待。
本机已验证配置如下，不需要密钥或模型下载：

```powershell
$env:LLM_PROVIDERS = 'local'
$env:LLM_LOCAL_BASE_URL = 'http://127.0.0.1:11434'
$env:LLM_LOCAL_DEFAULT_MODEL = 'qwen2.5:3b-instruct-q4_K_M'
$env:LLM_LOCAL_API_KEY = 'no-key-required'
$env:LLM_LOCAL_TIMEOUT_S = '15'
$env:LLM_LOCAL_MAX_RETRIES = '0'
```

用 `ollama list` 查看已有模型，`ollama ps` 查看当前加载模型。另有 qwen3:1.7b 和
qwen2.5:7b，本轮没有测试它们。bge-m3、nomic-embed-text 为嵌入模型，不作为该
聊天复核配置。本轮同样本真实复核没有显示准确率提升。

## 用户操作

1. 填写项目名称，选择 .py 文件、项目目录或只含 Python 文件的 ZIP。
2. 点击“导入项目快照”；原文件不修改，快照在服务数据目录持久保存。
3. 点击项目的“开始扫描”。扫描中自动刷新，完成后可查看风险等级、位置、证据和建议。
4. 如需模型辅助，勾选发送脱敏有限片段的同意框，再点击“AI 辅助分析”。
5. 点击 HTML、JSON 或 SARIF 导出；浏览器保存实际查询结果。HTML 可离线阅读。
6. 重新打开服务，可在检测历史查看旧任务。中断任务重新创建；AI 不可用可重试。

Web 目录导入不会自动执行任何文件。ZIP 中有非 .py、隐藏目录或链接时会被拒绝；
目录选择会跳过非 Python、隐藏目录、node_modules/build/dist。语法错误使任务失败，
没有成功报告；快照在扫描前被改动也会失败。编码须为 UTF-8（允许并规范化 BOM）。

## 备份、回滚和维护

服务关闭后，将整个数据目录备份到由用户管理的安全位置，包含数据库、projects
快照和服务锁文件；不要仅备份数据库而丢掉 AI 上下文对应源码。恢复时先核对版本
和摘要，使用另一个目录测试，不覆盖现有数据。恢复后原服务锁文件内容不影响
操作系统锁。目录最多 30 项目/200 历史任务，达到上限后关闭服务、备份归档，改用
新数据目录。没有自动删除历史功能，避免误删证据。

已有源文件修改前的备份在 `artifacts/graduation-20261009/backup/`。源码回滚先看
Git 差异并比较后续用户修改；不要将备份直接覆盖整个仓库。安装回滚使用保留的
上一 wheelhouse 建立另一运行环境，保留当前数据，先验证兼容性再切换服务。

MIT 许可证和依赖名称/版本随包保留。第三方许可证来源于 wheel 内 metadata/
许可证文件，依赖完整清单见 wheelhouse manifest；未完成法律审查或在线漏洞数据库
审计，不宣称依赖零漏洞。
