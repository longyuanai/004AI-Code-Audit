# C3 第一阶段：质量基线与可复现交付样例

日期：2026-09-24。状态：本机源码运行验证（Windows，Python 3.14.6）；C3 提交 5a5f0bb 并与 main 合并后推送，远程 CI 结果见 PR；未在干净环境安装验证，不是 GA。

## 1. 评测范围

| 项目 | 内容 |
|---|---|
| 语言 | Python（仅此一种；C++/Go/Java/TS 不在本轮范围） |
| 后端与规则 | builtin 默认后端 `004-phase2-taint`（`src/ai_code_audit/scanner.py` 文本 source/sink 启发式）；opengrep 后端 `CG-OG-PY-001`（`rules/opengrep/taint.yaml`，CWE-95） |
| 引擎版本 | Opengrep 1.26.0，二进制原始字节 SHA-256 在启动前与 `benchmarks/phase0/OPENGREP.lock` 校验，不符即不执行（写入 `run.opengrep_pin`）；二进制不入库 |
| 语料 | `benchmarks/c3/corpus/python`，版本 `c3-python-2026-09-24`，全部为合成样例：7 个漏洞行、9 个安全行（容易误报 6、修复后 3） |
| 标注 | 行内 `c3-expect` 标记 + `benchmarks/c3/labels.json` 逐例理由，依据代码事实人工编写，未使用扫描输出生成 |
| 方法 | 复用 Phase 0 行级方法（`benchmarks.phase0.benchmark.Location`），经产品入口 `scan_payload` 扫描，按规则计分 |

计分：规则声明的 CWE 集合（labels.json `claimed_cwes`）内的漏洞行才计 TP/FN；报在安全行或未标注行计 FP；报在声明范围外的漏洞行记 out_of_scope（不计 TP/FP）；没有任何规则声明的漏洞类别记 unsupported；分母为零时 precision/recall 为 null（N/A）；扫描失败记 error，不计为零发现。

**这些是小规模合成样例上的回归基线，不代表真实项目准确率。** 本轮没有授权真实项目样本，未下载或扫描任何外部目标。

## 2. 结果（2026-09-24，本机，三次重复结果一致）

| 后端 | 规则 | TP | FP | FN | TN | 范围外 | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| builtin | 004-phase2-taint | 6 | 4 | 1 | 5 | 0 | 60.0% | 85.7% |
| opengrep | CG-OG-PY-001（修复后） | 5 | 0 | 0 | 9 | 0 | 100.0% | 100.0% |
| opengrep | CG-OG-PY-001（修复前） | 3 | 0 | 2 | 8* | 0 | 100.0% | 60.0% |

**合并 main 后（2026-09-24，含 main 5d4d60c 扫描器修复）**：语料与标注未改，builtin 重测为 TP 5 / FP 2 / FN 2 / TN 7（P 71.4%、R 71.4%），opengrep 不变。变化原因：main 在匹配前清空注释与字符串，PY-FP-03（注释）、PY-FP-04（字符串）不再误报；sink 只与同一函数内的 source 配对，PY-CI-02（`os.getenv`，builtin 本就不认作 source）此前是借同文件另一函数的 `input()` 偶然命中，现为 FN。builtin 命中现为 medium/0.5，演示门禁因此由 high 改为 medium（opengrep 命中为 high，仍会触发）。三次重复一致，两种后端演示全部检查通过。

\* 修复前语料尚无 PY-FP-06，安全行为 8。opengrep 修复后的 100% 是**样本内**结果：该语料同时用于发现并验证修复，不能外推。

- builtin 声明 CWE-89 但语料无 SQL 注入样例（`claimed_cwes_without_cases`），该类未测。
- opengrep 包没有 CWE-78 规则：PY-CMD-01/02 记为 unsupported，不是 FN。
- 时间（非确定，仅供量级参考）：builtin 约 0.01 s，opengrep 约 2.4 s。

### 误报/漏报原因分析

| 用例 | 结果 | 原因 | 处理 |
|---|---|---|---|
| PY-FP-01 常量 eval、PY-FP-06 常量 exec | builtin FP | 文件级启发式：首个 source 行之后的任何 sink 都算一条流，无数据流 | 不修（引擎级限制，Phase 0 已记录；opengrep 后端正确） |
| PY-FP-03 注释中的 `eval(`、PY-FP-04 字符串中的 `system(` | builtin FP | SINK_PATTERN 对原始文本匹配，不区分注释/字符串 | 不修（需语法感知，属引擎改动） |
| PY-CI-05 sink 定义在 source 之上 | builtin FN | 只接受 source 行之后的 sink 行 | 不修；opengrep 过程内污点可覆盖 |
| PY-CI-03 `sys.argv` → eval、PY-CI-04 input → `exec` | opengrep FN（修复前） | 规则 sources 缺 `sys.argv`，sinks 缺 `exec(...)` | **已修**（见 §3） |
| 标注初稿中 PY-CI-05 被 builtin “命中” | 偶然 TP | 模块 docstring 中的单词 input 被 SOURCE_PATTERN 当作 source | 改写 docstring 使样例只测其目标；同时说明 builtin 会被注释中的 source 词触发 |

另发现（未修，记待办）：opengrep 后端的 Finding `id` 由指纹生成（规则 + 路径 + 代码片段），同一文件两处片段完全相同时两条 Finding `id`/`fingerprint` 相同（Phase 0 python 语料第 6、11 行可复现）。基线按指纹计数过滤，因此新增同片段问题仍会显示（计数多出一条），但 envelope 内 ID 不唯一；更改 ID 方案会影响 SARIF/基线兼容，本轮不改。

## 3. 本轮修复

`rules/opengrep/taint.yaml` 的 `CG-OG-PY-001`：sources 增加 `sys.argv`，sinks 增加 `exec(...)`（仍为 CWE-95，消息不变）。影响范围：仅 Python 的 `backend=opengrep|auto` 扫描可能多报这两类真实问题；builtin 后端、TypeScript 实现、Phase 0 评测规则（独立文件）不受影响。回归证据：修复前 TP 3/FN 2 → 修复后 TP 5/FN 0，新增安全用例 PY-FP-06（常量 exec）未误报；`tests/test_c3_quality.py` 锁定该结果（需本机固定版 Opengrep，缺失时显式 skip 并给出原因）。

## 4. 复现命令（源码运行）

在 `002AI-Code-Audit` 目录（PowerShell，`$pythonExe` 为满足依赖的解释器）：

```powershell
# 质量基线：双后端重复 3 次（退出码见下表）
$env:PYTHONPATH = "src;..\000shared-llm-core\src;.python-deps;."
& $pythonExe -m benchmarks.c3.quality --repeat 3 --json-output <out>\quality.json --markdown-output <out>\quality.md
# 可选 --opengrep <path>（默认 tools\opengrep\v1.26.0\opengrep.exe）；--backend builtin 只评 builtin，不需要 Opengrep

# 交付演示（不需要设置 PYTHONPATH；输出目录须为空或不存在；builtin 不需要 Opengrep）
& $pythonExe .\scripts\c3_demo.py --output-dir <空目录> [--backend builtin|opengrep]

# 测试（C3 用例在两种范围内均运行；演示用例属 integration）
& $pythonExe .\scripts\run_python_tests.py --scope unit
& $pythonExe .\scripts\run_python_tests.py --scope integration
```

质量脚本输出：`result`（确定性：语料/规则文本哈希、标注计数、所选后端、逐规则 TP/FP/FN/TN、明细、unsupported、重复 ID；失败后端为 `status: error` + `reason`，规则指标为 null，不填零）与 `run`（Python/平台、`opengrep_pin`、耗时、repeat、`backends_required`、`execution_ok`、`failed_backends`、`repeat_identical`、`exit_code`、`exit_reason`）。Markdown 顶部同样给出状态行与 pin 结果。

### 评测脚本退出码（2026-09-24 验收修复；不影响产品 scan/enrich 的 ADR-006 契约）

| 退出码 | 含义 | 报告 |
|---:|---|---|
| 0 | 所选后端全部执行成功，且重复运行 `result` 段一致 | 写出 |
| 4 | 任一所选后端失败：Opengrep pin 校验失败（missing / unreadable / lock_invalid / hash_mismatch，reason 为 `opengrep_pin_<原因>`）、后端不可用或执行错误（`execution_error`） | 写出（诊断保留） |
| 3 | 全部执行成功但重复结果不一致（`repeat_mismatch`） | 写出 |
| 2 | 参数错误、标注/语料无效或报告写入失败 | 不保证写出 |

优先级 2 > 4 > 3 > 0：“执行成功”（`execution_ok`）与“重复一致”（`repeat_identical`）分别判定并分别记录；执行失败时即使三次失败结果一致也返回 4。所有通过 `--backend` 选择的后端都是必需的（默认 builtin + opengrep）。

`scripts/c3_demo.py` 退出码：0 全部检查通过；1 有检查失败；2 参数或前置条件缺失；4 Opengrep pin 校验失败（写出只含失败原因的 `demo-summary.json`，`opengrep_started: false`，不建项目、不启动任何子进程）。

### Opengrep 执行前门禁

`benchmarks/c3/opengrep_pin.py`（质量脚本与演示共用）在启动 Opengrep **之前**校验实际所选二进制：读取 `benchmarks/phase0/OPENGREP.lock`（须有 version 与 64 位十六进制 sha256，否则 lock_invalid），对二进制**原始字节**计算 SHA-256（不做换行转换），缺失 → missing，不可读或非普通文件 → unreadable，不符 → hash_mismatch。校验通过后才把该精确路径（及评测规则目录）交给产品；不自动下载，不改锁文件。测试用占位文件与 `subprocess.Popen` 记录器证明校验失败时没有启动任何进程。

## 5. 演示内容与预期

`scripts/c3_demo.py` 在输出目录中建立合成项目 git 仓（`benchmarks/c3/demo_project` 的 before/after 两次提交），用子进程调用真实 CLI `python -m ai_code_audit`，并写出 `demo-summary.json`（命令、预期/实际退出码、每步发现的规则/路径/行/指纹、逐项检查；`result` 段两次运行逐字节一致，时间与路径放 `run` 段）。

| 步骤 | 命令要点 | 预期退出码 | 输出 |
|---|---|---:|---|
| 修复前扫描 | `scan --json --input {repo_path, backend, fail_on: medium} --output-file` | 1（门禁） | reports/before.json |
| 修复前 SARIF | `scan --output sarif --input … --output-file` | 1 | reports/before.sarif |
| 写基线 | payload `write_baseline: .codeguard/baseline.json`（必须位于被扫仓库内，随 after 提交保留） | 1 | project/.codeguard/baseline.json |
| 真实扫描的 Markdown | `enrich --envelope before.json --cache <不存在的临时路径> --output markdown` | 1（沿用输入门禁 medium） | reports/before.md：`skipped` / `no_queryable_cve`，逐条 `not_applicable`，缓存未创建 |
| 修复后扫描 | 同上 | 1 | reports/after.json：calculator.py 消失，admin.py 新问题出现 |
| 基线复查 | payload `baseline_path` | 1 | 仅 admin.py；summary.baselined 记录被基线接受的条数 |
| diff 复查 | payload `diff: {base: HEAD~1, head: HEAD}` | 1 | 仅变更行上的 admin.py |
| 合成 CVE 增强 | `enrich --envelope synthetic-cve-envelope.json --cache <演示临时缓存>`，JSON/SARIF/Markdown | 0 | synthetic-enriched.*：enriched、enriched、unknown、not_applicable；阶段 partial，network_refresh false |
| 严格模式 | 加 `--require-intel` | 3 | synthetic-strict.json（报告仍完整） |

期望发现（按 demo_project/README 人工推导）：builtin 修复前 calculator.py + report.py，修复后 report.py + admin.py；opengrep 修复前 calculator.py，修复后 admin.py（report.py 为 CWE-78，opengrep 包不覆盖）。两种后端均通过全部检查。

合成 CVE envelope 顶层带 `x_c3_demo` 标注，每条标题为 “SYNTHETIC … (not a scan result)”；情报缓存由漏洞模块自身 `CVEEnricher` + 假 provider 写入演示目录（CVE-2024-1111 三源、CVE-2024-3333 仅 EPSS、CVE-2024-4444 缺失）。真实扫描结果从不附加 CVE。

网络验证范围（2026-09-24 验收修复后如实区分，`demo-summary.json` 的 `result.network_verification` 同样记录）：

| 层面 | 状态 | 依据 |
|---|---|---|
| Python 层（每个 `python -m ai_code_audit` 子进程） | 已拦截并检查 | sitecustomize 阻断 socket/DNS/httpx 并记日志，`network-guard.log` 必须为空；代理变量指向失效的 127.0.0.1:9 |
| 原生子进程：`git`（演示仓库与 diff 扫描）、Opengrep 二进制（opengrep 后端） | **未验证** | sitecustomize 无法作用于原生进程；本轮没有操作系统级出站阻断。产品为 Opengrep 设置的关闭遥测环境变量只是配置，不是隔离 |
| 演示驱动进程本身 | 未加拦截 | 只用内存中的假 provider 写合成缓存 |
| 整个进程树零网络 | **未验证** | 不宣称 |

其他约束：模式 fast，不调用 LLM；清除子进程中 `CODEGUARD_*`、`OPENAI*`、`ANTHROPIC*`、`LLM_*` 环境变量；所有 enrich 显式 `--cache` 到演示目录，不读用户真实情报缓存或秘密配置；未访问真实情报源，未修改机器代理或防火墙。

## 6. 依赖与复现边界

| 需要 | 版本 | 说明 |
|---|---|---|
| 002AI-Code-Audit | 5a5f0bb（C3）及其与 main 的合并提交 | benchmarks/c3、scripts/c3_demo.py、tests/test_c3_quality.py、规则修改、本文档 |
| modules/vulnerability-analysis | dcb2f29 | 演示 enrich 与缓存写入；CI 已锁定该 SHA（已推送 agent/commercial-docs） |
| 000shared-llm-core | 本机 aecaa9e（工作区另有既有未提交修改） | CI 作业检出 `master`，未锁定 SHA |
| Python 依赖 | 本机 `.python-deps`（tree-sitter 绑定，未入库）与用户站点包 | CI 的安装清单见 `.github/workflows/ci.yml`，未在干净环境验证 |
| git | 本机 | 演示的 diff 步骤需要 |
| Opengrep 1.26.0 | 仅 opengrep 后端需要 | 须与 OPENGREP.lock 原始字节哈希一致；缺失或不符时评测与演示退出 4 且不启动；依赖真实二进制的两个测试在缺失时显式 skip，门禁负向测试不需要二进制 |

- 质量脚本与演示**不依赖**根仓 `suite.py`；它们只需上述两个产品仓与 shared-llm-core。
- 依赖根仓未提交文件的能力：`suite.py code audit -- enrich` 能导入漏洞模块依赖根 `suite.py` 的 `EXTRA_SOURCES`；根入口测试 `tests/test_suite_code_enrich.py`、`tests/test_suite_launcher.py` 与 `scripts/repair_links.py` 同样未提交。因此“只检出两个产品提交”不能复现经根入口运行的 enrich；当前整个工作区可运行不等于提交可复现。
- 已验证的是**源码运行**（PYTHONPATH 指向源码）。`pip install` / wheel / Poetry 安装、Linux、Python 3.11/3.12 均未验证，不得写成已支持。

## 7. 未验证与待办

见 [TODO](TODO.md) C3 “发布前待办”：原生子进程（git、Opengrep）网络隔离、远程 CI、Linux、Python 3.11/3.12、干净环境安装、真实情报数据写出的缓存、根仓提交、真实授权项目样本、TypeScript 侧（本轮未改未运行）。
