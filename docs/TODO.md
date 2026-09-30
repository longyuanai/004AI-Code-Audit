# 002AI-Code-Audit 开发任务

日期：2026-09-23。以下任务均为待执行；历史已有功能见 tech-spec，不把旧 TODO 的完成状态机械搬来。

每轮只做一个有验收边界的任务，建议 Code 首轮组合 C0 与 C1。任务完成后填写证据、日期和提交，不仅打勾。

[本项目技术规范](tech-spec.md) · [全局交接指南](../../docs/MODEL-HANDOFF.md)

## C0 — 现场基线和边界记录

- 状态：已完成（2026-09-23；记录随 2026-09-24 文档提交入库）。
- 工作：读取 Code 与漏洞模块 status、相关扫描/enrichment/cache 源码，执行受影响基线。
- 验收：记录解释器、命令、退出码、原有差异；确认 source 限制、联网路径、描述覆盖事实。
- 依赖与范围：无；只读与文档记录，不改功能。
- 完成证据：
  - 实际根目录 `<SUITE_ROOT>`（文档仍写 003AI-Network-Security）。Code HEAD 2c34661（agent/ai-codeguard-fusion），漏洞模块 HEAD 00f6199（agent/commercial-docs）；两仓开始时均有既有文档/测试未提交修改，已保留。
  - 解释器 Python 3.14.6（`%LOCALAPPDATA%\Programs\Python\Python314\python.exe`）；`-o addopts=`、独立短路径 basetemp；PYTHONPATH = 本仓 src、shared-llm-core/src、shared-integration/src、Code .python-deps。
  - Code `pytest tests`：185 passed，exit 0。basetemp 放在过长路径时 `test_local_git_url_is_shallow_cloned_and_scanned` 因 Windows `Filename too long` 失败，属环境问题。
  - 漏洞模块 `pytest tests`：183 passed、1 failed，exit 1。失败为 `test_cli_envelope.py::test_json_subprocess_adapter_end_to_end`：根 `.compat` 与 Firmware `modules/vulnerability-analysis` junction 仍指向旧目录 003AI-Network-Security，目录改名后悬空。与产品代码无关，未修改布局。
  - 现场探针确认：`enrich_envelope` 对 source `004` 抛 “must use source '002'”；对 `002` 将 description 替换为 PRisk narrative；`CVEEnricher` 缓存未命中确实发起外网请求（本机 HTTP(S)_PROXY 在 loopback，EPSS 取回真实数据，NVD/KEV temporary_error），且 KEV 错误时 metadata 无 kev 字段、combined 记录 `in_known_exploited=False`。
  - 真实扫描：`suite.py code audit -- scan --json --repo-path <Unicode 路径> --fail-on any` 输出 1 条 source `004` Finding，exit 1（门禁生效）。Python 静态 Finding 当前不带 `cve`；`--output-file` 仅对 SARIF 生效，envelope 输出时被静默忽略（留给 C2）。

## C1 — 纯离线 CVE 桥接核心

- 状态：已实现并提交（2026-09-23；Code 18c9924、漏洞模块 554c247，2026-09-24 推送）；独立复核通过。
- 工作：产品内纯转换 + 显式只读缓存适配；必要时漏洞模块新增只读公共查询；不接默认 CLI。
- 验收：004 原字段与未知字段保留、输入不变、缺失/过期/非法 CVE、provider unknown、重复 CVE；三种缓存路径断网零请求；旧 002 契约不变。
- 依赖与范围：C0；只允许 Code、唯一漏洞模块及对应文档/测试。
- 完成证据：
  - 实现：Code `src/ai_code_audit/cve_intel/`（bridge.py、cache.py），字段见 tech-spec §5；漏洞模块 `ReadOnlyEnrichmentStore`（store.py，tech-spec §8.4）。未改 CLI、Finding 枚举、`enrich_envelope`、依赖或共享契约。
  - 测试：`tests/test_cve_intel_bridge.py`（43）、`tests/test_cve_intel_cache.py`（5，用模块自身 CVEEnricher+假 provider 写入真实 SQLite 后只读桥接，socket/httpx 全阻断含 loopback）、fixtures/cve_intel 金样；漏洞模块 `tests/test_enrichment_store_readonly.py`（7）。
  - Code 全量：默认 PYTHONPATH 228 passed、1 skipped（test_cve_intel_cache 需漏洞模块 src），exit 0；追加模块 src 后 233 passed，exit 0。漏洞模块全量 190 passed、1 failed（同 C0 悬空 junction），旧 002 enrich/envelope 契约测试均通过。
  - 变异检查：缺失 KEV→false、过期当新鲜、覆盖 description、放行非 004 四种篡改分别被 4/5/3/5 个用例捕获。
  - ruff（用户级规则）新文件通过；mypy 1.20.2 `--strict` 对 `ai_code_audit.cve_intel` 通过，store.py 默认模式通过（Firmware .venv 的 python -m mypy；其 mypy.exe 启动器指向旧路径不可用）。
  - 未验证：Python 3.11/3.12 下运行测试（3.12 venv 无 pytest）、Linux、TypeScript 侧（未改动未运行）、CI。

## C2 — 显式 CLI 入口和报告

- 状态：已实现并提交（2026-09-24；Code 3e5fe6f、漏洞模块 dcb2f29，2026-09-24 推送），本机验收通过；远程 CI 已通过（见 C3 “合并 main 与远程 CI”）。
- 工作：C1 验收后确定兼容参数，添加 opt-in 流程和附加报告区；保持 scan_payload 和 fail_on 语义。
- 验收：默认行为回归；增强失败保留静态发现且标 partial；JSON/SARIF/Markdown 证据、UTF-8 路径与退出码用例通过。
- 依赖与范围：C1；不联动 UI，不引入新扫描引擎。
- 完成证据：
  - 前置环境：根改名后 11 个 junction 全部悬空；新增根 `scripts/repair_links.py`（按 layout.json，默认 dry-run，`--check`/`--apply`，只替换 junction，拒绝动真实目录），`--apply` 后 `--check` exit 0。修复后漏洞模块全量 191 passed（原失败的 `test_json_subprocess_adapter_end_to_end` 实际 PASSED）。
  - 实现：`enrich` 子命令（cli.py）、`cve_intel/stage.py`、`cache.py` 失败原因、SARIF `longyuanai:cve-intel` 属性、scan `--output-file` 修复与原子写；漏洞模块 `EnrichmentCacheError(reason)`、分块查询；suite.py 为 code audit 提供模块 src；ADR-006 退出码。规格见 tech-spec §6、§8。
  - 测试入口：`scripts/run_python_tests.py --scope unit|integration` + conftest `--vuln-integration`/`vuln_integration` 标记；缺模块时 integration 以退出 4 失败（已实测），unit 范围 deselect 而非 skip。CI `python-tests` 作业已配置（3.11/3.12），未在远程运行；`VULN_MODULE_REF=554c247` 尚未推送，推送前该作业会检出失败。
  - 结果（Python 3.14.6 本机）：Code unit 246 passed、13 deselected，exit 0；Code integration 259 passed，exit 0，无 skip。新增/改写：test_cli_enrich.py 26（unit 18 + integration 8）、test_cve_intel_cache.py 5（integration）、bridge 43。漏洞模块全量 194 passed（read-only store 10），旧 002 契约 4 个文件 17 passed。Firmware 416 passed、2 skipped（binwalk/squashfs 外部工具）；shared-integration 149 passed、4 skipped（未配 PostgreSQL）；根 launcher 3 + enrich 1 通过。
  - 断网：子进程 sitecustomize 阻断 socket/DNS/httpx（含 loopback），代理变量指向失效 127.0.0.1:9，每个子进程测试断言守卫日志为空；守卫自检确认 create_connection 与 httpx 均被拦截。本轮无任何真实外网探针。
  - Lint/类型：新文件 ruff 通过；cli.py、sarif.py、store.py、suite.py 的 ruff 结果与 HEAD 相同（均为既有问题）；mypy `--strict` 对 cve_intel 与测试入口通过，cli.py 11 个错误与 HEAD 完全相同（既有）；`git diff --check` 三仓通过。
  - 收尾（同日第二轮）：
    - Markdown：`enrich --output markdown`（stdout 或 `--output-file`），`ai_code_audit/output/markdown.py`，转义扫描文本防注入。
    - SARIF：独立审查发现缓存不存在时 SARIF 与未增强导出完全相同；已用该场景复现并修复，阶段记录写入 `runs[0].properties["longyuanai:cve-intel-stage"]`，覆盖 complete/partial/failed(cache_not_found、module_unavailable)/skipped/空 findings；普通 scan SARIF 无 run properties（有测试）。
    - 依赖核实：`git log --all -S EnrichmentCacheError` 无结果；554c247 不在任何远程分支。对 554c247 源码（git archive 只读导出）实测 Code：schema 不匹配报成 cache_unreadable，不可解码行原会崩溃（JSONDecodeError）；Code 适配层已加固为 cache_unreadable（test_cve_intel_adapter_errors.py 9 例）。CI `VULN_MODULE_REF` 置空并由首步显式失败，未伪造 SHA。
  - 本机已通过（Python 3.14.6，Windows）：Code unit 280 passed、17 deselected，exit 0；Code integration 297 passed，exit 0，无 skip。test_cli_enrich.py 50（unit 38 + integration 12）、test_markdown_report.py 5、test_cve_intel_adapter_errors.py 9、cache 5、bridge 43。漏洞模块 194 passed；旧 002 契约 17 passed；根 launcher 4 passed。三种格式退出码优先级 12 组合（1 优先于 3；严格模式仍写完整报告）通过；ruff、mypy `--strict`（cve_intel + markdown）通过，cli.py/sarif.py 既有问题与 HEAD 相同；`git diff --check` 三仓通过；无真实外网探针。
  - 提交（2026-09-24）：漏洞模块 dcb2f29（store.py、test_enrichment_store_readonly.py、tech-spec §8.4 一段）；Code 3e5fe6f（代码、测试、测试入口、CI、ADR-006）；CI `VULN_MODULE_REF` 已锁定 dcb2f29 完整 SHA。提交前复测：Code unit 280 passed/17 deselected、integration 297 passed、漏洞模块 194 passed，均 exit 0；漏洞模块暂存快照单独导出后 181 passed（排除依赖套件路径的 2 个 envelope 测试文件）。两仓既有的文档/路径迁移修改（README、tech-spec 头部、TODO、CAPABILITIES、.gitignore、pyproject 路径、envelope 测试路径）未纳入提交；根仓 suite.py 的 EXTRA_SOURCES 与 tests/test_suite_code_enrich.py 随根仓重组改动一并未提交。
  - 发布前剩余：① 推送 dcb2f29（agent/commercial-docs）与 3e5fe6f（agent/ai-codeguard-fusion），否则 CI 检出失败；② CI `python-tests` 未在远程运行，私有仓检出可能需 `SUITE_CHECKOUT_TOKEN`。
  - 未验证环境：远程 CI、Linux、Python 3.11/3.12 实跑、TypeScript（未改动未运行）、真实 NVD/KEV/EPSS 数据写出的缓存（测试缓存由模块自身 CVEEnricher + 假 provider 写入）。

## C3 — 质量与可交付闭环

- 状态：第一阶段（质量基线 + 可复现交付样例）完成并提交 5a5f0bb，与 main 合并后推送，远程 CI 通过（2026-09-24）；授权真实项目抽查与干净环境安装未做。
- 工作：在现有语料上做规则正反例、授权项目抽查、修复前后 diff/baseline、CLI/CI 使用说明。
- 验收：记录 TP/FP/FN 和样本版本；Python/TS 受影响测试/类型/Lint；可安装与可复现报告。
- 依赖与范围：C2；不承诺所有语言达到同一准确率。
- 起点（2026-09-24 核对）：根仓 7ccbb39（master，重组文档、suite.py EXTRA_SOURCES、tests/、scripts/repair_links.py 均未提交）；Code 3e5fe6f（agent/ai-codeguard-fusion，既有 README/TODO/tech-spec/.gitignore/CAPABILITIES/CODEX_INSTRUCTIONS/archive 未提交）；漏洞模块 dcb2f29（agent/commercial-docs，既有文档/pyproject 路径/测试路径修改未提交，本轮未改）；CI `VULN_MODULE_REF` = dcb2f291301129df257bdf48baf90ca694174a39。C2 行为未修改。
- 完成证据（第一阶段，详见 [c3-quality-and-demo.md](c3-quality-and-demo.md)）：
  - 范围：Python；builtin `004-phase2-taint` 与 opengrep 1.26.0 `CG-OG-PY-001`（二进制哈希与 OPENGREP.lock 一致）。复用 Phase 0 行级方法，新增合成语料 `benchmarks/c3/corpus`（c3-python-2026-09-24：漏洞 7、安全 9 = 易误报 6 + 修复后 3），人工标注理由在 `benchmarks/c3/labels.json`。
  - 结果（三次重复一致）：builtin TP 6/FP 4/FN 1/TN 5，P 60.0%，R 85.7%；opengrep TP 5/FP 0/FN 0/TN 9，P/R 100%（样本内，修复前 TP 3/FN 2）；CWE-78 两例对 opengrep 为 unsupported；builtin 声明的 CWE-89 无样例。合成样例，不是真实项目准确率。
  - 修复：`rules/opengrep/taint.yaml` CG-OG-PY-001 增加 source `sys.argv`、sink `exec(...)`。builtin 的 4 个 FP（常量 sink、注释、字符串）与 1 个 FN（sink 在 source 之上）为引擎启发式限制，已分析未修。
  - 发现未修：opengrep Finding `id` 按指纹生成，同文件同片段两处 ID 重复（基线按计数不会因此隐藏新问题）。
  - 演示：`scripts/c3_demo.py`（修复前/后扫描、SARIF、基线、diff、真实扫描 enrich skipped/not_applicable、合成 CVE envelope + 临时缓存的 JSON/SARIF/Markdown、`--require-intel` 退出 3）；builtin 与 opengrep 两种后端全部检查通过，网络守卫日志为空，两次运行 `result` 段一致。
  - 测试（Python 3.14.6，Windows）：`tests/test_c3_quality.py` 7 例（unit 6 + integration 1）；Code unit 286 passed、18 deselected，exit 0；integration 304 passed，exit 0。新文件 ruff 通过、mypy `--strict`（quality.py、c3_demo.py）通过。漏洞模块与 TypeScript 未改动，未重跑。
- 验收修复（2026-09-24，评测可靠性；已含于 5a5f0bb）：
  - 问题：① 指定不存在的 Opengrep 时后端记 error，但重复一致仍退出 0；② Opengrep 哈希在扫描后才记录，不符也可能退出 0，且哈希做了换行转换；③ 演示把 Python 层拦截表述为“离线/零网络”。
  - 修复：新增 `benchmarks/c3/opengrep_pin.py`（原始字节 SHA-256，对照 OPENGREP.lock，启动前校验，原因 missing/unreadable/lock_invalid/hash_mismatch；质量脚本与演示共用，builtin 不需要）；`quality.py` 分别判定 execution_ok 与 repeat_identical，退出码 0/4/3/2（优先级 2>4>3>0），失败后端指标为 null，JSON/Markdown 仍写出，新增 `--backend`；`c3_demo.py` pin 失败退出 4、不建项目不启动进程，`result.network_verification` 区分 Python 层（已拦截）与 git/Opengrep 原生子进程（未验证）、整个进程树零网络（未验证）。产品 scan/enrich 退出码、Finding 来源/ID、基线规则未改。
  - 验证（`%LOCALAPPDATA%\Programs\Python\Python314\python.exe` 3.14.6，git 2.55.0，输出新目录 `work/c3/acceptance-fix-20260924`）：双后端 `--repeat 3` 退出 0，三次一致，pin verified；指标不变 builtin 6/4/1/5、opengrep 5/0/0/9；builtin、opengrep 演示各 24/24 检查通过，Python 层拦截记录 0 次。`tests/test_c3_quality.py` 16 例（新增 CLI 退出码、pin 缺失/占位文件不符/锁无效/不可读/原始字节、执行错误、重复不一致与优先级、演示 pin 失败无进程）；变异检查：“失败退出 0”被 5 例捕获，“先启动后校验”被 2 例捕获。Code integration 313 passed、0 failed、0 skipped，exit 0；unit 295 passed、18 deselected，exit 0。ruff 0.16.0、mypy 1.20.2 `--strict`（quality.py、opengrep_pin.py、c3_demo.py）通过，`git diff --check` 通过。
- 提交（2026-09-24）：Code 5a5f0bb（benchmarks/c3、scripts/c3_demo.py、tests/test_c3_quality.py、docs/c3-quality-and-demo.md、rules/opengrep 两个文件；未推送）。本 TODO 与 tech-spec 的 C3 段落当时未提交（HEAD 中两文件仍是重组前旧版，C3 段无法脱离既有重写单独提交），2026-09-24 随重组文档一并提交。提交前用暂存区导出快照单独测试，发现演示先检查漏洞模块再做 pin 校验，缺模块的检出中 pin 失败被报为退出 2；已改为 pin 校验优先（快照 17 passed、2 skipped（无 Opengrep 二进制）；工作区 C3 integration 20 passed；opengrep 演示 24/24）。
- 合并 main 与远程 CI（2026-09-24）：PR #1 与 main 冲突导致 CI 不触发；合并 origin/main 为 460c817（8 个冲突，含 sarif.py 的 SARIF 身份统一 + C2 run_properties；codeguard 模块路径随 224c7ba 迁至 ai_code_audit）。main 5d4d60c 让 builtin 命中降为 medium/0.5 并忽略注释/字符串、按函数配对：C3 builtin 在语料与标注不变时重测为 TP 5/FP 2/FN 2/TN 7（P/R 71.4%），opengrep 不变；门禁测试与演示门槛改为 medium。首次 CI（run 35972707945）失败：合并保留了 e500dab 在缺少 000shared-integration 时报错的套件根查找，收集中断；f91b506 改为跳过并在无该仓的 CI 布局下本地复现通过。f91b506 上 ci（Node 18/20/22、pytest 3.11/3.12 unit+integration、action-smoke）、code-guard、security-scan 全部通过（run 35975160311 等）；CI 中显式跳过 4 项（2 项需 shared-integration，2 项需固定版 Opengrep）。本机 npm ci 重建 node_modules 后 TS 593 passed/2 skipped，typecheck、lint 通过；Python integration 350 passed。
- 发布前待办（均未验证）：⓪ git/Opengrep 原生子进程的网络隔离（需操作系统级出站阻断或沙箱证据）；① CI 覆盖缺口：未检出 000shared-integration（2 项跳过），未获取并校验固定版 Opengrep（2 项跳过），shared-llm-core 检出 master 未锁 SHA；② Linux 仅经 CI 验证（本机只在 Windows 实跑）；③ 干净环境 pip/Poetry 安装（当前只验证源码运行）；④ 真实 NVD/KEV/EPSS 数据写出的缓存；⑤ 授权真实项目样本抽查。已完成：远程 CI（Linux，Python 3.11/3.12，Node 18/20/22），根仓提交（2026-09-24，本地，根仓无远端）。
- C3-2 本机评测（2026-09-27）：真实自有子模块 `src/ai_code_audit`，固定 Code `0fb5b18d32006c8db08997bbeb383ffcf2bc6ede`，36 文件/6645 行；builtin 与已校验哈希及运行版本的 Opengrep 1.26.0 各跑两次，均成功、结果一致、0 发现。发现复核清单为空；预先限定五个文件的函数抽查记录两条无法确认的覆盖外风险线索（URL 主机限制、临时文件碰撞），不计算真实项目召回率，不改引擎。此前“⑤ 授权真实项目样本抽查”由本次证据补齐本机样本部分，独立人类签署仍未完成。详见 [C3-2 报告](c3-2-realworld-20260927.md) 与 `benchmarks/c3/realworld-20260927/review.json`。
- C3-2 本轮验证：相关 pytest 19 passed / 1 deselected，exit 0；双后端评测 exit 0，离线机制探针 exit 0，最终 Ruff exit 0，git diff --check exit 0；初次 mypy exit 1（当前解释器缺模块）；后用已有 Firmware Python 3.12.14 / mypy 1.20.2 对两个新脚本严格检查，默认目标与显式 Python 3.14 目标均 exit 0，见 C3-2 报告补验记录。原生网络隔离、独立人类复核、干净环境安装未验证；不是发布验收。本轮只新增评测材料与文档，未提交或推送。
- 下一项最小任务：由独立人类签署复核清单（C3-2 脚本严格类型检查已补验通过）。另列后续任务 RW-02（报告临时文件唯一性、碰撞/并发回归）；RW-01 先确认远程扫描的网络信任边界。保持引擎修复与本轮评测分开。

## 通用停止条件

范围超出任务、需要新技术栈/冻结接口破坏性改动、外部部署环境缺失时，先完成可独立验证部分并报告具体条件。不得删除测试、降低权限或伪造验证来满足验收。

原技术规范和旧任务清单保存在 docs/archive/2026-09-23-pre-consolidation；历史计划用于追溯，不自动执行。
