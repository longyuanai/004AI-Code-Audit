# 002 AI-Code-Audit 技术规范

版本：1.0 / 2026-09-23，合并后的开发基线。Python 包 ai_code_audit、TypeScript 包 ai-codeguard、来源 `004` 保持。
旧 AI-CodeGuard 商业技术规范归档；冻结契约仍以 shared-llm-core 为准。

## 1. 产品目标

先完成可重复运行的代码安全审计与修复验证闭环：读取授权代码 → 静态发现 → 可选模型辅助 → 风险与证据报告 → 基线/diff 复查。初期以命令行和 CI 结果交付；共享 web-ui 后接入，不另做一套后台。

Vulnerability 模块位于 `modules/vulnerability-analysis`，仍是独立 Git 仓，负责扫描器报告归一化、CVE 情报、缓存和风险能力。Firmware 复用此唯一源码；不要建立 Code/Firmware 两份情报数据库实现。

## 2. 当前实现与入口

| 位置（相对本仓） | 当前实现 |
|---|---|
| src/ai_code_audit/cli.py：scan_payload | 仓库输入、backend/mode、diff/baseline、结果后处理与混合审计 |
| src/ai_code_audit/scanner.py、dataflow.py、taint.py | Python 扫描与分析 |
| src/ai_code_audit/backends | builtin/opengrep 后端边界 |
| src/ai_code_audit/languages | 按后端实现的语言能力 |
| src/ai_code_audit/triage.py、triage_context.py | 可选 LLM 分析与上下文 |
| src/ai_code_audit/output | envelope 与 SARIF |
| package.json、src 下 TypeScript 实现 | Node CLI、规则、报告与 TS 测试体系 |
| modules/vulnerability-analysis/src/ai_vuln_agent/enrich_envelope.py | 当前仅 source `002` 的增强入口 |
| 模块 enrichment/client.py、store.py、prioritizer.py | 情报客户端、SQLite 缓存（含只读查询 ReadOnlyEnrichmentStore）、PRisk |
| src/ai_code_audit/cve_intel | C1 离线 CVE 桥接核心与只读缓存适配；C2 阶段编排 stage.py，由 `enrich` 子命令调用 |
| scripts/run_python_tests.py | Python 测试入口：`--scope unit` / `--scope integration`（见 §8） |

Python 和 TypeScript 是并存实现，不在本轮删除任一语言，也不承诺功能完全对等。新增规则应写明后端/语言/规则编号和适用范围；不能把目录存在当作全面语言支持。

根入口：`suite.py code audit -- --help`、`suite.py code vulnerability -- --help`。扫描与离线 CVE 增强是两步：`scan` 保存 envelope，`enrich` 显式后处理（§6）；扫描默认不增强。suite.py 为 `code audit` 额外提供唯一漏洞模块 src。根启动器现在调用 `python -m ai_code_audit`；`python -m ai_code_audit.cli` 仅加载定义，不会调用 main。交接时须检查帮助内容与实际 JSON 输出，不能只看进程成功退出。

## 3. 输入、输出和不变条件

复用现有 scan_payload 校验与 envelope，不另建一套扫描请求。代码路径和仓库来源按现有物化流程处理；禁止执行仓库内的不可信构建/安装脚本来完成静态分析。

静态 Finding 是审计事实基线。LLM triage 为可选辅助；失败保留静态发现并显示 warning。未知数据和部分失败不得降低原扫描门禁。SARIF、基线/diff 和 JSON 的现有语义必须保留。

情报补充必须保留每条 Finding 的 id/source/severity/confidence/title/description/evidence/related 及未知字段。新情报只能作为附加 metadata/报告区；若未来需要改变严重性，应建立明确可审计政策与独立测试，不能默默重写。

## 4. 已确认的集成阻碍

1. enrich_envelope._normalize_item 强制来源 `002`；直接输入代码来源 `004` 会拒绝。
2. 当前增强会把 description 替换为 narrative，不满足保留原始代码描述的要求。
3. CVEEnricher 缓存未命中会调用 NVD/KEV/EPSS。offline_stage 仅说明扫描后阶段，不保证不联网。
4. 现有 PRisk 的 Exposure 来自主机端口，且未知信号按零计分；不应原样当作源代码可达性或“低风险”判断。
5. `suite.py` 给一个能力构造环境；Code 不能假设模块已作为可导入包装入该解释器。

因此首轮采用产品内独立桥接，保持旧 source `002` 行为不变。优先复用情报记录与只读查询，避免套用现有完整 enrich_envelope 后再修字段。

## 5. C1：离线桥接（核心已实现，2026-09-23；C2 起由 enrich 子命令调用）

核心转换函数接收已验证 envelope 和按 CVE 索引的情报记录；禁止核心函数自己联网。缓存读取是独立适配层，复用唯一漏洞模块的 store；若缺少稳定只读 API，在该模块增加公共查询方法，不读取其私有实现来绑定产品。

实现：

- `ai_code_audit.cve_intel.bridge`：纯同步函数、无 I/O。`cve_query_keys(envelope)` 校验并返回去重、大写的待查 CVE；`bridge_code_findings(envelope, observations, now=aware_datetime)` 返回 `BridgeResult(envelope, summary)`。`observations` 为 `{CVE: {provider: ProviderObservation}}`。
- `ai_code_audit.cve_intel.cache`：`VulnerabilityCacheReader(path)` 仅使用漏洞模块公共 `ReadOnlyEnrichmentStore`；`bridge_from_cache(envelope, cache_path, now=None)` 串起校验→只读查询→桥接。读取每个 provider 的独立记录（nvd/kev/epss），不读 `combined` 记录，因为后者把 KEV 未知折叠为 `in_known_exploited=False`。模块不可导入或库不存在/不兼容时抛 `CveCacheUnavailableError`，不自动创建缓存。
- 不构造 `CVEEnricher` 或任何 HTTP 客户端，不做新评分；原 `enrich_envelope` 与 source `002` 限制不变。

`metadata.code_audit_enrichment`（schema_version 1，样例见 tests/fixtures/cve_intel/expected-enriched.json）：

| 字段 | 语义 |
|---|---|
| status | enriched（三源均新鲜 ok/not_found）、partial（部分可用）、stale（无可用源且有过期）、unknown（缓存无记录）、not_applicable（无 CVE）、invalid_input（CVE 非字符串或格式错） |
| cve | 规范化查询键；原 Finding 的 `cve` 字段原样保留 |
| providers | 每源 status：ok / not_found / missing / stale / unsupported_status（附 cache_status）/ invalid_cache，及 fetched_at、expires_at |
| values | cvss_v3、cvss_vector、cwe、epss、epss_percentile、kev；只来自新鲜可用记录，否则为 null。kev 仅在 KEV 新鲜 not_found 时为 false |
| warnings | 缺失、过期、异常缓存与非法输入的可读原因 |

`summary`（不写入 envelope，由 C2 决定呈现）：schema_version、evaluated_at、findings、cves、status_counts，缓存适配层另加 cache 路径。过期边界：`expires_at <= now` 视为过期，过期值不输出。已有 `metadata.code_audit_enrichment` 时拒绝，不覆盖。

| 输入情形 | 必须行为 |
|---|---|
| source `004` + 有效 CVE + 新鲜缓存 | 补充附加情报；原始 Finding 保持 |
| 无 CVE | 原样保留；not_applicable，不推测 CVE |
| 非法 CVE | 保留原始证据；invalid_input，不能请求外部 API |
| 缓存无记录/过期 | unknown/stale，不能补零或得出安全结论 |
| provider 部分数据 | 保留已知值并标出缺失来源；不得把 unknown KEV 写成 false |
| 非 `004` 来源进入 Code 专用桥接 | 明确拒绝或返回不支持错误，不悄悄改来源 |
| envelope 畸形 | 可定位错误；不生成空的成功结果 |

第一轮不做新评分，只呈现情报事实与缺失状态。保持输入对象不被原地修改；去重请求不等于去重 Finding，原条数和顺序保持。CVE 大小写可在查询键规范化，但不覆盖输入原值。

断网验收必须在测试中阻断所有网络访问，并断言缓存命中/未命中/过期三种路径均零请求。不要仅 mock 一个 HTTP 函数后宣称整个进程离线。

## 6. C2：CLI 与报告闭环（已实现，2026-09-23 本机验证；2026-09-24 提交 Code 3e5fe6f，2026-09-24 推送，远程 CI 通过）

显式离线后处理子命令，复用 C1；不联网刷新、不调用 LLM、不改默认扫描。

```text
ai-code-audit enrich --envelope <scan.json | -> [--cache <dir|file.sqlite3>]
                     [--output-file <path>] [--output envelope|sarif|markdown]
                     [--fail-on none|any|info|low|medium|high|critical]
                     [--require-intel]
```

- 输入：`scan --json` 保存的 source `004` envelope（UTF-8，可带 BOM，≤64 MiB，`-` 为 stdin）。`--input/--repo-path/--git-url` 与 enrich 互斥；`--envelope/--cache/--require-intel` 不能用于 scan。
- `--cache` 缺省时用漏洞模块默认位置（Windows `%LOCALAPPDATA%\ai-vuln-agent\enrichment-v1.sqlite3`）。只在存在可查询 CVE 时打开，且只读；从不创建。
- 输出：增强 envelope（原顶层/Finding 字段与未知字段原样），每条 Finding 的 `metadata.code_audit_enrichment`（§5），以及顶层阶段记录 `code_audit_enrichment`：schema_version、status、reason、error、cache、evaluated_at、`network_refresh: false`、sources（三个来源说明）、providers、findings、cves、status_counts。未知值保持 null。stderr 另输出一行阶段摘要。
- SARIF（`--output sarif`，需 `--output-file`）：运行级 `runs[0].properties["longyuanai:cve-intel-stage"]` 为完整阶段记录（complete/partial/failed/skipped 与空 findings 均写入，含 reason/error/cache）；结果级 properties 另有 `longyuanai:cve-intel`（仅在有逐条情报时）。修复前缓存不存在时 SARIF 与未增强导出完全相同、丢失 failed/cache_not_found（独立审查发现），现以运行级属性区分。普通 scan SARIF 不带 run properties，保持原样。
- Markdown（`--output markdown`，仅 enrich；可 stdout 或 `--output-file`）：由 `ai_code_audit.output.markdown` 从同一增强文档渲染，包括阶段状态/原因/错误、缓存、评估时间、“联网刷新：否”、情报来源、状态统计、扫描门禁与警告、每条原始发现（ID/来源/严重性/置信度/规则/位置/原 CVE/描述/源码证据），以及逐来源状态、采集/过期时间和情报字段。null 显示为“未知（null）”，stale 标“已过期，值未采用”，failed 阶段显示醒目提示且不附情报。扫描文本全部转义（HTML 与 Markdown 特殊字符），证据放入比内部反引号更长的代码围栏，不能注入标记。`scan --output markdown` 报错 2。

阶段状态：

| 情形 | status / reason | Finding 数据 |
|---|---|---|
| 无 Finding 带 CVE | skipped / no_queryable_cve；不打开缓存 | 逐条 not_applicable |
| 仅非法 CVE | partial / no_queryable_cve；不打开缓存 | invalid_input |
| 全部 enriched 或 not_applicable | complete | 附情报 |
| 有 stale / unknown / partial / invalid_input | partial / intel_incomplete | 附情报与缺失原因 |
| 模块不可导入 | failed / module_unavailable | 原样，不加元数据 |
| 缓存不存在 | failed / cache_not_found | 原样 |
| 非 SQLite、损坏、缺表、行不可解码 | failed / cache_unreadable | 原样 |
| schema 版本不等于 1 | failed / cache_schema_mismatch | 原样 |

漏洞模块版本要求：结构化原因依赖 `EnrichmentCacheError` 与分块查询，已于 2026-09-24 提交为漏洞模块 dcb2f29（2026-09-24 推送）。对已提交的 554c247（仅 C1）实测：缓存缺失/损坏仍为 cache_not_found/cache_unreadable；schema 不匹配会报成 cache_unreadable；不可解码行原先会以 JSONDecodeError 崩溃，Code 适配层已改为捕获 sqlite3/ValueError 并报 cache_unreadable，其他异常仍抛出。CI 已锁定 dcb2f29 完整 SHA。

退出码（ADR-006）：0 成功（含 partial/failed 的非严格模式，状态写在报告里）；1 扫描门禁触发（优先于 3）；2 参数、输入、envelope 校验或写文件失败，stdout 为空、不写输出文件；3 `--require-intel` 且阶段 partial/failed（仍输出完整报告）。门禁阈值：显式 `--fail-on` 优先，否则沿用输入 `summary.gate.threshold`；`--fail-on none` 本次不据门禁返回 1，但保留记录的 `summary.gate`。

`--output-file`（scan 与 enrich 统一）：写入该文件，stdout 只输出解析后的绝对路径；同目录临时文件后 `os.replace` 原子覆盖已有文件，失败不截断旧文件；目标为目录时报错 2；enrich 的输出路径不得等于输入 envelope。修复前 scan 的 JSON 模式静默忽略此参数（C0 记录）；现在 `scan --json --output-file` 与不带 `--json` 时都写 envelope 文件，SARIF 行为不变。

不做：CVE 情报不改变 severity，不做评分；模型推测与 CVE 情报在 JSON 中位于不同 metadata 键（`llm_triage` 与 `code_audit_enrichment`），情报存在不证明可利用。

## 7. 性能、安全与配置

- 路径筛选、忽略文件、文件大小与超时沿用现有扫描配置；新增限制须有清晰错误，不静默漏扫。
- LLM 默认可关闭；发送源码前遵循现有数据策略，只发送必要上下文，不读取工作区秘密。
- 后端工具路径与参数采用现有安全调用方式；缺 Opengrep 时显式报告实际后端，不能假装执行成功。
- 缓存区分采集时间、有效期、缺失与失败；网络刷新是后续显式行为，第一轮不增加后台刷新。
- 规则版本、引擎版本、配置与样本版本写入可复现记录；质量数字必须指明标注集、TP/FP/FN 与样本规模。

## 8. 验收矩阵

历史基线：Python 185、TypeScript 586 项通过（TS 2 跳过）；漏洞模块 184 项通过。详见 [验证说明](../../docs/VALIDATION.md)。

C1 必测：字段深度保真/输入不变、无 CVE、格式错误、空/过期缓存、未知 provider、重复 CVE 多 Finding、非法 source、网络被阻断。模块旧 `002` 契约回归必须继续通过。
C1 现场结果（2026-09-23）见 [TODO](TODO.md) C1 完成证据；断网测试在 socket 层阻断全部连接（含 loopback，因本机 HTTP(S) 代理走 127.0.0.1）并断言命中/过期/缺失零请求。

C2 必测：关闭增强与旧快照一致，开启后的 JSON/报告样例，部分失败保留扫描门禁，Unicode/绝对路径，未知字段往返。
C2 覆盖：`tests/test_cli_enrich.py`（真实子进程，三种格式、退出码优先级、文件输出、SARIF 运行级阶段五种情形；子进程经 sitecustomize 阻断 socket/DNS/httpx，代理变量指向失效的 127.0.0.1:9，并断言守卫日志为空）、`tests/test_markdown_report.py`（渲染与注入转义）、`tests/test_cve_intel_adapter_errors.py`（旧版 store 异常映射）与根 `tests/test_suite_code_enrich.py`（经 suite.py）。

测试入口（两种范围）：

- `python scripts/run_python_tests.py --scope unit`：仅 Code；带 `vuln_integration` 标记的测试 deselected（不计 skip/pass），不需要漏洞模块。
- `python scripts/run_python_tests.py --scope integration`：追加 `modules/vulnerability-analysis/src` 并传 `--vuln-integration`；模块不可导入或不来自该目录时 pytest 以 usage error（退出 4）失败，不跳过。
- 两者都以 `-o addopts=`、系统临时目录下新 basetemp 运行，环境变量只作用于 pytest 进程及其子进程；CI 见 `.github/workflows/ci.yml` 的 `python-tests`（Python 3.11/3.12，unit 与 integration 两步；2026-09-24 在 f91b506 上远程通过）。该作业的 `VULN_MODULE_REF` 已锁定 dcb2f291301129df257bdf48baf90ca694174a39（已推送）。shared-llm-core 仍检出 master，未锁 SHA；CI 未检出 000shared-integration，相关 2 项测试显式跳过。

C3 必测：固定正反例语料、真实授权项目回归、误报抽查、修复前后 diff/baseline；不做未经测量的准确率承诺。

C3 第一阶段（2026-09-24，提交 5a5f0bb，合并 main 后推送，远程 CI 通过；builtin 指标在合并 main 5d4d60c 后重测，见 [c3-quality-and-demo.md](c3-quality-and-demo.md)）：

- 质量基线 `benchmarks/c3/quality.py`：Python 合成语料 `benchmarks/c3/corpus` + 人工标注 `labels.json`（逐例理由、规则声明的 CWE 范围）；经 `scan_payload` 按规则计 TP/FP/FN/TN、范围外、unsupported、错误，分母为零输出 null；`result` 段确定性。退出码（验收修复后）：0 成功且重复一致，4 任一所选后端失败（含 Opengrep 执行前 pin 校验失败，不启动），3 重复不一致，2 用法/标注/写报告错误，优先级 2>4>3>0。Opengrep 路径由 `benchmarks/c3/opengrep_pin.py` 按原始字节 SHA-256 对照 OPENGREP.lock 门禁（质量脚本与演示共用）。仅是合成样例回归基线。
- 规则变更：`CG-OG-PY-001` 增加 source `sys.argv`、sink `exec(...)`（仅影响 Python opengrep/auto 后端）。
- 交付演示 `scripts/c3_demo.py`：运行真实 CLI（Python 层网络拦截；git/Opengrep 原生子进程网络未验证）完成扫描 → 基线 → 修复 → 复查（全量/基线/diff），导出 JSON/SARIF/Markdown，合成 CVE envelope + 演示临时缓存 enrich；不依赖根 suite.py。
- 测试 `tests/test_c3_quality.py`；范围、结果、原因分析、依赖与未验证项见 [c3-quality-and-demo.md](c3-quality-and-demo.md)。

## 9. 发布与下一步

优先交付可安装 CLI + 报告样例 + 复现脚本，随后做 CI 使用说明和小范围试用。产品和漏洞模块分别提交；发布记录写明两个提交版本和契约版本。
任务见 [TODO](TODO.md)，其他模型从 [交接指南](../../docs/MODEL-HANDOFF.md) 的 C0/C1 开始。
