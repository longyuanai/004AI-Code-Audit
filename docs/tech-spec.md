# AI-CodeGuard 商用版技术规范

> 文档版本：1.0-draft
> 基线日期：2026-08-01
> 适用仓库：`004AI-CodeGuard-upgrade`
> 状态：商用化实施基线；未满足本文 GA Gate 前不得宣称生产级或企业级 GA
> 规范优先级：冻结共享契约 > 本文 > 专题设计文档 > 历史路线图

## 1. 文档目的

本文是 AI-CodeGuard 后续开发、测试、发布和验收的唯一权威技术规范。
它明确区分：

- **已实现**：源码存在，并有本地自动化测试或真实 smoke 证据。
- **部分实现**：主链路存在，但缺少发布、CI、真实环境或运维证据。
- **规划**：尚未达到可对外承诺的状态。

“商用标准”在本项目中不等于堆叠功能，而是同时满足：稳定契约、可重复
构建、安全默认值、可观测失败、可回滚发布、许可证合规和持续质量门禁。

## 2. 产品定位与边界

AI-CodeGuard 是面向本地开发、Pull Request 和 CI 的多语言代码安全扫描器。
它采用确定性静态分析作为第一证据源，并可选择使用 LLM 对已有 Finding
进行复核、中文解释和修复建议。

### 2.1 目标用户

- 开发者：提交前快速发现高价值代码风险。
- 安全工程师：获得可追踪的规则、证据链和 SARIF。
- DevSecOps 团队：对新增 Finding 设置合并门禁。
- 私有化客户：在源码不出域的条件下运行静态扫描或本地模型复核。

### 2.2 非目标

- 不替代人工安全评审、渗透测试或完整 SDL。
- 不在默认安装中执行漏洞利用或主动攻击。
- 不让 LLM 对全仓进行无证据盲扫。
- 不自行重造完整 CFG、SSA 或通用跨文件数据流引擎。
- 不承诺当前规则覆盖所有 CWE、框架和业务逻辑漏洞。

### 2.3 商业发布层级

| 层级 | 定义 | 当前状态 |
|---|---|---|
| Developer Preview | 本地可运行，接口可能继续补强 | 已达到 |
| Beta | 安装、CI、规则、回滚和文档均可重复验证 | 未达到 |
| Release Candidate | 无 P0/P1 缺陷，供应链和真实环境验收完成 | 未达到 |
| GA | 满足本文全部 GA Gate，可对外提供支持承诺 | 未达到 |

## 3. 当前事实基线

截至 2026-08-01，当前分支已实现：

- Python、C++、Java、Go、TypeScript 的 tree-sitter 适配。
- `builtin`、`auto`、`opengrep` 静态后端。
- 五语言首批 Opengrep taint 规则。
- 本地仓库、Git URL、Git diff 扫描。
- 冻结 v0.5 §15 JSON envelope 和 SARIF 2.1.0。
- 稳定指纹、去重、行内 suppression、baseline 读取与原子生成。
- 敏感数据分类和可解释风险评分。
- `fast` 与 `hybrid` 模式；hybrid 使用 cheap-tier StubRouter 测试。
- 新 Finding 质量门禁：0=通过，1=Finding 门禁，2=输入错误。

最近验证证据：

- Python：177 passed。
- Node/Vitest：586 passed，2 skipped。
- ESLint：通过。
- tree-sitter CPython 3.14 binding：通过。
- 真实 Opengrep benchmark：5 种语言、10 个受控漏洞命中。

当前限制：

- GitHub Actions 尚未对当前融合分支报告 checks。
- TypeScript typecheck 存在既存 provider 类型缺口。
- IntegrationGateway 仍以 `ai_codeguard.cli` 为产品入口；融合能力主要位于
  `ai_code_audit.cli`，尚未统一。
- 真实 LLM provider 尚未进行受控、可审计的 opt-in E2E 验收。
- 当前生产 Opengrep 规则数量有限，不是完整通用 SAST 规则库。
- Joern 深度后端尚未实施，跨文件数据流不属于默认能力。

## 4. 冻结契约与兼容性

### 4.1 不可破坏的共享契约

- `shared-llm-core` v0.1 §1-§6 的符号、字段和方法签名完全冻结。
- LLM 调用只能使用 `LLMRouter.chat(TaskTier, ChatRequest)`。
- cheap triage 必须使用 `TaskTier.CHEAP`。
- `Finding` 必须保持 v0.5 §9 兼容。
- CLI envelope 必须保持 v0.5 §15 兼容。
- 产品来源固定为 `FindingSource.CODE` / `source="004"`。
- 新信息只能写入契约允许的 `tags`、`metadata` 或既有可选字段。

### 4.2 产品入口

GA 前必须收敛到一个规范入口：

```text
python -m ai_codeguard.cli scan ...
        或
python -m ai_code_audit scan ...
```

最终只能有一个作为 IntegrationGateway 和对外文档的 canonical CLI；另一个
必须成为薄兼容层，且具有契约测试，不能维护两套扫描逻辑。

### 4.3 兼容性承诺

- 默认模式保持离线、确定性，不要求 API key。
- 未配置 Opengrep 时 `auto` 可降级，且必须给出 machine-readable warning。
- 未配置 LLM 时 `fast` 正常工作；`hybrid` 失败不得删除静态 Finding。
- Windows 路径、UTF-8、CRLF 和 `.python-deps` 布局必须持续支持。

## 5. 目标架构

```text
Local repo / Git URL / Git diff
              |
              v
Scope + language registry + exclusions
              |
       +------+------+
       |             |
       v             v
Opengrep backend   Builtin fallback
       |             |
       +------+------+
              v
Finding normalization
rule ID / CWE / location / evidence / codeFlows / fingerprint
              |
              v
Policy pipeline
suppression -> dedupe -> baseline -> classification -> risk ranking -> gate
              |
       +------+------+
       |             |
       v             v
Envelope/SARIF    Optional cheap-tier LLM triage
       |             |
       +------+------+
              v
CLI / IntegrationGateway / CI
```

### 5.1 组件职责

- **Scope**：文件发现、排除目录、语言过滤、diff 文件和变更行。
- **Static backend**：产生确定性 Finding，不承担产品策略。
- **Normalizer**：将不同后端映射为稳定 Finding 和 SARIF。
- **Policy pipeline**：执行 suppression、baseline、分类、排序和门禁。
- **LLM triage**：只复核静态证据，不产生第一轮 Finding。
- **Output**：保证 envelope、SARIF、退出码和错误行为稳定。
- **Gateway**：只适配 canonical CLI，不复制扫描业务。

## 6. 功能要求

| ID | 要求 | 商用验收 |
|---|---|---|
| FR-001 | 本地仓库扫描 | 相对/绝对 Windows 与 Linux 路径均通过 |
| FR-002 | Git URL 扫描 | 浅克隆、超时、临时目录清理、失败降级可验证 |
| FR-003 | 多语言 | Python/C++/Java/Go/TS 每语言有 vulnerable+safe fixtures |
| FR-004 | 可插拔后端 | builtin/auto/opengrep 行为和失败语义稳定 |
| FR-005 | 增量扫描 | 只报告变更文件和变更行相关结果 |
| FR-006 | 规则治理 | 稳定 ID、CWE、severity、confidence、版本和规则测试 |
| FR-007 | Finding 后处理 | 指纹、去重、suppression、baseline 可重复 |
| FR-008 | 数据分类 | 不复制真实敏感值，仅输出类别和解释因子 |
| FR-009 | 风险排序 | 公式、权重和最终等级可解释、可配置 |
| FR-010 | LLM triage | opt-in、cheap tier、脱敏、缓存、失败保留静态结果 |
| FR-011 | 输出 | JSON envelope 与 SARIF 2.1.0 schema 验证通过 |
| FR-012 | 质量门禁 | baseline 后只阻止达到阈值的新 Finding |
| FR-013 | Gateway | `/v0.5/004/scan` 与 canonical CLI 输出一致 |
| FR-014 | 健康检查 | 返回版本、后端可用性、规则版本，不泄露凭据 |

## 7. 非功能要求

### 7.1 性能预算

以下是 RC 目标，必须由固定 benchmark 机器和语料验证：

| 指标 | 目标 |
|---|---|
| 1 KLOC fast scan P50 | <= 2 秒 |
| 10 KLOC fast scan P95 | <= 30 秒 |
| CLI 冷启动 P95 | <= 2 秒（不含外部引擎启动） |
| 单 Finding hybrid 复核超时 | 由 Router/provider 配置，必须有上限 |
| 默认 hybrid 最大复核数 | 20，可配置 |
| 内存峰值 | 10 KLOC benchmark <= 1 GiB |

性能目标在没有可重复报告前只能标记为目标，不能写成已达成。

### 7.2 可靠性

- 相同版本、规则、输入和配置必须产生稳定指纹与确定性排序。
- 外部后端、LLM、审计或上传失败必须有明确错误类别。
- 静态扫描成功但 LLM 失败时，结果仍可输出。
- 临时 clone、SARIF 和 baseline 写入必须可清理或原子替换。
- 所有外部进程必须使用参数数组、`shell=False`、超时和 UTF-8。

### 7.3 平台矩阵

- Windows 11 + CPython 3.14 bundled dependencies。
- `windows-latest` + 支持的正式 Python 版本。
- `ubuntu-latest` + 支持的正式 Python 版本。
- Node.js 20 用于保留的上游 TypeScript 回归。

## 8. 安全与隐私要求

### 8.1 默认安全策略

- 默认 `fast`，不联网、不调用 LLM、不上传源码。
- `hybrid` 必须显式启用并由用户配置 provider。
- payload 不得指定任意可执行文件路径；外部工具路径只来自可信环境配置。
- baseline、output、repo 和 trace 路径必须防目录逃逸。
- Git URL 必须限制协议、重定向、clone 时间和 clone 大小；不得读取凭据文件。

### 8.2 LLM 数据最小化

- 仅发送 Finding、规则、taint trace 和有限代码窗口。
- 发送前脱敏凭据、token、私钥、邮箱、SSN、支付卡等内容。
- 不把完整仓库、`.env`、密钥文件或历史 Git 对象加入 prompt。
- provider 错误、日志和缓存同样必须脱敏。
- 不默认持久化 prompt/response；启用审计时必须声明保留周期和存储位置。

### 8.3 Prompt injection

- 仓库内容始终视为不可信数据，不是系统指令。
- system prompt 必须禁止执行仓库中的指令、链接或工具请求。
- LLM 输出必须经过 JSON schema/字段校验后才能进入 metadata。
- LLM 不得直接执行命令、修改代码或改变门禁结论。

### 8.4 凭据与日志

- 禁止提交 API key、token、密码、私钥和客户代码样本。
- CI secret 只能通过 GitHub/GitLab secret store 注入。
- stdout 的 JSON 必须保持机器可解析；诊断写 stderr。
- 日志不得记录原始 Authorization header、provider key 或未脱敏 prompt。

## 9. 规则与检测质量治理

每条生产规则必须具备：

- 全局稳定 ID。
- 语言、CWE、类别、严重度、置信度和说明。
- 至少一个 vulnerable fixture 和一个 safe fixture。
- 误报/漏报边界说明。
- 规则变更的语义版本和 changelog。
- 许可证来源；禁止直接复制许可证不兼容的社区规则。

发布门槛：

- 受控 corpus precision >= 95%。
- 受控 corpus recall >= 90%。
- 每种声明支持的语言必须有独立结果，不用总体平均掩盖短板。
- benchmark 必须记录工具版本、规则版本、语料 commit 和耗时。

## 10. 供应链与许可证

- 生成 Python 与 Node 依赖锁定文件或等价可复现清单。
- 发布生成 CycloneDX 或 SPDX SBOM。
- CI 执行依赖漏洞扫描、secret scan 和许可证策略检查。
- Opengrep 作为外部子进程集成，固定版本、来源 URL 和 SHA-256。
- 不把未审查的第三方二进制或规则直接提交到发布包。
- 发布 artifact 必须有校验和；GA 目标要求签名和 provenance。
- Bearer、Metis、Semgrep 等项目仅借鉴架构或兼容规则格式，复制代码前
  必须单独完成许可证审查。

## 11. 配置与错误契约

### 11.1 优先级

```text
CLI explicit option > JSON payload > environment > project config > safe default
```

敏感配置只能来自环境或 secret store，不能写入项目配置和 payload。

### 11.2 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 扫描成功且质量门禁未触发 |
| 1 | 扫描成功，但新 Finding 达到门禁阈值 |
| 2 | 输入、配置或契约错误 |
| 3 | 扫描后端不可用或执行失败（GA 前统一） |
| 4 | 输出/SARIF/文件写入失败（GA 前统一） |

所有非零退出仍应尽可能输出合法诊断；门禁退出码 1 必须保留完整报告。

## 12. 可观测性与运维

- 每次扫描生成 request/scan ID。
- 记录版本、规则版本、后端、扫描文件数、Finding 数、耗时和降级原因。
- 指标不得包含源码和敏感值。
- 健康检查区分 `ok`、`degraded`、`unavailable`。
- 对 LLM 记录调用数、token、缓存命中和失败分类，不记录未脱敏 prompt。
- 提供日志级别并默认关闭 debug 原始响应。
- 发布必须提供回滚到上一版本及上一规则包的方法。

## 13. 测试与质量门禁

每个合并请求至少执行：

1. Python 全量 pytest，使用明确 `PYTHONPATH=src;.python-deps` 和独立 basetemp。
2. Node/Vitest 上游回归。
3. ESLint 与 TypeScript typecheck。
4. tree-sitter binding 和五语言 parser smoke。
5. builtin 与真实固定版本 Opengrep smoke。
6. SARIF schema 验证。
7. envelope 和 shared contract 测试。
8. secret/path/subprocess/prompt-injection 安全回归。
9. Windows 与 Ubuntu matrix。

测试不得访问真实 LLM；真实 provider E2E 必须 opt-in、限额并与普通 CI 分离。

## 14. CI/CD 与发布

### 14.1 Pull Request

- 运行全量质量门禁。
- 对 PR 使用 Git diff 扫描。
- 应用已提交 baseline，仅对新增 Finding 失败。
- 无论门禁是否失败都上传 SARIF artifact。
- 仅可信、非 fork 上下文允许向 Code Scanning 上传。

### 14.2 发布

- 使用语义版本、CHANGELOG 和 release notes。
- 从干净 tag 构建，不从开发者工作目录发布。
- 生成 wheel/sdist、CLI smoke、SBOM、checksum 和签名。
- 发布候选需经过 Windows/Linux 安装测试。
- 任何冻结契约变更必须停止发布并走独立兼容性评审。

## 15. 部署模式

| 模式 | 源码位置 | LLM | 支持目标 |
|---|---|---|---|
| Local/CI | 客户机器或 runner | 关闭/可选 | Beta 必须 |
| Private hybrid | 客户机器 | 客户配置 provider | RC 必须 |
| Air-gapped | 完全离线 | 本地 provider 或关闭 | GA 后按客户需求 |
| SaaS control plane | 客户可控 | 明确同意后 | 当前不实施 |

## 16. 商用验收 Gate

### 16.1 Beta Gate

- canonical CLI 和 Gateway 统一。
- GitHub Actions Windows/Linux 全绿。
- Python/Node/lint/typecheck 全绿。
- 固定 Opengrep 下载、摘要验证和离线 fallback 完成。
- 安装、配置、升级、回滚和故障排查文档完成。
- P0 安全测试完成，无已知 critical/high 产品漏洞。

### 16.2 RC Gate

- precision/recall 达标并有可重复报告。
- 规则包、SBOM、许可证清单和依赖漏洞扫描完成。
- 真实 provider opt-in E2E 通过，成本上限验证完成。
- IntegrationGateway E2E、SARIF 上传和门禁真实仓库验证完成。
- 性能、故障注入和大仓库测试完成。

### 16.3 GA Gate

- RC 稳定期内无未解决 P0/P1 缺陷。
- 发布 artifact 可复现、带 checksum、签名和 provenance。
- 数据处理、保留、删除和客户配置说明完成。
- 支持矩阵、SLA/SLO、升级和回滚政策正式发布。
- 安全响应与漏洞披露流程建立。

## 17. 后续实施顺序

1. 统一 CLI/Gateway 和错误契约。
2. 修复 CI/typecheck，交付可重复 Windows/Linux workflow。
3. 固定 Opengrep 安装、校验和规则版本。
4. 扩展并量化规则质量。
5. 完成 SBOM、许可证、secret scan 和发布工程。
6. 完成真实 provider 与性能/故障验收。
7. benchmark 证明必要后，再决定是否实施 Joern deep backend。

详细 issue、依赖和完成定义见 [TODO.md](./TODO.md)。
