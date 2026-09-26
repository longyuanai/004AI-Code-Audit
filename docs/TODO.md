# AI-CodeGuard 商用化 TODO

> 基线日期：2026-08-01
> 目标：从 Developer Preview 推进到 Beta、RC、GA
> 规则：每个 issue 独立 commit；实现必须带测试、CLI smoke、回滚说明和文档更新

## 1. 状态说明

| 状态 | 含义 |
|---|---|
| done | 已实现、已验证、已提交 |
| local | 已实现并本地提交，尚未推送 |
| in-progress | 已开工但未达到 DoD |
| pending | 尚未开工 |
| blocked | 有明确外部依赖，已记录解除条件 |
| optional | 只有 benchmark/客户需求触发才实施 |

## 2. 当前里程碑

| Phase | 目标 | 状态 | 证据 |
|---|---|---|---|
| 0 | 多语言 benchmark 与 Opengrep 选型 | done | `33c17a2` |
| 1 | 可插拔 builtin/auto/opengrep 后端 | done | `4b44d50` |
| 2 | 生产规则、Finding 归一化、SARIF codeFlows | done | `d629242` |
| 3 | 数据分类和风险排序 | done | `3c95805`、`9821584`、`7dab300` |
| 4 | cheap-tier LLM triage | done | `06ab61e`、`8c5c823`、`4e4bbf0` |
| 5.1 | 原子 baseline 生成 | done | `c640f3c` |
| 5.2 | 新 Finding 质量门禁 | done | `7214971` |
| 5.3 | 商用 CI/SARIF/PR gate | pending | — |
| 6 | Joern 深度后端 | optional | 需 benchmark/客户需求 |

## 3. P0：Beta 阻断项

### DOC-001 · 商用技术规范

- 状态：done
- 输出：`docs/tech-spec.md`、`docs/TODO.md`、文档导航更新。
- DoD：当前能力、目标能力、非目标、契约、安全、SLO、供应链、CI/CD、
  Beta/RC/GA Gate 均有明确可验证描述。

### SYNC-001 · 同步本地质量门禁 commit

- 状态：done
- 工作：推送 `7214971` 到 `origin/agent/ai-codeguard-fusion`。
- DoD：本地 HEAD、远端分支和 Draft PR head SHA 一致。

### CLI-UNIFY-001 · 统一 canonical CLI

- 状态：pending
- 工作：选择唯一对外入口；另一个 CLI 仅做薄兼容转发。
- 约束：不破坏 v0.5 §15 envelope 和 CodeAdapter 调用方式。
- 测试：直接 CLI、JSONSubprocessAdapter、IntegrationGateway 三条链路输出一致。
- DoD：扫描逻辑只有一个实现源，文档只展示一个 canonical 命令。

### GATEWAY-002 · Gateway 使用融合扫描链路

- 状态：pending
- 依赖：CLI-UNIFY-001。
- 工作：`/v0.5/004/scan` 支持 backend/mode/diff/baseline/fail_on。
- 测试：health、fast scan、diff scan、hybrid StubRouter、非零门禁语义。
- DoD：Gateway 与 CLI Finding、summary、warning 一致。

### CI-003 · 可重复的商业 CI workflow

- 状态：pending
- 工作：
  - Windows/Ubuntu matrix。
  - Python、Node、lint、typecheck、契约、真实 Opengrep smoke。
  - PR diff + baseline + `--fail-on high`。
  - 门禁失败时仍上传 SARIF artifact。
  - 非 fork、权限允许时上传 GitHub Code Scanning。
- DoD：Draft PR 出现 checks，连续 3 次运行稳定通过。

### TYPE-001 · 修复 TypeScript typecheck 基线

- 状态：pending
- 工作：解决 optional provider 类型和既存 implicit-any；不无理由加入生产依赖。
- DoD：`npm run typecheck` 在干净安装和 CI 上均为 0。

### OPENGREP-DIST-001 · 固定引擎分发

- 状态：pending
- 工作：固定版本、平台资产 URL、SHA-256、许可证和下载缓存策略。
- 安全：下载后先校验再执行；payload 不得覆盖 executable path。
- DoD：Windows/Linux 安装 smoke、篡改摘要失败测试、离线 fallback 测试通过。

### SEC-001 · 产品安全回归

- 状态：pending
- 覆盖：路径逃逸、恶意 Git URL、超时、压缩/仓库炸弹、命令注入、
  prompt injection、日志泄密、baseline symlink、恶意 SARIF 字段。
- DoD：无未解决 critical/high 缺陷；测试在普通 CI 中执行。

### PKG-001 · 可安装发布包

- 状态：pending
- 工作：wheel/sdist、console script、规则资产、安装验证、版本一致性。
- DoD：全新 Windows/Linux 环境按文档安装后可以运行 fast smoke。

## 4. P1：RC 阻断项

### RULE-002 · 生产规则扩充和治理

- 状态：pending
- 工作：按风险价值扩展 SQLi、RCE、XSS、SSRF、路径穿越、不安全反序列化、
  XXE、凭据和弱加密；不追求虚假的规则数量。
- 每条规则：稳定 ID、CWE、说明、vulnerable+safe、边界、许可证来源。
- DoD：分语言 precision >= 95%、recall >= 90%，报告可重复。

### PERF-001 · 性能与大仓库测试

- 状态：pending
- 工作：1/10/100 KLOC，冷启动、P50/P95、峰值内存、diff 节省比例。
- DoD：结果写入版本化 benchmark 报告；未达目标有明确容量限制。

### LLM-E2E-001 · 真实 provider 受控验收

- 状态：pending
- 工作：opt-in、限额、脱敏断言、超时、429/5xx、非法 JSON、缓存。
- 约束：普通 CI 永远使用 StubRouter；真实 key 不进入日志或 artifact。
- DoD：至少一个 OpenAI-compatible 或本地 provider 通过受控 smoke。

### SUPPLY-001 · SBOM、许可证和依赖安全

- 状态：pending
- 工作：CycloneDX/SPDX SBOM、Python/Node/Opengrep 许可证清单、漏洞扫描、
  secret scan、依赖更新策略。
- DoD：RC artifact 附带 SBOM；无未接受的 critical/high 依赖漏洞。

### OBS-001 · 可观测性和故障分类

- 状态：pending
- 工作：scan ID、耗时、后端/规则版本、降级原因、token/cache 指标。
- 约束：指标和日志不包含源码、密钥或未脱敏 prompt。
- DoD：错误可区分输入、后端、输出、门禁；health 支持 degraded。

### CONFIG-001 · 配置 schema 与迁移

- 状态：pending
- 工作：统一 CLI/payload/env/project config 优先级，提供 schema 和版本。
- DoD：未知字段、废弃字段、非法敏感字段有稳定错误；有迁移测试。

## 5. P2：GA 与运营

### RELEASE-001 · 可复现发布

- 状态：pending
- 工作：语义版本、CHANGELOG、tag 构建、checksum、签名、provenance、回滚。
- DoD：两次干净环境构建产生可解释的一致 artifact；回滚演练通过。

### PRIVACY-001 · 数据处理与保留策略

- 状态：pending
- 工作：源码/prompt/response/审计日志的数据流、保留期、删除、客户配置。
- DoD：Local、private hybrid、air-gapped 三种模式有明确数据边界。

### SUPPORT-001 · 商业支持材料

- 状态：pending
- 工作：支持矩阵、安装升级、故障排查、备份回滚、安全响应和披露流程。
- DoD：运维人员可在无开发者协助下完成安装、升级和常见故障恢复。

### IDE-001 · IDE 集成

- 状态：pending
- 依赖：canonical CLI/API、稳定配置和 Finding 契约。
- DoD：VS Code 最小插件支持扫描、定位、解释和 suppression；不自动改代码。

### DASH-001 · 团队视图

- 状态：pending
- 依赖：数据治理、认证授权、租户隔离和审计模型。
- DoD：单租户私有化 MVP；SaaS 不在当前承诺范围。

## 6. 可选深度能力

### JOERN-001 · 跨函数/跨文件深度扫描

- 状态：optional
- 启动条件：
  - benchmark 证明 fast 模式对关键漏洞存在不可接受漏报；
  - 客户接受 JDK、内存、启动时间和部署复杂度；
  - 许可证与分发评审通过。
- DoD：相同 corpus 相比 fast 有量化增益；不可用时不影响默认流程。

## 7. 通用 Definition of Done

每个 issue 完成必须同时满足：

1. 修改范围与 issue 一致，无顺手重构。
2. 新行为有正常、边界、失败测试。
3. Python 全量测试通过；涉及上游时 Node/lint/typecheck 通过。
4. Windows CLI smoke；跨平台行为在 CI 验证。
5. 不修改 shared-llm-core、shared-integration 或 AI-CodeGuard-main。
6. 不提交 secret、客户数据、下载二进制或临时 artifact。
7. 文档、示例、错误消息和回滚说明同步。
8. `git diff --check` 通过，工作树范围清楚。
9. 一个 issue 一个 commit，推送后本地/远端 SHA 一致。
10. 回报包含 Files / Tests / CLI smoke / Deviations。

## 8. 推荐执行顺序

```text
DOC-001 -> SYNC-001
        -> CLI-UNIFY-001 -> GATEWAY-002
        -> TYPE-001 -> CI-003 -> OPENGREP-DIST-001
        -> SEC-001 -> PKG-001
        -> RULE-002 -> PERF-001 -> LLM-E2E-001
        -> SUPPLY-001 -> OBS-001 -> CONFIG-001
        -> RELEASE-001 -> PRIVACY-001 -> SUPPORT-001
```

当前下一项：`CLI-UNIFY-001`，统一 canonical CLI 后再让 Gateway 接入
同一融合扫描链路。
