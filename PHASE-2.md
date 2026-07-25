# 004AI代码审计 · Phase-2 计划

> **本仓角色**: AI 代码审计 Agent。`tree-sitter` 多语言解析 + 安全模式识别 + Finding 产出。注意:实际仓库路径是 `004AI代码审计/004AI-CodeGuard-upgrade/`(嵌套)。
> **当前状态**: v0.6 §15 CLI Envelope 已实现,S4 worker 4 件套全绿,D 绿(包含 `.python-deps/` PYTHONPATH 配置)。
> **下一阶段**: v0.6+ 多语言扩展 + SARIF 导出。

---

## 现状摘要(2026-07-25)

| 项 | 状态 |
|----|------|
| v0.1 LLM 集成 | ✅ |
| v0.5 Finding schema | ✅ |
| `tree-sitter-python` 单语言(已装在 `.python-deps/`)| ✅ |
| `repo_path` / `git_url` 两种输入 | ✅ |
| CLI 子命令 `scan --input '<json>' --json` | ✅ |
| S4 worker 4 件套 | ✅ PASS(含 PYTHONPATH 配 `.python-deps`)|

---

## Phase-2 hooks

### Hook A · 多语言 tree-sitter(派活 021-CODEC-MULTILANG)

**目标**:除 Python 外,加 C++ / Java / Go / TypeScript 解析。

**派活文档**:`021-CODE-MULTILANG.md`(待起草)

- 加 `tree_sitter_cpp` / `tree_sitter_java` / `tree_sitter_go` / `tree_sitter_typescript`
- 装到 `.python-deps/`(沿用现布局)
- 新增 `languages` 选项:CLI payload 增量 `{"repo_path": "...", "languages": ["cpp", "go"]}`
- ≥ 2 个 test fixture per language

**为什么 Phase-2**:
- 现在只 Python
- 真实客户混合语言

### Hook B · SARIF 导出

**目标**:导出 SARIF 2.1.0 格式,GitHub Code Scanning 直接消费。

**派活文档**:`022-CODE-SARIF.md`(待起草)

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {"driver": {"name": "longyuanai-codeguard", "version": "0.6"}},
    "results": [<每条 Finding 转 SARIF result>]
  }]
}
```

- CLI 加 `scan --output=sarif` 选项
- 测试:导出的 SARIF 满足 schema(用 jsonschema 验证)

**为什么 Phase-2**:
- 现在只 envelope 给 gateway
- 用户自己用 SARIF 接 GitHub 比 envelope 更友好

### Hook C · IDE 插件初稿(可选,vscode + intellij placeholder)

**目标**:vscode extension、JetBrains plugin 各一个空壳,接 codeguard CLI。

- 不在本 Phase-2 计划主路,Phase-3 候选
- 实现方式:启动 codeguard 子进程,展示 inline 问题

### Hook D · 增量扫描(只扫 diff)

**目标**:用 git diff 范围代替 `repo_path` 全扫。

- 派活文档:`023-CODE-INCREMENTAL.md`(待起草)
- 与 code review 流程整合

---

## v1.0 路线图

```
v0.5 已冻结:Python tree-sitter
v0.6: Hook A (C++/Java/Go/TS) + Hook B (SARIF)
v0.7: Hook D (incremental git diff)
v1.0: Hook C (vscode + JetBrains extension)
```

---

## 不要做的事

- ❌ 不要破坏 `.python-deps/` 布局(那是 Windows 唯一能跑的方式)
- ❌ 不要在 scan 里直接 import .python-deps 之外的 tree-sitter(系统 python 装不到)
- ❌ 不要把 `repo_path` 改成 HTTP 下载(那是 git_url 的事)
- ❌ 不要破坏 v0.5 §15 envelope 的 source=`004` 注入

---

**最近修订**: 2026-07-25 · Claude 起草 Phase-2 计划
**下次回看触发**: v0.6 启动 / Hook A 启动
