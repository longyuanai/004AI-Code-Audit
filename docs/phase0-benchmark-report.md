# Phase 0 静态分析后端选型报告

> 日期：2026-07-29  
> 结论：通过 Phase 0 门槛，推荐进入 `OpengrepBackend` 适配阶段。

## 1. 评测目标

验证成熟静态分析引擎是否在保持 Windows 兼容、离线扫描和稳定输出的前提下，明显优于当前 `ai_code_audit.scanner` 的通用 source/sink 启发式。

本阶段不修改生产扫描器的默认后端。

## 2. 环境

- 操作系统：Windows
- Python：CPython 3.14
- tree-sitter：项目 `.python-deps` 中的 cp314 bindings
- 外部引擎：Opengrep 1.26.0
- 官方资产：`opengrep_windows_x86.exe`
- SHA-256：`4e6c0e201982cd72ca4aff5798a2ff133e17de8af3b00b460238fdda4dd266e3`
- 下载来源：<https://github.com/opengrep/opengrep/releases/tag/v1.26.0>

Opengrep 二进制保存在被 Git 忽略的 `tools/opengrep/v1.26.0/`，不进入 `.python-deps`，也不提交到仓库。

固定版本和摘要记录在 `benchmarks/phase0/OPENGREP.lock`。

## 3. 语料设计

评测语料覆盖：

- Python
- C++
- Java
- Go
- TypeScript

每种语言包含三个带行级标注的 sink：

1. 当前扫描器能够识别的直接 source-to-sink 漏洞。
2. 使用另一种真实输入源的 source-to-sink 漏洞。
3. 代码中存在用户输入，但危险函数只接收常量的安全用例。

总计：

- 10 个漏洞 sink
- 5 个安全 sink

这种设计同时测量：

- TP：正确识别真实漏洞。
- FN：遗漏另一类输入源。
- FP：错误地把无关输入与常量 sink 关联。
- TN：正确忽略安全 sink。

## 4. 结果

| Engine | TP | FP | FN | TN | Precision | Recall | Seconds |
|---|---:|---:|---:|---:|---:|---:|---:|
| builtin | 5 | 5 | 5 | 0 | 50.0% | 50.0% | 0.0131 |
| opengrep | 10 | 0 | 0 | 5 | 100.0% | 100.0% | 2.9388 |

时间为一次本地 Windows 运行结果，只用于数量级比较，不作为稳定性能承诺。

可复现命令：

```powershell
$env:PYTHONPATH = "src;$((Resolve-Path '.python-deps').Path)"

& 'C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe' `
  -m benchmarks.phase0.benchmark `
  --engine all `
  --opengrep tools/opengrep/v1.26.0/opengrep.exe `
  --json-output artifacts/phase0-all.json `
  --markdown-output artifacts/phase0-all.md
```

## 5. 原因分析

### 内置启发式

当前实现找到文件中第一个 source 后，会将其之后所有文本匹配到的 sink 视为同一条数据流。

因此：

- 未识别的输入 API 造成 FN。
- 与输入无关的常量 sink 造成 FP。
- tree-sitter 当前主要用于语言分发、函数和类统计，没有建立真实变量传播关系。

### Opengrep

评测规则使用 Semgrep 兼容 taint 模式：

- 独立声明 source 和 sink。
- 通过变量赋值传播 taint。
- C++ `std::cin >> value` 使用 focus metavariable 和 side-effect taint。
- 常量 sink 不会继承无关变量的 taint。

## 6. 选型决定

推荐：

- Opengrep 作为默认 `fast` backend。
- 当前 tree-sitter scanner 改为显式 fallback，而不是立即删除。
- 使用独立子进程调用，保持 LGPL 边界。
- 生产适配必须增加版本检查、固定超时、UTF-8、路径规范化和结构化错误。
- 所有 Opengrep 结果必须映射到冻结的 Finding 和 v0.5 §15 envelope。

暂不推荐：

- 立即引入 Joern、JDK 或向量数据库。
- 直接替换现有 CLI 契约。
- 将评测规则直接视为完整生产规则集。

## 7. 局限与下一步

本语料是小型、受控的架构验证集，100% 不代表真实世界精度。

Phase 1 应完成：

1. `StaticAnalysisBackend` protocol。
2. `OpengrepBackend`。
3. `BuiltinTreeSitterBackend` fallback。
4. 超时、不可用、无效 JSON 和 Windows 路径测试。
5. 保持当前 CLI 和 envelope 向后兼容。

进入生产默认切换前，还需要扩大规则语料，并在现有 TypeScript precision corpus 和真实开源样本上再次比较。
