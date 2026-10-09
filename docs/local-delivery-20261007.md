# AI代码审计：2026-10-07 本机交付验证

结论：本机 builtin 安装、静态扫描、报告导出和已知产品缺陷修复回归通过。
独立人类签署、生产验收、发布和商业有效性尚未完成。

## 本轮实际修复

RW-02：`cli.py` 报告临时文件原先用目标文件名与进程号生成，同进程并发请求共享路径。
实际回归先复现两项失败：碰撞与误删预置临时文件；修复改用 mkstemp 独占随机文件，
通过句柄写入并关闭，最后原子替换，只清理本次临时文件。
复核中又出现 Windows WinError 5 短暂替换冲突，新增对 5/32/33 的最多5次重试，
累计等待最多0.1秒。其他错误立即抛出；持续锁定仍失败，保留旧报告并清理临时文件。
语义仍为最后成功写入者生效，不是合并报告或事务队列。

`tests/test_output_atomic.py` 共6项，包括确定性交错并发、预置文件、编码失败、替换失败、
短暂锁重试和永久锁上限。最终十轮重复均 exit 0；失败日志也保留。

## 安装与真实扫描

全新 `artifacts/delivery-20261007/clean-env` 非editable安装产品与同级共享核心。
首次离线安装因 poetry-core 缓存缺失失败；随后联网获取已有声明的依赖，未修改生产依赖。
最终源码重新离线安装并验证摘要一致；产品与共享核心均从该环境 site-packages 加载。
`python -I` 从源码目录外运行，无 PYTHONPATH/用户site依赖；uv pip check 30包通过。

真实自有样本：最终 `src/ai_code_audit` 的36个Python文件快照，逐文件摘要见
`artifacts/delivery-20261007/installed-check-4/sample-manifest.json`。builtin、fast模式；
扫描0发现，JSON与SARIF均实际导出。没有完整漏洞真值集，不计算真实召回率，0发现不代表安全。
RW-02来自人工代码复核及回归测试，不把它冒充静态扫描命中。

独立的合成功能样例：输入→eval 为1发现、门禁退出1；改为 ast.literal_eval 后0发现、退出0。
只静态读取样例，不执行样例代码；这不是外部真实客户案例或整体安全保证。

## 本轮验证

- Python integration：360 passed；既有 cache_dir 配置警告1条。
- TypeScript：593 passed、2 skipped（真实模型provider相关），typecheck、lint、build通过。
- 新增Python测试 Ruff与strict mypy通过；修改CLI仍有4项既有Ruff问题，与备份一致，无新增。
- CLI安装摘要与最终源码一致；依赖一致性通过；git diff --check通过。
- 本机Windows/Python3.14.6已验证；本轮未执行远程CI、Linux或操作系统级网络隔离。

## 客户交付的最低内容

授权和输入范围、样本版本/摘要、扫描器及规则版本、原始JSON/SARIF、逐项复核、
修复依据与前后复扫、遗漏范围、人工签名。先交付限定范围服务，不承诺覆盖所有漏洞。

当前CLI的backend/mode通过JSON `--input`传入，不存在`--backend`或`--mode`独立参数。
示例（PowerShell，在已安装环境调用）：

```powershell
$payload = @{repo_path='D:\授权样本'; backend='builtin'; mode='fast'} | ConvertTo-Json -Compress
ai-code-audit scan --input $payload --json --fail-on medium --output-file 'D:\交付\scan.json'
ai-code-audit scan --input $payload --output sarif --fail-on medium --output-file 'D:\交付\scan.sarif'
```

退出1表示风险门禁触发，不是扫描执行失败。输出文件仍按已有契约原子覆盖；先保留旧版本。
本轮安装验收仅覆盖builtin。Opengrep规则配置、完整套件情报模块、CI覆盖缺口另行验收。

## 备份与回滚

修改前源码/README/TODO逐文件备份和摘要在 `artifacts/delivery-20261007/backup/`。
回滚先核对摘要与本轮差异；若用户此后又修改，不直接用备份覆盖。新文件通过Git差异单独处理。
没有改远程扫描信任边界，不推进RW-01；独立人类复核仍pending。

## 同日续轮

续轮已消除上述CLI的11处严格类型错误，并处理4处Ruff诊断（两处provider故障保全边界显式保留广义捕获，附理由与回归）。最新Python integration370 passed；隔离环境重装、依赖一致性与真实/合成样例再次通过。详见 [续轮验证](local-delivery-20261007-continue.md)。
