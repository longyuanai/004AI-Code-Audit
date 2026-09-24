# C3 demo project (synthetic)

`before/` and `after/` are two commits of the same tiny synthetic project,
used by `scripts/c3_demo.py`. Every issue is intentional; nothing is executed.

| File | before | after |
|---|---|---|
| app/calculator.py | `eval(input(...))` (CWE-95) | fixed with `ast.literal_eval` |
| app/report.py | `os.system` with input (CWE-78), accepted legacy issue | unchanged |
| app/admin.py | absent | new `exec(sys.argv[1])` (CWE-95) |
