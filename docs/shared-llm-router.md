# shared-llm-core integration

AI-CodeGuard v0.5 sends every Stage 2 request through the frozen
`shared_llm_core.LLMRouter.chat(tier, request)` interface.

## Configuration

Set the shared core project path only when it cannot be discovered beside the
AI security projects:

```powershell
$env:SHARED_LLM_CORE_PATH = 'E:\path\to\000shared-llm-core'
```

Configure providers with the shared core environment variables or pass its YAML
file through AI-CodeGuard:

```powershell
$env:CODEGUARD_LLM_CONFIG = 'E:\path\to\llm.yml'
$env:CODEGUARD_LLM_TIER = 'standard'
node dist/index.js scan . --fail-on high
```

`CODEGUARD_PYTHON` may select a Python 3.11+ executable on Windows. The Node
adapter launches Python without a shell, passes JSON over stdin/stdout, and
never places prompts or credentials in command-line arguments.

The legacy `llm.provider`, `llm.model`, and `llm.apiKey` fields still parse so
existing v0.4 config files do not break, but routing and credentials are owned
by `shared_llm_core`.

