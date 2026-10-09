# Starts the installed local Web service. Ctrl+C stops this foreground service.
[CmdletBinding()]
param(
    [string]$RuntimeDirectory = (Join-Path $PSScriptRoot 'runtime'),
    [string]$DataDirectory = (Join-Path $PSScriptRoot 'data'),
    [ValidateRange(0, 65535)][int]$Port = 8765,
    [switch]$UseVerifiedLocalModel
)
$ErrorActionPreference = 'Stop'
$runtimePython = Join-Path ([IO.Path]::GetFullPath($RuntimeDirectory)) 'Scripts/python.exe'
if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf)) {
    throw 'Run install-graduation.ps1 first, or specify the installed runtime directory.'
}
if ($UseVerifiedLocalModel) {
    $env:LLM_PROVIDERS = 'local'
    $env:LLM_LOCAL_BASE_URL = 'http://127.0.0.1:11434'
    $env:LLM_LOCAL_DEFAULT_MODEL = 'qwen2.5:3b-instruct-q4_K_M'
    $env:LLM_LOCAL_API_KEY = 'no-key-required'
    $env:LLM_LOCAL_TIMEOUT_S = '15'
    $env:LLM_LOCAL_MAX_RETRIES = '0'
}
& $runtimePython -I -m ai_code_audit.web.server --port $Port --data-dir ([IO.Path]::GetFullPath($DataDirectory))
if ($LASTEXITCODE -ne 0) { throw "Web service exited with code $LASTEXITCODE." }
