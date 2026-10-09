# Offline, hash-locked installation. Never replaces an existing runtime.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PythonExecutable,
    [string]$Wheelhouse = (Join-Path $PSScriptRoot 'wheelhouse'),
    [string]$RuntimeDirectory = (Join-Path $PSScriptRoot 'runtime')
)
$ErrorActionPreference = 'Stop'
$pythonPath = (Resolve-Path -LiteralPath $PythonExecutable).Path
$wheelPath = (Resolve-Path -LiteralPath $Wheelhouse).Path
$runtimePath = [IO.Path]::GetFullPath($RuntimeDirectory)
if (Test-Path -LiteralPath $runtimePath) {
    throw "Runtime already exists: $runtimePath. Choose a new directory."
}
$requirementsPath = Join-Path $wheelPath 'requirements.txt'
if (-not (Test-Path -LiteralPath $requirementsPath -PathType Leaf)) {
    throw 'Missing hash-locked requirements.txt.'
}
& $pythonPath -I -c "import platform,struct,sys; sys.exit(0 if sys.version_info[:2] == (3,14) and platform.system() == 'Windows' and struct.calcsize('P') == 8 and platform.python_implementation() == 'CPython' else 1)"
if ($LASTEXITCODE -ne 0) { throw 'This wheelhouse requires Windows x64 / CPython 3.14.' }
& $pythonPath -I -m venv $runtimePath
if ($LASTEXITCODE -ne 0) { throw "venv creation failed; inspect $runtimePath." }
$runtimePython = Join-Path $runtimePath 'Scripts/python.exe'
& $runtimePython -I -m pip install --disable-pip-version-check --no-cache-dir --no-index --find-links $wheelPath --require-hashes -r $requirementsPath
if ($LASTEXITCODE -ne 0) { throw "Offline installation failed; inspect $runtimePath." }
& $runtimePython -I -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Installed dependency check failed.' }
Write-Output "Installed successfully: $runtimePython"
