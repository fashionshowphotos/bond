param(
  [string]$SourceDir = "$PSScriptRoot\..\vscode-extension",
  [string]$TargetDir = "$env:USERPROFILE\.vscode\extensions\coherent-light.bond-vscode-0.1.0"
)

$ErrorActionPreference = 'Stop'

$src = (Resolve-Path $SourceDir).Path
if (-not (Test-Path $src)) {
  throw "Source extension directory not found: $SourceDir"
}

if (-not (Test-Path $TargetDir)) {
  New-Item -ItemType Directory -Path $TargetDir | Out-Null
}

Copy-Item -Recurse -Force "$src\*" $TargetDir
Write-Host "Installed Bond extension to: $TargetDir"
