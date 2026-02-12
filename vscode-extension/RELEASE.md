# Release Notes

## Local Install

Use the project installer script:

`powershell
powershell -ExecutionPolicy Bypass -File scripts/install_vscode_extension.ps1
`

It installs this extension to:

$env:USERPROFILE\\.vscode\\extensions\\coherent-light.bond-vscode-0.1.0

## Pre-release Checklist

1. Validate extension syntax: 
ode --check vscode-extension/extension.cjs
2. Validate manifest JSON: 
ode -e "JSON.parse(require('fs').readFileSync('vscode-extension/package.json','utf8'));console.log('ok')"
3. Reload VS Code window and verify all commands appear.
4. Run $(System.Collections.Hashtable.displayName): Start and $(System.Collections.Hashtable.displayName): Run Tests once.
5. Package with sce package (optional) when publishing to Marketplace.
