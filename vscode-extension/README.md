# Bond VS Code Extension

Start, stop, and monitor the Bond MCP server directly from VS Code.

**Publisher:** coherent-light
**Version:** 0.1.0
**Min VS Code:** 1.80.0

## Installation

### Option A: PowerShell Script

```powershell
.\scripts\install_vscode_extension.ps1
```

### Option B: Manual

Copy the `vscode-extension/` folder to your VS Code extensions directory, or use the extension from a workspace that contains the Bond project.

## Commands

Open the command palette (`Ctrl+Shift+P`) and type "Bond":

| Command | Shortcut | Description |
|---------|----------|-------------|
| **Bond: Start** | — | Starts the Bond server as a background process. Output streams to the Bond output channel. |
| **Bond: Stop** | — | Gracefully stops the server (SIGINT, 5s timeout, then force kill). |
| **Bond: Restart** | — | Stop then Start. |
| **Bond: Status** | — | Shows a notification with: running/stopped state, PID, project root, and run command. |
| **Bond: Run Tests** | — | Opens a new terminal and runs the test command (`python -m pytest -q`). |
| **Bond: Open README** | — | Opens the project `README.md` in the editor. |
| **Bond: Open Project Root** | — | Opens the Bond project folder in your system file manager. |

## Status Bar

A persistent status bar item (left side) shows the server state:

- **`▶ Bond`** — Server is running. Tooltip shows PID. Click to view status.
- **`⊘ Bond`** — Server is stopped. Click to view status.

## Settings

Configure in VS Code Settings (`Ctrl+,`) or `settings.json`:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `bond.rootPath` | string | `""` (auto-detect) | Absolute path to the Bond project root. Leave empty to auto-detect from workspace. |
| `bond.runCommand` | string | `python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules` | Shell command used by **Bond: Start**. |
| `bond.testCommand` | string | `python -m pytest -q` | Shell command used by **Bond: Run Tests**. |
| `bond.autoStart` | boolean | `false` | Automatically start the server when VS Code opens. |
| `bond.showOutputOnStart` | boolean | `true` | Focus the Bond output channel when the server starts. |

## How Project Root Detection Works

The extension finds the Bond project root in this order:

1. **Explicit setting**: If `bond.rootPath` is set and contains `bond_server.py` + `core/`, use it.
2. **Workspace folder**: Scan workspace folders for one containing `bond_server.py` + `core/`.
3. **Nested folder**: Check for a Bond subfolder within each workspace folder.
4. **Extension parent**: Check the parent directory of the extension itself.

If none match, you'll see an error asking you to set `bond.rootPath`.

## Output Channel

All server stdout and stderr output is logged to the **Bond** output channel (`View > Output > Bond`). Each line is timestamped. Stderr lines are prefixed with `[stderr]`.

## Notes

- This repo ships without `modules/module_manifests.json`, so the default run command includes `--insecure-allow-unverified-modules`. Remove this flag in production after creating manifests.
- The server process is killed when VS Code closes (cleanup via `deactivate`).
- Server stdout is captured but not parsed — Bond uses stdin/stdout for MCP JSON-RPC, so the extension's process does NOT act as an MCP client. It's purely a lifecycle manager.
