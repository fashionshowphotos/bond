const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const PRODUCT_NAME = 'Bond';
const COMMAND_PREFIX = 'bond';
const CONFIG_NS = 'bond';
const ROOT_SENTINELS = ["bond_server.py","core"];
const DEFAULT_RUN_COMMAND = "python -u bond_server.py --policy RESTRICTED --insecure-allow-unverified-modules";
const DEFAULT_TEST_COMMAND = "python -m pytest -q";

let output;
let statusItem;
let runtimeProcess = null;
let runtimeRoot = null;

function log(message) {
  if (!output) {
    return;
  }
  output.appendLine(`[${new Date().toISOString()}] ${message}`);
}

function cfg() {
  return vscode.workspace.getConfiguration(CONFIG_NS);
}

function isProjectRoot(candidate) {
  if (!candidate) {
    return false;
  }
  return ROOT_SENTINELS.every((entry) => fs.existsSync(path.join(candidate, entry)));
}

function resolveProjectRoot() {
  const configured = String(cfg().get('rootPath', '') || '').trim();
  if (configured) {
    const resolved = path.resolve(configured);
    if (isProjectRoot(resolved)) {
      return resolved;
    }
    throw new Error(`${CONFIG_NS}.rootPath is invalid: ${resolved}`);
  }

  const folders = vscode.workspace.workspaceFolders || [];
  for (const folder of folders) {
    const candidate = folder.uri.fsPath;
    if (isProjectRoot(candidate)) {
      return candidate;
    }

    const nested = path.join(candidate, path.basename(path.resolve(__dirname, '..')));
    if (isProjectRoot(nested)) {
      return nested;
    }
  }

  const fallback = path.resolve(__dirname, '..');
  if (isProjectRoot(fallback)) {
    return fallback;
  }

  throw new Error(`Unable to find ${PRODUCT_NAME} root. Set "${CONFIG_NS}.rootPath" in VS Code settings.`);
}

function updateStatus() {
  if (!statusItem) {
    return;
  }

  if (runtimeProcess) {
    statusItem.text = `$(play) ${PRODUCT_NAME}`;
    statusItem.tooltip = `${PRODUCT_NAME} is running (PID ${runtimeProcess.pid || 'n/a'})`;
  } else {
    statusItem.text = `$(circle-slash) ${PRODUCT_NAME}`;
    statusItem.tooltip = `${PRODUCT_NAME} is stopped`;
  }

  statusItem.command = `${COMMAND_PREFIX}.status`;
  statusItem.show();
}

function startProcess() {
  if (runtimeProcess) {
    vscode.window.showInformationMessage(`${PRODUCT_NAME} is already running.`);
    return;
  }

  const root = resolveProjectRoot();
  const runCommand = String(cfg().get('runCommand', DEFAULT_RUN_COMMAND) || '').trim();
  if (!runCommand) {
    throw new Error(`No run command configured. Set "${CONFIG_NS}.runCommand".`);
  }

  runtimeRoot = root;
  updateStatus();
  log(`Starting ${PRODUCT_NAME} in ${root}`);
  log(`Command: ${runCommand}`);

  const child = spawn(runCommand, {
    cwd: root,
    shell: true,
    env: { ...process.env },
    windowsHide: true
  });

  runtimeProcess = child;
  updateStatus();

  if (cfg().get('showOutputOnStart', true)) {
    output.show(true);
  }

  if (child.stdout) {
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => log(String(chunk).trimEnd()));
  }

  if (child.stderr) {
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => log(`[stderr] ${String(chunk).trimEnd()}`));
  }

  child.on('error', (err) => {
    log(`[error] ${err.message}`);
    vscode.window.showErrorMessage(`${PRODUCT_NAME}: ${err.message}`);
  });

  child.on('exit', (code, signal) => {
    log(`${PRODUCT_NAME} exited (code=${code}, signal=${signal || 'none'})`);
    runtimeProcess = null;
    updateStatus();
  });
}

async function stopProcess() {
  if (!runtimeProcess) {
    vscode.window.showInformationMessage(`${PRODUCT_NAME} is not running.`);
    return;
  }

  const child = runtimeProcess;
  log(`Stopping ${PRODUCT_NAME} (PID ${child.pid || 'n/a'})`);

  const stopped = new Promise((resolve) => {
    const done = () => resolve(undefined);
    child.once('exit', done);
    setTimeout(done, 5000);
  });

  try {
    child.kill('SIGINT');
  } catch {
    // ignored
  }

  await stopped;

  if (runtimeProcess === child) {
    try {
      child.kill();
    } catch {
      // ignored
    }
  }

  runtimeProcess = null;
  updateStatus();
}

async function restartProcess() {
  await stopProcess();
  startProcess();
}

function showStatus() {
  const root = runtimeRoot || (() => {
    try {
      return resolveProjectRoot();
    } catch {
      return 'unresolved';
    }
  })();

  const state = runtimeProcess ? `running (PID ${runtimeProcess.pid || 'n/a'})` : 'stopped';
  const runCommand = String(cfg().get('runCommand', DEFAULT_RUN_COMMAND) || '').trim();

  vscode.window.showInformationMessage(`${PRODUCT_NAME}: ${state}. Root=${root}. Command=${runCommand || 'not set'}`);
}

function runTests() {
  const root = resolveProjectRoot();
  const testCommand = String(cfg().get('testCommand', DEFAULT_TEST_COMMAND) || '').trim();
  if (!testCommand) {
    throw new Error(`No test command configured. Set "${CONFIG_NS}.testCommand".`);
  }

  const terminal = vscode.window.createTerminal({
    name: `${PRODUCT_NAME} Tests`,
    cwd: root
  });

  terminal.show(true);
  terminal.sendText(testCommand, true);
}

async function openReadme() {
  const root = resolveProjectRoot();
  const readmePath = path.join(root, 'README.md');
  if (!fs.existsSync(readmePath)) {
    throw new Error(`README not found at ${readmePath}`);
  }

  const doc = await vscode.workspace.openTextDocument(readmePath);
  await vscode.window.showTextDocument(doc, { preview: false });
}

async function openProjectRoot() {
  const root = resolveProjectRoot();
  await vscode.env.openExternal(vscode.Uri.file(root));
}

function withErrorHandling(fn) {
  return async () => {
    try {
      await fn();
    } catch (err) {
      const message = err && err.message ? err.message : String(err);
      log(`Command failed: ${message}`);
      vscode.window.showErrorMessage(`${PRODUCT_NAME}: ${message}`);
      updateStatus();
    }
  };
}

async function activate(context) {
  output = vscode.window.createOutputChannel(PRODUCT_NAME, { log: true });
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusItem.name = PRODUCT_NAME;

  context.subscriptions.push(output, statusItem);

  context.subscriptions.push(
    vscode.commands.registerCommand(`${COMMAND_PREFIX}.start`, withErrorHandling(startProcess)),
    vscode.commands.registerCommand(`${COMMAND_PREFIX}.stop`, withErrorHandling(stopProcess)),
    vscode.commands.registerCommand(`${COMMAND_PREFIX}.restart`, withErrorHandling(restartProcess)),
    vscode.commands.registerCommand(`${COMMAND_PREFIX}.status`, withErrorHandling(showStatus)),
    vscode.commands.registerCommand(`${COMMAND_PREFIX}.runTests`, withErrorHandling(runTests)),
    vscode.commands.registerCommand(`${COMMAND_PREFIX}.openReadme`, withErrorHandling(openReadme)),
    vscode.commands.registerCommand(`${COMMAND_PREFIX}.openProjectRoot`, withErrorHandling(openProjectRoot))
  );

  context.subscriptions.push({
    dispose: () => {
      if (runtimeProcess) {
        try {
          runtimeProcess.kill();
        } catch {
          // ignored
        }
      }
    }
  });

  updateStatus();

  if (cfg().get('autoStart', false)) {
    await withErrorHandling(startProcess)();
  }

  log(`${PRODUCT_NAME} extension activated.`);
}

async function deactivate() {
  if (runtimeProcess) {
    try {
      runtimeProcess.kill();
    } catch {
      // ignored
    }
    runtimeProcess = null;
  }
}

module.exports = {
  activate,
  deactivate
};
