/**
 * Build standalone Promptheus CLI with PyInstaller and place in resources/bin
 * for inclusion in the packaged Electron app. Run from repo root:
 *   node apps/desktop/scripts/build-cli.js
 * Requires: Python with promptheus deps, pyinstaller (pip install pyinstaller)
 */
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const repoRoot = path.resolve(__dirname, '../..');
const desktopDir = path.join(repoRoot, 'apps', 'desktop');
const resourcesBin = path.join(desktopDir, 'resources', 'bin');
const specPath = path.join(desktopDir, 'promptheus-cli.spec');

if (!fs.existsSync(specPath)) {
  console.error('Spec file not found:', specPath);
  process.exit(1);
}

fs.mkdirSync(resourcesBin, { recursive: true });

const result = spawnSync(
  'pyinstaller',
  ['--clean', '--noconfirm', '--distpath', resourcesBin, '--workpath', path.join(desktopDir, 'build-cli'), '--specpath', desktopDir, specPath],
  { cwd: repoRoot, stdio: 'inherit', shell: true }
);

if (result.status !== 0) {
  console.error('PyInstaller failed. Ensure pyinstaller is installed (pip install pyinstaller) and run from repo root.');
  process.exit(result.status ?? 1);
}

// PyInstaller with --distpath resources/bin puts the exe directly in resources/bin
const exeName = process.platform === 'win32' ? 'promptheus.exe' : 'promptheus';
const exePath = path.join(resourcesBin, exeName);
if (fs.existsSync(exePath)) {
  console.log('CLI built:', exePath);
} else {
  console.warn('Expected executable not found at', exePath);
}
