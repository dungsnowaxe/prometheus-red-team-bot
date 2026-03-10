import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'node:path';
import started from 'electron-squirrel-startup';
import { getCliPathOverride, setCliPathOverride } from './store.js';
import { getCliPath, runScan, runAgentScan, runPrReview } from './scan.js';

// Enable remote debugging in dev mode for automated testing
if (!app.isPackaged) {
  app.commandLine.appendSwitch('remote-debugging-port', '9222');
}

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (started) {
  app.quit();
}

let mainWindowRef = null;

const createWindow = () => {
  // Create the browser window.
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  // and load the index.html of the app.
  if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`));
  }

  mainWindowRef = mainWindow;
  // Open the DevTools (optional; can remove for production)
  // mainWindow.webContents.openDevTools();
};

let currentScanKill = null;

function setupIpc() {
  const sendOutput = (event, data) => {
    mainWindowRef?.webContents?.send('scan-output', { event, data });
  };

  ipcMain.handle('run-scan', async (_, targetUrl) => {
    const override = getCliPathOverride();
    const cliPath = getCliPath(override);
    const result = await runScan(cliPath, targetUrl, sendOutput);
    return result;
  });

  ipcMain.handle('run-agent-scan', async (_, options) => {
    const override = getCliPathOverride();
    const cliPath = getCliPath(override);
    const { promise, kill } = runAgentScan(cliPath, options, sendOutput);
    currentScanKill = kill;
    try {
      return await promise;
    } finally {
      currentScanKill = null;
    }
  });

  ipcMain.handle('run-pr-review', async (_, options) => {
    const override = getCliPathOverride();
    const cliPath = getCliPath(override);
    const { promise, kill } = runPrReview(cliPath, options, sendOutput);
    currentScanKill = kill;
    try {
      return await promise;
    } finally {
      currentScanKill = null;
    }
  });

  ipcMain.handle('cancel-scan', () => {
    if (currentScanKill) {
      currentScanKill();
      currentScanKill = null;
    }
  });

  ipcMain.handle('get-cli-path-override', () => getCliPathOverride() ?? '');
  ipcMain.handle('set-cli-path-override', (_, value) => {
    setCliPathOverride(value);
  });
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(() => {
  setupIpc();
  createWindow();

  // On OS X it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and import them here.
