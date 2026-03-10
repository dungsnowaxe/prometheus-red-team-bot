const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  runScan: (targetUrl) => ipcRenderer.invoke('run-scan', targetUrl),
  runAgentScan: (options) => ipcRenderer.invoke('run-agent-scan', options),
  runPrReview: (options) => ipcRenderer.invoke('run-pr-review', options),
  cancelScan: () => ipcRenderer.invoke('cancel-scan'),
  getCliPathOverride: () => ipcRenderer.invoke('get-cli-path-override'),
  setCliPathOverride: (value) => ipcRenderer.invoke('set-cli-path-override', value),
  onScanOutput: (callback) => {
    ipcRenderer.on('scan-output', (_, data) => callback(data));
  },
});
