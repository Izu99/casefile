const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('bridge', { ipc: ipcRenderer });
