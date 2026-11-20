const { app, BrowserWindow, shell } = require('electron');
app.commandLine.appendSwitch('ignore-certificate-errors');
function open() {
  const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });
  win.loadURL('http://shop.vuln-site.lk');
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
}
app.whenReady().then(open);
