// SPDX-FileCopyrightText: 2026 Rubi960 & Ryosh1
//
// SPDX-License-Identifier: MIT

const { app, BrowserWindow } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 380,
    height: 520,
    resizable: false,
    title: 'Search Explorer',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  win.loadFile('index.html');

  // Quita la barra de menú (opcional, más limpio)
  win.setMenuBarVisibility(false);
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  app.quit();
});
