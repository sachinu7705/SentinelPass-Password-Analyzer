const { app, BrowserWindow } = require('electron')
const path = require('path')

function createWindow () {
  const win = new BrowserWindow({
    width: 900,
    height: 700,
  })

  win.loadURL('http://localhost:5000')
}

app.whenReady().then(createWindow)
