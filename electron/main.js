const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const backendBridge = require('./backend_bridge');

let mainWindow = null;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1080,
        minHeight: 700,
        title: 'ForensiVault — Forensic Data Recovery & Certified Sanitization Platform',
        backgroundColor: '#F3EFE9', // Warm Linen Cream
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false
        }
    });

    mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));

    if (process.env.FORENSIVAULT_TEST === '1') {
        mainWindow.webContents.once('did-finish-load', async () => {
            console.log('[TEST] Page loaded in Electron with full IPC initialized.');
            try {
                const info = await mainWindow.webContents.executeJavaScript('window.forensiAPI.getPlatformInfo()');
                console.log('[TEST] Platform info from IPC:', JSON.stringify(info));
                const drives = await mainWindow.webContents.executeJavaScript('window.forensiAPI.detectDrives()');
                console.log('[TEST] Drives detected via IPC:', drives.length);
                const brand = await mainWindow.webContents.executeJavaScript('document.querySelector(".brand-title").textContent');
                console.log('[TEST] DOM Brand Title:', brand);
                console.log('[TEST] Automated Electron end-to-end verification SUCCEEDED!');
            } catch (err) {
                console.error('[TEST FAILED]', err);
            }
            app.quit();
        });
    }

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

// ----------------------------------------------------------------------------
// IPC Handlers
// ----------------------------------------------------------------------------

ipcMain.handle('system:getInfo', () => {
    return {
        platform: process.platform === 'win32' ? 'Windows x64' : process.platform === 'linux' ? 'Linux x64' : 'macOS',
        binaryPath: backendBridge.getBinaryLocation(),
        nodeVersion: process.versions.node,
        electronVersion: process.versions.electron
    };
});

ipcMain.handle('dialog:selectFile', async (_event, options = {}) => {
    if (!mainWindow) return null;
    const res = await dialog.showOpenDialog(mainWindow, {
        title: options.title || 'Select File',
        properties: ['openFile'],
        filters: options.filters || [{ name: 'All Files', extensions: ['*'] }]
    });
    if (res.canceled || !res.filePaths.length) return null;
    return res.filePaths[0];
});

ipcMain.handle('dialog:selectFolder', async (_event, options = {}) => {
    if (!mainWindow) return null;
    const res = await dialog.showOpenDialog(mainWindow, {
        title: options.title || 'Select Folder',
        properties: ['openDirectory', 'createDirectory']
    });
    if (res.canceled || !res.filePaths.length) return null;
    return res.filePaths[0];
});

ipcMain.handle('dialog:saveFile', async (_event, options = {}) => {
    if (!mainWindow) return null;
    const res = await dialog.showSaveDialog(mainWindow, {
        title: options.title || 'Save File',
        defaultPath: options.defaultPath || 'export.jsonl',
        filters: options.filters || [{ name: 'JSON Lines', extensions: ['jsonl', 'json'] }]
    });
    if (res.canceled || !res.filePath) return null;
    return res.filePath;
});

ipcMain.handle('drive:detect', async () => {
    return await backendBridge.detectDrives();
});

ipcMain.handle('drive:sanitize', async (_event, { target, standard }) => {
    return await backendBridge.sanitizeDrive(target, standard, (progress) => {
        if (mainWindow) mainWindow.webContents.send('drive:progress', progress);
    });
});

ipcMain.handle('file:preview', async (_event, targetPath) => {
    return await backendBridge.erasePreview(targetPath);
});

ipcMain.handle('file:erase', async (_event, { targetPath, method }) => {
    return await backendBridge.erase(targetPath, method, (progress) => {
        if (mainWindow) mainWindow.webContents.send('file:progress', progress);
    });
});

ipcMain.handle('carve:start', async (_event, { imagePath, outputDir }) => {
    return await backendBridge.carve(imagePath, outputDir, (progress) => {
        if (mainWindow) mainWindow.webContents.send('carve:progress', progress);
    });
});

ipcMain.handle('fs:recover', async (_event, { imagePath, outputDir }) => {
    return await backendBridge.fsRecover(imagePath, outputDir);
});

ipcMain.handle('disk:inspect', async (_event, imagePath) => {
    return await backendBridge.inspectDrive(imagePath);
});

ipcMain.handle('bench:run', async () => {
    return await backendBridge.benchmark();
});

ipcMain.handle('audit:export', async (_event, savePath) => {
    return await backendBridge.auditExport(savePath);
});

ipcMain.handle('shell:openPath', async (_event, targetPath) => {
    if (!targetPath) return { success: false, error: 'Path not specified' };
    const resolvedPath = path.isAbsolute(targetPath) ? targetPath : path.resolve(process.cwd(), targetPath);
    if (!fs.existsSync(resolvedPath)) {
        fs.mkdirSync(resolvedPath, { recursive: true });
    }
    const err = await shell.openPath(resolvedPath);
    return { success: !err, error: err };
});

ipcMain.handle('fs:listDirectory', async (_event, targetPath) => {
    try {
        const resolvedPath = path.isAbsolute(targetPath) ? targetPath : path.resolve(process.cwd(), targetPath);
        if (!fs.existsSync(resolvedPath)) {
            return { exists: false, files: [] };
        }
        const entries = fs.readdirSync(resolvedPath, { withFileTypes: true });
        const files = [];
        for (const entry of entries) {
            const fullPath = path.join(resolvedPath, entry.name);
            try {
                const stats = fs.statSync(fullPath);
                files.push({
                    name: entry.name,
                    fullPath,
                    isDirectory: entry.isDirectory(),
                    size: stats.size,
                    modified: stats.mtime.toISOString(),
                    created: stats.birthtime.toISOString()
                });
            } catch (e) {
                files.push({
                    name: entry.name,
                    fullPath,
                    isDirectory: entry.isDirectory(),
                    size: 0,
                    modified: new Date().toISOString()
                });
            }
        }
        return { exists: true, path: resolvedPath, files };
    } catch (err) {
        return { exists: false, error: err.message, files: [] };
    }
});
