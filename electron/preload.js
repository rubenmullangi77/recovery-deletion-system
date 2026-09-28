const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('forensiAPI', {
    // Dialogs
    selectFile: (options) => ipcRenderer.invoke('dialog:selectFile', options),
    selectFolder: (options) => ipcRenderer.invoke('dialog:selectFolder', options),
    saveFile: (options) => ipcRenderer.invoke('dialog:saveFile', options),

    // System info
    getPlatformInfo: () => ipcRenderer.invoke('system:getInfo'),

    // Module 1: Drive Sanitizer
    detectDrives: () => ipcRenderer.invoke('drive:detect'),
    sanitizeDrive: (target, standard) => ipcRenderer.invoke('drive:sanitize', { target, standard }),
    onDriveProgress: (callback) => {
        ipcRenderer.on('drive:progress', (_event, data) => callback(data));
    },

    // Module 2: File & Folder Eraser
    erasePreview: (targetPath) => ipcRenderer.invoke('file:preview', targetPath),
    eraseTarget: (targetPath, method) => ipcRenderer.invoke('file:erase', { targetPath, method }),
    onEraseProgress: (callback) => {
        ipcRenderer.on('file:progress', (_event, data) => callback(data));
    },

    // Module 3: File Carver
    carveImage: (imagePath, outputDir) => ipcRenderer.invoke('carve:start', { imagePath, outputDir }),
    onCarveProgress: (callback) => {
        ipcRenderer.on('carve:progress', (_event, data) => callback(data));
    },

    // Module 4: Filesystem Recovery
    fsRecover: (imagePath, outputDir) => ipcRenderer.invoke('fs:recover', { imagePath, outputDir }),

    // Module 5: Disk Geometry & Inspection
    inspectDrive: (imagePath) => ipcRenderer.invoke('disk:inspect', imagePath),

    // Module 7: Benchmark
    runBenchmark: () => ipcRenderer.invoke('bench:run'),

    // Module 8: Audit
    exportAudit: (savePath) => ipcRenderer.invoke('audit:export', savePath),

    // Explorer & File System Helpers
    openPath: (targetPath) => ipcRenderer.invoke('shell:openPath', targetPath),
    listDirectory: (targetPath) => ipcRenderer.invoke('fs:listDirectory', targetPath)
});
