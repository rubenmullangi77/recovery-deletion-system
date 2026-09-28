const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

class BackendBridge {
    constructor() {
        this.binaryPath = this.resolveBinaryPath();
    }

    resolveBinaryPath() {
        const isWin = process.platform === 'win32';
        const binaryName = isWin ? 'forensivault_cli.exe' : 'forensivault_cli';

        const possibleLocations = [
            path.join(__dirname, '..', 'build', 'bin', binaryName),
            path.join(__dirname, '..', 'build', 'bin', 'Release', binaryName),
            path.join(__dirname, '..', 'bin', binaryName),
            path.join(process.cwd(), 'build', 'bin', binaryName)
        ];

        for (const loc of possibleLocations) {
            if (fs.existsSync(loc)) {
                return loc;
            }
        }

        return binaryName; // Fallback to PATH
    }

    getBinaryLocation() {
        return this.binaryPath;
    }

    executeCommand(args, onStdout, onStderr) {
        return new Promise((resolve) => {
            const child = spawn(this.binaryPath, args, {
                windowsHide: true
            });
            try { child.stdin.end(); } catch (e) {}

            let fullStdout = '';
            let fullStderr = '';

            child.stdout.on('data', (chunk) => {
                const text = chunk.toString();
                fullStdout += text;
                if (onStdout) onStdout(text);
            });

            child.stderr.on('data', (chunk) => {
                const text = chunk.toString();
                fullStderr += text;
                if (onStderr) onStderr(text);
            });

            child.on('close', (code) => {
                resolve({
                    code,
                    stdout: fullStdout,
                    stderr: fullStderr,
                    success: code === 0
                });
            });

            child.on('error', (err) => {
                resolve({
                    code: -1,
                    stdout: fullStdout,
                    stderr: err.message,
                    success: false
                });
            });
        });
    }

    async detectDrives() {
        const res = await this.executeCommand(['--detect-drives']);
        const lines = res.stdout.split('\n');
        const devices = [];
        let currentDev = null;

        for (let rawLine of lines) {
            const line = rawLine.trim();
            if (line.startsWith('Device:')) {
                if (currentDev) devices.push(currentDev);
                const parts = line.replace('Device:', '').trim();
                const parenMatch = parts.match(/^(.*?)\s*\((.*?)\)$/);
                currentDev = {
                    deviceId: parenMatch ? parenMatch[1].trim() : parts,
                    name: parenMatch ? parenMatch[2].trim() : parts,
                    model: 'Generic Storage',
                    interfaceType: 'Unknown',
                    mediaType: 'Storage',
                    sizeText: '',
                    isSystem: false,
                    isSafe: true,
                    capabilities: []
                };
            } else if (currentDev) {
                if (line.startsWith('Model:')) currentDev.model = line.replace('Model:', '').trim();
                else if (line.startsWith('Interface:')) currentDev.interfaceType = line.replace('Interface:', '').trim();
                else if (line.startsWith('Media Type:')) currentDev.mediaType = line.replace('Media Type:', '').trim();
                else if (line.startsWith('Capacity:')) currentDev.sizeText = line.replace('Capacity:', '').trim();
                else if (line.startsWith('System/Root:')) currentDev.isSystem = line.includes('YES');
                else if (line.startsWith('Safe to Wipe:')) currentDev.isSafe = line.includes('YES');
                else if (line.startsWith('Capabilities:')) currentDev.capabilities.push(line.replace('Capabilities:', '').trim());
            }
        }
        if (currentDev) devices.push(currentDev);
        return devices;
    }

    async erasePreview(targetPath) {
        const res = await this.executeCommand(['--erase-preview', targetPath]);
        const stdout = res.stdout;

        const isProtected = stdout.includes('SYSTEM PATH DETECTED');
        let filesCount = 0;
        let foldersCount = 0;
        let bytesCount = 0;

        const filesMatch = stdout.match(/Files to Erase:\s+(\d+)/);
        if (filesMatch) filesCount = parseInt(filesMatch[1], 10);

        const foldersMatch = stdout.match(/Folders to Remove:\s+(\d+)/);
        if (foldersMatch) foldersCount = parseInt(foldersMatch[1], 10);

        const bytesMatch = stdout.match(/Total Bytes:\s+(\d+)/);
        if (bytesMatch) bytesCount = parseInt(bytesMatch[1], 10);

        return {
            target: targetPath,
            isProtected,
            filesCount,
            foldersCount,
            bytesCount,
            rawOutput: stdout
        };
    }

    erase(targetPath, method, onProgress) {
        const args = ['--erase', targetPath, '--confirm'];
        if (method === 'DOD') args.push('--dod');
        else if (method === 'RANDOM') args.push('--random');

        return this.executeCommand(args, (chunk) => {
            if (!onProgress) return;
            const match = chunk.match(/Overwriting:\s+([\d\.]+)%\s+\[Pass\s+(\d+)\/(\d+)\]\s+(.*)/);
            if (match) {
                onProgress({
                    percent: parseFloat(match[1]),
                    currentPass: parseInt(match[2], 10),
                    totalPasses: parseInt(match[3], 10),
                    currentFile: match[4].trim()
                });
            }
        });
    }

    sanitizeDrive(targetPath, standard, onProgress) {
        const args = ['--sanitize-drive', targetPath, '--confirm'];
        if (standard === 'DOD') args.push('--dod');
        else if (standard === 'RANDOM') args.push('--random');

        return this.executeCommand(args, (chunk) => {
            if (!onProgress) return;
            const match = chunk.match(/Sanitizing:\s+([\d\.]+)%\s+\[Pass\s+(\d+)\/(\d+)\]/);
            if (match) {
                onProgress({
                    percent: parseFloat(match[1]),
                    currentPass: parseInt(match[2], 10),
                    totalPasses: parseInt(match[3], 10)
                });
            }
        });
    }

    carve(imagePath, outputDir, onProgress) {
        const args = ['--carve', imagePath, outputDir];
        return this.executeCommand(args, (chunk) => {
            if (!onProgress) return;
            const match = chunk.match(/([\d\.]+)%\s+\|\s+Discovered:\s+(\d+)/);
            if (match) {
                onProgress({
                    percent: parseFloat(match[1]),
                    discoveredFiles: parseInt(match[2], 10)
                });
            }
        });
    }

    fsRecover(imagePath, outputDir) {
        return this.executeCommand(['--fs-recover', imagePath, outputDir]);
    }

    inspectDrive(imagePath) {
        return this.executeCommand(['--scan-image', imagePath]);
    }

    benchmark() {
        return this.executeCommand(['--benchmark-hash']);
    }

    auditExport(savePath) {
        return this.executeCommand(['--audit-export', savePath]);
    }
}

module.exports = new BackendBridge();
