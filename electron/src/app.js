/**
 * ForensiVault — Minimalist Frontend Application Controller
 * Strict Cream & Orange Neumorphism • Fast & Streamlined
 */

document.addEventListener('DOMContentLoaded', async () => {
    let pendingDestructiveAction = null;
    let detectedDrivesCache = [];

    // Helper: Format bytes
    function formatBytes(bytes) {
        if (!bytes || isNaN(bytes) || bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Helper: Toast notification
    function showNotification(message) {
        const existing = document.getElementById('floating-toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.id = 'floating-toast';
        toast.className = 'toast-notice';
        toast.textContent = message;

        document.body.appendChild(toast);
        setTimeout(() => {
            if (toast.parentNode) toast.remove();
        }, 3500);
    }

    // Helper: Escape HTML
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // -------------------------------------------------------------------------
    // 1. System Platform Check
    // -------------------------------------------------------------------------
    try {
        const info = await window.forensiAPI.getPlatformInfo();
        const badgePlatform = document.getElementById('badgePlatform');
        if (badgePlatform && info.platform) {
            badgePlatform.textContent = info.platform;
        }
    } catch (err) {
        console.error('Platform check failed:', err);
    }

    // -------------------------------------------------------------------------
    // 2. Tab Navigation
    // -------------------------------------------------------------------------
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');

    function switchTab(targetTabId) {
        navItems.forEach(item => {
            if (item.getAttribute('data-tab') === targetTabId) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });

        tabPanes.forEach(pane => {
            if (pane.id === `pane-${targetTabId}`) {
                pane.style.display = 'block';
            } else {
                pane.style.display = 'none';
            }
        });

        if (targetTabId === 'deviceDetector') {
            loadStorageDevices();
        } else if (targetTabId === 'driveSanitizer') {
            refreshDriveDropdown();
        } else if (targetTabId === 'evidenceCatalog') {
            loadEvidenceCatalog();
        }
    }

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const tab = item.getAttribute('data-tab');
            if (tab) switchTab(tab);
        });
    });

    // Dashboard Direct Buttons
    const btnDashLaunchCarver = document.getElementById('btnDashLaunchCarver');
    const btnDashLaunchFs = document.getElementById('btnDashLaunchFs');
    const btnDashLaunchCatalog = document.getElementById('btnDashLaunchCatalog');
    const btnDashLaunchEraser = document.getElementById('btnDashLaunchEraser');
    const btnDashLaunchDriveSanitize = document.getElementById('btnDashLaunchDriveSanitize');
    const btnDashLaunchDevices = document.getElementById('btnDashLaunchDevices');

    if (btnDashLaunchCarver) btnDashLaunchCarver.addEventListener('click', () => switchTab('carver'));
    if (btnDashLaunchFs) btnDashLaunchFs.addEventListener('click', () => switchTab('fsRecovery'));
    if (btnDashLaunchCatalog) btnDashLaunchCatalog.addEventListener('click', () => switchTab('evidenceCatalog'));
    if (btnDashLaunchEraser) btnDashLaunchEraser.addEventListener('click', () => switchTab('fileEraser'));
    if (btnDashLaunchDriveSanitize) btnDashLaunchDriveSanitize.addEventListener('click', () => switchTab('driveSanitizer'));
    if (btnDashLaunchDevices) btnDashLaunchDevices.addEventListener('click', () => switchTab('deviceDetector'));

    // -------------------------------------------------------------------------
    // 3. Confirmation Modal
    // -------------------------------------------------------------------------
    const safetyModal = document.getElementById('safetyModal');
    const modalTargetText = document.getElementById('modalTargetText');
    const modalConfirmInput = document.getElementById('modalConfirmInput');
    const modalBtnCancel = document.getElementById('modalBtnCancel');
    const modalBtnConfirm = document.getElementById('modalBtnConfirm');

    function openSafetyModal(targetDesc, onConfirmAction) {
        pendingDestructiveAction = onConfirmAction;
        modalTargetText.innerHTML = `<strong>Target:</strong> ${escapeHtml(targetDesc)}`;
        modalConfirmInput.value = '';
        modalBtnConfirm.disabled = true;
        safetyModal.classList.add('active');
        modalConfirmInput.focus();
    }

    function closeSafetyModal() {
        safetyModal.classList.remove('active');
        pendingDestructiveAction = null;
        modalConfirmInput.value = '';
        modalBtnConfirm.disabled = true;
    }

    modalConfirmInput.addEventListener('input', () => {
        modalBtnConfirm.disabled = (modalConfirmInput.value.trim().toUpperCase() !== 'DESTROY');
    });

    modalBtnCancel.addEventListener('click', closeSafetyModal);

    modalBtnConfirm.addEventListener('click', async () => {
        if (modalConfirmInput.value.trim().toUpperCase() !== 'DESTROY') return;
        const action = pendingDestructiveAction;
        closeSafetyModal();
        if (action) await action();
    });

    // -------------------------------------------------------------------------
    // 4. File Carver
    // -------------------------------------------------------------------------
    const carverImagePath = document.getElementById('carverImagePath');
    const carverOutputDir = document.getElementById('carverOutputDir');
    const btnBrowseCarverImage = document.getElementById('btnBrowseCarverImage');
    const btnBrowseCarverOut = document.getElementById('btnBrowseCarverOut');
    const btnStartCarve = document.getElementById('btnStartCarve');

    const carverProgressCard = document.getElementById('carverProgressCard');
    const carverProgressFill = document.getElementById('carverProgressFill');
    const carverProgressStatus = document.getElementById('carverProgressStatus');
    const carverProgressFiles = document.getElementById('carverProgressFiles');

    const carverResultCard = document.getElementById('carverResultCard');
    const carverResultContent = document.getElementById('carverResultContent');

    btnBrowseCarverImage.addEventListener('click', async () => {
        const file = await window.forensiAPI.selectFile({ title: 'Select File to Carve' });
        if (file) carverImagePath.value = file;
    });

    btnBrowseCarverOut.addEventListener('click', async () => {
        const folder = await window.forensiAPI.selectFolder({ title: 'Select Output Folder' });
        if (folder) carverOutputDir.value = folder;
    });

    btnStartCarve.addEventListener('click', async () => {
        const image = carverImagePath.value.trim();
        const outDir = carverOutputDir.value.trim() || 'recovered/carved';

        if (!image) {
            showNotification('Please select a file or disk image to carve.');
            return;
        }

        carverProgressCard.style.display = 'block';
        carverProgressFill.style.width = '0%';
        carverProgressStatus.textContent = '0%';
        carverProgressFiles.textContent = '0 files';
        carverResultCard.style.display = 'none';
        btnStartCarve.disabled = true;

        try {
            const res = await window.forensiAPI.carveImage(image, outDir);
            carverProgressCard.style.display = 'none';
            carverResultCard.style.display = 'block';

            carverResultContent.innerHTML = `<pre class="console-box">${escapeHtml(res.stdout || res.stderr || 'Completed.')}</pre>`;
            showNotification(res.success ? 'Carving completed!' : 'Carving finished with warnings.');
            loadEvidenceCatalog();
        } catch (err) {
            carverProgressCard.style.display = 'none';
            carverResultCard.style.display = 'block';
            carverResultContent.innerHTML = `<pre class="console-box">${escapeHtml(err.message)}</pre>`;
        } finally {
            btnStartCarve.disabled = false;
        }
    });

    window.forensiAPI.onCarveProgress((p) => {
        carverProgressFill.style.width = `${Math.min(100, Math.max(0, p.percent))}%`;
        carverProgressStatus.textContent = `${p.percent.toFixed(0)}%`;
        carverProgressFiles.textContent = `${p.discoveredFiles} files`;
    });

    // -------------------------------------------------------------------------
    // 5. Filesystem Recovery
    // -------------------------------------------------------------------------
    const fsImagePath = document.getElementById('fsImagePath');
    const fsOutputDir = document.getElementById('fsOutputDir');
    const btnBrowseFsImage = document.getElementById('btnBrowseFsImage');
    const btnBrowseFsOut = document.getElementById('btnBrowseFsOut');
    const btnStartFsRecover = document.getElementById('btnStartFsRecover');

    const fsResultCard = document.getElementById('fsResultCard');
    const fsResultContent = document.getElementById('fsResultContent');

    btnBrowseFsImage.addEventListener('click', async () => {
        const file = await window.forensiAPI.selectFile({ title: 'Select Disk Image' });
        if (file) fsImagePath.value = file;
    });

    btnBrowseFsOut.addEventListener('click', async () => {
        const folder = await window.forensiAPI.selectFolder({ title: 'Select Output Folder' });
        if (folder) fsOutputDir.value = folder;
    });

    btnStartFsRecover.addEventListener('click', async () => {
        const img = fsImagePath.value.trim();
        const out = fsOutputDir.value.trim() || 'recovered/filesystem';

        if (!img) {
            showNotification('Please select a disk image.');
            return;
        }

        btnStartFsRecover.disabled = true;
        fsResultCard.style.display = 'none';

        try {
            const res = await window.forensiAPI.fsRecover(img, out);
            fsResultCard.style.display = 'block';
            fsResultContent.innerHTML = `<pre class="console-box">${escapeHtml(res.stdout || res.stderr || 'Completed.')}</pre>`;
            showNotification(res.success ? 'Recovery finished!' : 'Recovery finished with warnings.');
            loadEvidenceCatalog();
        } catch (err) {
            fsResultCard.style.display = 'block';
            fsResultContent.innerHTML = `<pre class="console-box">${escapeHtml(err.message)}</pre>`;
        } finally {
            btnStartFsRecover.disabled = false;
        }
    });

    // -------------------------------------------------------------------------
    // 6. Recovered Files Catalog
    // -------------------------------------------------------------------------
    const catalogDirPath = document.getElementById('catalogDirPath');
    const btnBrowseCatalogDir = document.getElementById('btnBrowseCatalogDir');
    const btnRefreshCatalog = document.getElementById('btnRefreshCatalog');
    const btnOpenCatalogFolder = document.getElementById('btnOpenCatalogFolder');
    const catalogCountBadge = document.getElementById('catalogCountBadge');
    const evidenceTableBody = document.getElementById('evidenceTableBody');

    async function loadEvidenceCatalog() {
        const targetDir = (catalogDirPath && catalogDirPath.value.trim()) || 'recovered';
        if (!evidenceTableBody) return;

        evidenceTableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 20px;">Scanning files...</td></tr>';

        try {
            let res = await window.forensiAPI.listDirectory(targetDir);
            let allFiles = [];

            if (res.exists) {
                for (const item of res.files) {
                    if (item.isDirectory) {
                        const subRes = await window.forensiAPI.listDirectory(item.fullPath);
                        if (subRes.exists) {
                            subRes.files.forEach(f => {
                                if (!f.isDirectory) allFiles.push(f);
                            });
                        }
                    } else {
                        allFiles.push(item);
                    }
                }
            }

            if (catalogCountBadge) {
                catalogCountBadge.textContent = `${allFiles.length} files`;
            }

            if (allFiles.length === 0) {
                evidenceTableBody.innerHTML = `
                    <tr>
                        <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 25px;">
                            No files found in <code>${escapeHtml(targetDir)}</code>.
                        </td>
                    </tr>
                `;
                return;
            }

            let rowsHtml = '';
            allFiles.forEach(file => {
                const dateStr = file.modified ? new Date(file.modified).toLocaleDateString() : '-';
                rowsHtml += `
                    <tr>
                        <td><strong>${escapeHtml(file.name)}</strong></td>
                        <td>${formatBytes(file.size)}</td>
                        <td>${dateStr}</td>
                        <td>
                            <button class="btn btn-secondary open-evidence-btn" data-path="${escapeHtml(file.fullPath)}" style="padding: 4px 10px; font-size: 12px;">
                                Open
                            </button>
                        </td>
                    </tr>
                `;
            });

            evidenceTableBody.innerHTML = rowsHtml;

            document.querySelectorAll('.open-evidence-btn').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const filePath = btn.getAttribute('data-path');
                    if (filePath) await window.forensiAPI.openPath(filePath);
                });
            });

        } catch (err) {
            evidenceTableBody.innerHTML = `<tr><td colspan="4" style="padding: 15px;">Error: ${escapeHtml(err.message)}</td></tr>`;
        }
    }

    if (btnRefreshCatalog) btnRefreshCatalog.addEventListener('click', loadEvidenceCatalog);

    if (btnBrowseCatalogDir) {
        btnBrowseCatalogDir.addEventListener('click', async () => {
            const folder = await window.forensiAPI.selectFolder({ title: 'Select Folder' });
            if (folder) {
                catalogDirPath.value = folder;
                loadEvidenceCatalog();
            }
        });
    }

    if (btnOpenCatalogFolder) {
        btnOpenCatalogFolder.addEventListener('click', async () => {
            const dir = (catalogDirPath && catalogDirPath.value.trim()) || 'recovered';
            await window.forensiAPI.openPath(dir);
        });
    }

    // -------------------------------------------------------------------------
    // 7. File & Folder Eraser
    // -------------------------------------------------------------------------
    const erasePathInput = document.getElementById('erasePath');
    const btnBrowseFile = document.getElementById('btnBrowseFile');
    const btnBrowseFolder = document.getElementById('btnBrowseFolder');
    const btnPreviewErase = document.getElementById('btnPreviewErase');
    const btnStartErase = document.getElementById('btnStartErase');

    const erasePreviewCard = document.getElementById('erasePreviewCard');
    const erasePreviewContent = document.getElementById('erasePreviewContent');

    const eraseProgressCard = document.getElementById('eraseProgressCard');
    const eraseProgressFill = document.getElementById('eraseProgressFill');
    const eraseProgressStatus = document.getElementById('eraseProgressStatus');
    const eraseProgressFile = document.getElementById('eraseProgressFile');

    const eraseResultCard = document.getElementById('eraseResultCard');
    const eraseResultDetails = document.getElementById('eraseResultDetails');

    btnBrowseFile.addEventListener('click', async () => {
        const filePath = await window.forensiAPI.selectFile({ title: 'Select File' });
        if (filePath) erasePathInput.value = filePath;
    });

    btnBrowseFolder.addEventListener('click', async () => {
        const folderPath = await window.forensiAPI.selectFolder({ title: 'Select Folder' });
        if (folderPath) erasePathInput.value = folderPath;
    });

    btnPreviewErase.addEventListener('click', async () => {
        const target = erasePathInput.value.trim();
        if (!target) {
            showNotification('Please enter or select a target path.');
            return;
        }

        btnPreviewErase.disabled = true;
        erasePreviewCard.style.display = 'none';

        try {
            const preview = await window.forensiAPI.erasePreview(target);
            erasePreviewCard.style.display = 'block';

            erasePreviewContent.innerHTML = `
                <div class="table-responsive">
                    <table class="neu-table">
                        <tbody>
                            <tr><td style="width: 140px;">Target</td><td><code>${escapeHtml(preview.target)}</code></td></tr>
                            <tr><td>Files</td><td><strong>${preview.filesCount}</strong></td></tr>
                            <tr><td>Folders</td><td><strong>${preview.foldersCount}</strong></td></tr>
                            <tr><td>Total Size</td><td><strong>${formatBytes(preview.bytesCount)}</strong></td></tr>
                        </tbody>
                    </table>
                </div>
            `;
        } catch (err) {
            showNotification('Preview failed: ' + err.message);
        } finally {
            btnPreviewErase.disabled = false;
        }
    });

    btnStartErase.addEventListener('click', () => {
        const target = erasePathInput.value.trim();
        if (!target) {
            showNotification('Please enter or select a target path.');
            return;
        }

        const selectedRadio = document.querySelector('input[name="eraseStandard"]:checked');
        const method = selectedRadio ? selectedRadio.value : 'NIST';

        openSafetyModal(target, async () => {
            eraseProgressCard.style.display = 'block';
            eraseProgressFill.style.width = '0%';
            eraseProgressStatus.textContent = '0%';
            eraseResultCard.style.display = 'none';
            btnStartErase.disabled = true;

            try {
                const res = await window.forensiAPI.eraseTarget(target, method);
                eraseProgressCard.style.display = 'none';
                eraseResultCard.style.display = 'block';

                eraseResultDetails.innerHTML = `<pre class="console-box">${escapeHtml(res.stdout || res.stderr || 'Completed.')}</pre>`;
                showNotification(res.success ? 'Erase completed!' : 'Erase finished with warnings.');
            } catch (err) {
                eraseProgressCard.style.display = 'none';
                eraseResultCard.style.display = 'block';
                eraseResultDetails.innerHTML = `<pre class="console-box">${escapeHtml(err.message)}</pre>`;
            } finally {
                btnStartErase.disabled = false;
            }
        });
    });

    window.forensiAPI.onEraseProgress((p) => {
        eraseProgressFill.style.width = `${Math.min(100, Math.max(0, p.percent))}%`;
        eraseProgressStatus.textContent = `${p.percent.toFixed(0)}%`;
        eraseProgressFile.textContent = p.currentFile || 'Overwriting...';
    });

    // -------------------------------------------------------------------------
    // 8. Drive Sanitizer
    // -------------------------------------------------------------------------
    const driveTargetPathInput = document.getElementById('driveTargetPath');
    const btnBrowseDiskImage = document.getElementById('btnBrowseDiskImage');
    const selectDriveDropdown = document.getElementById('selectDriveDropdown');
    const btnStartDriveSanitize = document.getElementById('btnStartDriveSanitize');

    const driveProgressCard = document.getElementById('driveProgressCard');
    const driveProgressFill = document.getElementById('driveProgressFill');
    const driveProgressStatus = document.getElementById('driveProgressStatus');

    const driveResultCard = document.getElementById('driveResultCard');
    const driveResultContent = document.getElementById('driveResultContent');

    async function refreshDriveDropdown() {
        selectDriveDropdown.innerHTML = '<option value="">Scanning...</option>';
        try {
            detectedDrivesCache = await window.forensiAPI.detectDrives();
            selectDriveDropdown.innerHTML = '<option value="">-- Choose Detected Drive --</option>';

            detectedDrivesCache.forEach(dev => {
                const opt = document.createElement('option');
                opt.value = dev.deviceId;
                opt.textContent = `${dev.deviceId} — ${dev.name || dev.model} (${dev.sizeText || 'Drive'})`;
                if (dev.isSystem) opt.disabled = true;
                selectDriveDropdown.appendChild(opt);
            });
        } catch (err) {
            selectDriveDropdown.innerHTML = '<option value="">Failed to scan drives</option>';
        }
    }

    selectDriveDropdown.addEventListener('change', () => {
        if (selectDriveDropdown.value) driveTargetPathInput.value = selectDriveDropdown.value;
    });

    btnBrowseDiskImage.addEventListener('click', async () => {
        const imagePath = await window.forensiAPI.selectFile({ title: 'Select Disk Image' });
        if (imagePath) driveTargetPathInput.value = imagePath;
    });

    btnStartDriveSanitize.addEventListener('click', () => {
        const target = driveTargetPathInput.value.trim();
        if (!target) {
            showNotification('Please select or specify a target.');
            return;
        }

        const selectedRadio = document.querySelector('input[name="driveStandard"]:checked');
        const standard = selectedRadio ? selectedRadio.value : 'NIST';

        openSafetyModal(target, async () => {
            driveProgressCard.style.display = 'block';
            driveProgressFill.style.width = '0%';
            driveProgressStatus.textContent = '0%';
            driveResultCard.style.display = 'none';
            btnStartDriveSanitize.disabled = true;

            try {
                const res = await window.forensiAPI.sanitizeDrive(target, standard);
                driveProgressCard.style.display = 'none';
                driveResultCard.style.display = 'block';

                driveResultContent.innerHTML = `<pre class="console-box">${escapeHtml(res.stdout || res.stderr || 'Completed.')}</pre>`;
                showNotification(res.success ? 'Sanitization completed!' : 'Sanitization finished with warnings.');
            } catch (err) {
                driveProgressCard.style.display = 'none';
                driveResultCard.style.display = 'block';
                driveResultContent.innerHTML = `<pre class="console-box">${escapeHtml(err.message)}</pre>`;
            } finally {
                btnStartDriveSanitize.disabled = false;
            }
        });
    });

    window.forensiAPI.onDriveProgress((p) => {
        driveProgressFill.style.width = `${Math.min(100, Math.max(0, p.percent))}%`;
        driveProgressStatus.textContent = `${p.percent.toFixed(0)}%`;
    });

    // -------------------------------------------------------------------------
    // 9. Storage Devices Detection
    // -------------------------------------------------------------------------
    const devicesListContainer = document.getElementById('devicesListContainer');
    const btnRefreshDevices = document.getElementById('btnRefreshDevices');

    async function loadStorageDevices() {
        devicesListContainer.innerHTML = '<div class="neu-card"><p>Scanning devices...</p></div>';
        try {
            const devices = await window.forensiAPI.detectDrives();
            detectedDrivesCache = devices;

            if (devices.length === 0) {
                devicesListContainer.innerHTML = '<div class="neu-card"><p>No drives detected.</p></div>';
                return;
            }

            let cardsHtml = '';
            devices.forEach(dev => {
                cardsHtml += `
                    <div class="neu-card">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <strong>${escapeHtml(dev.name || dev.deviceId)}</strong>
                            <span class="badge">${dev.isSystem ? 'SYSTEM' : 'DATA'}</span>
                        </div>
                        <div class="table-responsive">
                            <table class="neu-table">
                                <tbody>
                                    <tr><td style="width: 140px;">Device</td><td><code>${escapeHtml(dev.deviceId)}</code></td></tr>
                                    <tr><td>Model</td><td>${escapeHtml(dev.model || '-')}</td></tr>
                                    <tr><td>Capacity</td><td>${escapeHtml(dev.sizeText || '-')}</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            });

            devicesListContainer.innerHTML = cardsHtml;
        } catch (err) {
            devicesListContainer.innerHTML = `<div class="neu-card"><p>Error: ${escapeHtml(err.message)}</p></div>`;
        }
    }

    btnRefreshDevices.addEventListener('click', loadStorageDevices);

    // -------------------------------------------------------------------------
    // 10. Disk Hashes
    // -------------------------------------------------------------------------
    const inspectImagePath = document.getElementById('inspectImagePath');
    const btnBrowseInspectImage = document.getElementById('btnBrowseInspectImage');
    const btnStartInspect = document.getElementById('btnStartInspect');

    const inspectResultCard = document.getElementById('inspectResultCard');
    const inspectResultContent = document.getElementById('inspectResultContent');

    btnBrowseInspectImage.addEventListener('click', async () => {
        const file = await window.forensiAPI.selectFile({ title: 'Select Image or File' });
        if (file) inspectImagePath.value = file;
    });

    btnStartInspect.addEventListener('click', async () => {
        const img = inspectImagePath.value.trim();
        if (!img) {
            showNotification('Please select a file or disk image.');
            return;
        }

        btnStartInspect.disabled = true;
        inspectResultCard.style.display = 'none';

        try {
            const res = await window.forensiAPI.inspectDrive(img);
            inspectResultCard.style.display = 'block';
            inspectResultContent.innerHTML = `<pre class="console-box">${escapeHtml(res.stdout || res.stderr || 'Completed.')}</pre>`;
        } catch (err) {
            inspectResultCard.style.display = 'block';
            inspectResultContent.innerHTML = `<pre class="console-box">${escapeHtml(err.message)}</pre>`;
        } finally {
            btnStartInspect.disabled = false;
        }
    });

    // -------------------------------------------------------------------------
    // 11. Benchmark
    // -------------------------------------------------------------------------
    const btnRunBenchmark = document.getElementById('btnRunBenchmark');
    const benchResultCard = document.getElementById('benchResultCard');
    const benchResultContent = document.getElementById('benchResultContent');

    btnRunBenchmark.addEventListener('click', async () => {
        btnRunBenchmark.disabled = true;
        benchResultCard.style.display = 'none';

        try {
            const res = await window.forensiAPI.runBenchmark();
            benchResultCard.style.display = 'block';
            benchResultContent.innerHTML = `<pre class="console-box">${escapeHtml(res.stdout || res.stderr || 'Completed.')}</pre>`;
        } catch (err) {
            benchResultCard.style.display = 'block';
            benchResultContent.innerHTML = `<pre class="console-box">${escapeHtml(err.message)}</pre>`;
        } finally {
            btnRunBenchmark.disabled = false;
        }
    });

    // -------------------------------------------------------------------------
    // 12. Audit Log Export
    // -------------------------------------------------------------------------
    const btnExportAudit = document.getElementById('btnExportAudit');
    const auditResultCard = document.getElementById('auditResultCard');
    const auditResultContent = document.getElementById('auditResultContent');

    btnExportAudit.addEventListener('click', async () => {
        const savePath = await window.forensiAPI.saveFile({
            title: 'Export Audit Log',
            defaultPath: 'forensivault_audit.jsonl'
        });

        if (!savePath) return;

        btnExportAudit.disabled = true;
        auditResultCard.style.display = 'none';

        try {
            const res = await window.forensiAPI.exportAudit(savePath);
            auditResultCard.style.display = 'block';
            auditResultContent.innerHTML = `<pre class="console-box">${escapeHtml(res.stdout || res.stderr || 'Export completed: ' + savePath)}</pre>`;
            showNotification('Audit log exported successfully!');
        } catch (err) {
            auditResultCard.style.display = 'block';
            auditResultContent.innerHTML = `<pre class="console-box">${escapeHtml(err.message)}</pre>`;
        } finally {
            btnExportAudit.disabled = false;
        }
    });

    // Initial background loading
    refreshDriveDropdown();
    loadEvidenceCatalog();
});
