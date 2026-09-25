# ForensiVault

ForensiVault is an integrated C++17 software platform that unifies certified data sanitization with forensic-grade file recovery and carving capabilities.

---

## Background

With the growth of digital storage technologies, organizations, government agencies, law enforcement units, enterprises, and individual users face two major challenges: securely destroying sensitive data to prevent unauthorized recovery, and recovering deleted digital evidence during forensic investigations. Existing solutions generally focus on either secure data deletion or file recovery, forcing investigators to use multiple fragmented tools. ForensiVault addresses this by combining certified data sanitization with forensic file carving in a single native environment.

---

## Core Modules

### 1. Secure Drive Eraser Module
- Supports HDDs, SSDs, USB drives, memory cards, and external storage devices.
- Certified erasure standards: NIST SP 800-88 Rev 1 (Clear / Purge), DoD 5220.22-M (3-Pass with read-back verification), and Cryptographic Pseudorandom overwrite.
- Post-wipe verification: Shannon entropy calculation, pattern-match verification, and pre/post-wipe cryptographic hash comparison.
- Full hardware disclosures for SSD NAND storage (FTL wear leveling / overprovisioning).
- Immutable, cryptographically chained audit logging.

### 2. Secure File and Folder Eraser Module
- Selective secure deletion of targeted files and directories.
- Residual metadata removal: filename obfuscation, timestamp scrambling, and zero-truncation prior to unlinking.
- Batch processing and recursive directory sanitization.
- Non-destructive pre-erase preview showing total files, folders, bytes, and safety classification.
- Safety interlock: permanently blocks attempts to sanitize root drives (`/` or `C:\`) and critical system paths (`/boot`, `/etc`, `C:\Windows`).

### 3. Advanced File Carving and Recovery Module
- File recovery from formatted, damaged, or corrupted raw media without relying on filesystem metadata.
- Dual-mode operation:
  - Filesystem metadata extraction for FAT32, exFAT, and NTFS (directory tables, stream extensions, and $MFT tombstones).
  - Raw sector signature-based and structure-based carving.
- Bifragment gap analysis and conservative reconstruction for fragmented files.
- Automated format validation and classification for JPEG, PNG, PDF, ZIP, DOCX, XLSX, MP4, and MP3.
- Explainable confidence scoring (0-100%, High / Medium / Low) with forensic validation reasoning.
- Strict read-only access ensuring evidence immutability and preservation of chain of custody.

---

## Interface & Tooling

- **Interactive Terminal**: Text-based interface featuring real-time path autocompletion powered by `fzf`.
- **Scriptable CLI**: Command-line arguments for automated pipelines (`--carve`, `--fs-recover`, `--erase`, `--sanitize-drive`, `--scan-image`, `--inspect-drive`, `--detect-drives`).
- **Decoupled C++ Public API**: Public headers located in `backend/include/forensivault/` (`file_eraser.hpp`, `drive_sanitizer.hpp`, `carver.hpp`, `fs_recovery.hpp`) decoupled from internal logic for future GUI integration.

---

## Building

Build instructions for both Linux and Windows are documented in [BUILD.md](BUILD.md).

Quick start (Linux):
```bash
./build.sh
./build/bin/forensivault_cli
```

Quick start (Windows):
```cmd
build.bat
build\bin\forensivault_cli.exe
```

---

## Standards Compliance

- NIST SP 800-88 Rev 1: Guidelines for Media Sanitization
- DoD 5220.22-M: National Industrial Security Program Operating Manual (NISPOM)
- ISO/IEC 27037: Guidelines for identification, collection, acquisition, and preservation of digital evidence
