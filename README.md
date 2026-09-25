# ForensiVault

ForensiVault is an integrated C++17 software platform that unifies certified data sanitization with forensic-grade file recovery and carving capabilities.

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
