# ForensiVault

ForensiVault is an integrated C++17 software platform that unifies certified data sanitization with forensic-grade file recovery and carving capabilities.

## Interfaces & Tooling

- **Dear ImGui Native Desktop GUI**: Lightweight hardware-accelerated desktop application (Windows & Linux) with 12 forensic modules, asynchronous progress telemetry, interactive tables, safety interlocks, and Neumorphic cream & orange styling.
- **Interactive Terminal**: Text-based interface featuring real-time path autocompletion powered by `fzf`.
- **Scriptable CLI**: Command-line arguments for automated pipelines (`--carve`, `--fs-recover`, `--erase`, `--sanitize-drive`, `--scan-image`, `--inspect-drive`, `--detect-drives`).
- **Decoupled Architecture**: Clean standalone C++ API headers located in `backend/include/forensivault/` (`file_eraser.hpp`, `drive_sanitizer.hpp`, `carver.hpp`, `fs_recovery.hpp`). The GUI frontends live completely independently in `gui/` and can be built or modified without touching the backend library.

---

## Launching & Building

### 1. C++ Backend & Dear ImGui GUI
Build instructions for both Linux and Windows are documented in [BUILD.md](BUILD.md).

Quick start (Linux):
```bash
./build.sh
./build/bin/forensivault-gui      # Dear ImGui GUI
./build/bin/forensivault_cli      # Interactive Terminal
```

Quick start (Windows):
```cmd
build.bat
build\bin\forensivault-gui.exe    # Dear ImGui GUI
build\bin\forensivault_cli.exe    # Interactive Terminal
```

---

## Standards Compliance

- NIST SP 800-88 Rev 1: Guidelines for Media Sanitization
- DoD 5220.22-M: National Industrial Security Program Operating Manual (NISPOM)
- ISO/IEC 27037: Guidelines for identification, collection, acquisition, and preservation of digital evidence
