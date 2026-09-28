# ForensiVault

ForensiVault is an integrated C++17 software platform that unifies certified data sanitization with forensic-grade file recovery and carving capabilities.

## Interfaces & Tooling

- **Electron Desktop GUI**: Neumorphic Soft UI interface built with Electron, featuring a warm linen cream (`#F3EFE9`) and vibrant orange (`#FA701F`) palette, Apple iPhone San Francisco typography stack, large high-contrast text, dual soft box-shadows, and complete decoupling from the C++ core via IPC backend bridge.
- **Dear ImGui Desktop GUI**: Lightweight C++ hardware-accelerated desktop window (Windows & Linux) with 8 forensic modules, non-blocking asynchronous progress bars, interactive tables, safety interlocks, and Neumorphic cream & orange styling.
- **Interactive Terminal**: Text-based interface featuring real-time path autocompletion powered by `fzf`.
- **Scriptable CLI**: Command-line arguments for automated pipelines (`--carve`, `--fs-recover`, `--erase`, `--sanitize-drive`, `--scan-image`, `--inspect-drive`, `--detect-drives`).
- **Decoupled Architecture**: Clean standalone C++ API headers located in `backend/include/forensivault/` (`file_eraser.hpp`, `drive_sanitizer.hpp`, `carver.hpp`, `fs_recovery.hpp`). The GUI frontends live completely independently in `electron/` and `gui/` and can be swapped or modified without touching the backend library.

---

## Launching & Building

### 1. Electron Desktop GUI (Cross-Platform)
```bash
# Launch directly from root:
npm start

# Or from electron directory:
cd electron
npm install   # If not already installed
npm start
```

### 2. C++ Backend & Dear ImGui GUI
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
