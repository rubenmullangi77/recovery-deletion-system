# Build Instructions

## Prerequisites

### Linux
- C++17 compiler (`g++` >= 9 or `clang++` >= 10)
- CMake >= 3.20
- Make or Ninja
- Optional: `fzf` for interactive terminal path autocompletion (`sudo apt install fzf`, `sudo dnf install fzf`, or `sudo pacman -S fzf`)

Ubuntu/Debian:
```bash
sudo apt update && sudo apt install -y build-essential cmake fzf
```

Fedora:
```bash
sudo dnf install -y gcc-c++ cmake make fzf
```

Arch Linux:
```bash
sudo pacman -S base-devel cmake fzf
```

### Windows
- Visual Studio 2019/2022 with "Desktop development with C++" workload OR MinGW-w64 (GCC >= 9)
- CMake >= 3.20
- Optional: `fzf` in PATH (`winget install fzf` or `choco install fzf`)

---

## Linux Build

### Using Build Script
```bash
./build.sh
```

Flags:
- `./build.sh --debug`: Compile with debug symbols.
- `./build.sh --clean`: Clean build directory before building.

### Manual CMake
```bash
cmake -B build -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build -j$(nproc)
```

Binaries are placed in `build/bin/`:
- `forensivault-gui`: Dear ImGui graphical desktop interface (Windows & Linux)
- `forensivault_cli`: Main interactive terminal application
- `forensic-inspect`: Low-level geometry and sector inspector
- `forensic-demo`: Verification workflow demonstration

### CMake Options:
- `-DBUILD_GUI=ON` (Default: ON): Build the standalone Dear ImGui graphical window application.
- `-DBUILD_GUI=OFF`: Build headless CLI and core backend library only (no GLFW or OpenGL requirements).
- `-DBUILD_TESTING=ON` (Default: OFF): Build automated unit test suite.

---

## Windows Build

### Using Build Script
From Command Prompt or PowerShell:
```cmd
build.bat
```

Flags:
- `build.bat debug`: Compile with debug symbols.
- `build.bat clean`: Clean build directory before building.

### Manual CMake (MSVC)
From "x64 Native Tools Command Prompt":
```cmd
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build --config Release
```

### Manual CMake (MinGW)
```cmd
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build -j%NUMBER_OF_PROCESSORS%
```

---

## Clang LSP (`clangd`) Setup

CMake generates `build/compile_commands.json` and creates a symlink at `compile_commands.json` in the project root. Clangd-enabled editors (VS Code, Neovim, CLion) detect it automatically.

---

## Running the Application

### 1. Electron Desktop GUI (Neumorphic Soft UI, iPhone Typography):
Requires Node.js (>= 18):
```bash
# From repository root:
npm start

# Or directly from the electron directory:
cd electron
npm install
npm start
```

### 2. Graphical Interface (Dear ImGui):
```bash
# Linux
./build/bin/forensivault-gui

# Windows
build\bin\forensivault-gui.exe
```

### Interactive Terminal Mode (CLI):
```bash
# Linux
./build/bin/forensivault_cli

# Linux with root privileges (required for raw block devices or protected files)
sudo ./build/bin/forensivault_cli

# Windows (Run Command Prompt as Administrator for physical drives)
build\bin\forensivault_cli.exe
```
