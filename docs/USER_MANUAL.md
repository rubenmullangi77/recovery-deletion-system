# ForensiVault: User Manual & Operational Guide

## 1. System Requirements & Prerequisites

### 1.1 Operating System Compatibility
* **Windows**: Windows 10, Windows 11, Windows Server 2019/2022 (x86_64).
* **Linux**: Ubuntu 20.04+, Debian 11+, RHEL/Rocky Linux 8+, Fedora 38+ (x86_64).

### 1.2 Development & Runtime Dependencies
* **C++ Compiler**: Modern C++17 compliant compiler (MSVC v142+ on Windows, GCC 9+ or Clang 11+ on Linux).
* **CMake**: Version 3.16 or higher.
* **OpenSSL**: Version 1.1.1 or 3.0+ (used for SHA-256, MD5, and CSPRNG).
* **Node.js & npm**: Node.js v16.0+ (recommended v20 LTS or v24) and npm v8+.
* **Headless Browser (Optional for PDF generation)**: Google Chrome or Microsoft Edge installed in system PATH.

---

## 2. Building from Source

### 2.1 Windows Build Instructions (PowerShell / Visual Studio Developer Command Prompt)
```powershell
# Navigate to the repository root
cd d:\File_recovery_System\recovery-deletion-system

# Create build directory
mkdir build
cd build

# Configure CMake with Visual Studio generator
cmake .. -G "Visual Studio 17 2022" -A x64

# Compile Release binaries
cmake --build . --config Release

# Run automated forensic test suite
.\bin\forensivault_tests.exe
```

### 2.2 Linux Build Instructions
```bash
# Update and install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev nodejs npm

# Create build directory and compile
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Run test suite
./bin/forensivault_tests
```

---

## 3. Launching the Dear ImGui Desktop GUI

The native desktop interface runs via Dear ImGui and OpenGL with a Soft Neumorphic UI (Warm Linen Cream `#F4F0EA` background with Radiant Orange `#FA701F` interactive accents and crisp high-DPI modern typography).

### 3.1 Quick Start
From the project root directory:
```bash
# Linux
./build/bin/forensivault-gui

# Windows
build\bin\forensivault-gui.exe
```

---

## 4. Desktop GUI Modules: Step-by-Step Guide

### 4.1 Module 1: Certified Drive Sanitizer
1. **Device Detection**: Click **"Detect Drives"** to scan physical drives, external USBs, and virtual disk images.
2. **Drive Selection**: Select the target storage device from the list.
   * *Safety Interlock*: The system drive hosting the operating system (e.g., `\\.\PhysicalDrive0`) is highlighted with `[PROTECTED - LOCKED]` and cannot be selected for erasure.
3. **Algorithm Selection**:
   * **NIST SP 800-88 Rev 1 (Clear)**: Single-pass zero overwrite with sector verification.
   * **DoD 5220.22-M (3-Pass)**: Fixed pattern zero, fixed pattern one, and cryptographically random bytes.
   * **Cryptographic Random**: High-entropy PRNG overwrite.
4. **Execution**: Click **"Sanitize Drive"**. Type `DESTROY` into the safety modal to proceed.
5. **Sampling Verification**: The system automatically verifies lead (first 5%), median (middle 5%), and tail (last 5%) sectors, issuing a sanitization certificate upon 100% compliance.

---

### 4.2 Module 2: Secure File & Folder Eraser
1. **Select Target**: Enter or browse for the specific file or directory to erase.
2. **Preview Operation**: Click **"Preview Sanitization"**. The non-destructive preview reports:
   * Total files and subdirectories targeted.
   * Cumulative byte size.
   * Safety classification (confirming no system files or protected paths are impacted).
3. **Execution**: Click **"Erase File/Folder"**.
   * Multi-pass data block overwriting is applied with cache flushing (`FlushFileBuffers` / `fsync`).
   * Filenames are scrambled through three passes of randomized alphanumeric tokens before unlinking.
   * File length is truncated to zero bytes.

---

### 4.3 Module 3: Advanced File Carver
1. **Evidence Source**: Enter the path to any raw binary source, such as a disk image (`.dd`, `.img`), unallocated space file, or damaged compound file (`.pdf`, `.docx`, etc.).
2. **Carve Target**: Specify an output directory to receive extracted artifacts.
3. **Execution**: Click **"Carve Files"**.
4. **Results Table**: The carver renders all recovered artifacts displaying:
   * **Artifact ID & File Name**.
   * **File Type** (`PDF`, `DOCX`, `XLSX`, `PPTX`, `OLE_DOC`, `JPEG`, `PNG`, `GIF`, `MP3`, `MP4`).
   * **Offset (Hex & Decimal)** and **Exact Size**.
   * **Confidence Score (0–100%)** with Qualitative Classification badge (`HIGH`, `MEDIUM`, `LOW`, `UNCERTAIN`).
   * **SHA-256 Hash** for forensic custody tracking.

---

### 4.4 Module 4: Filesystem Structure Recovery
1. **Select Volume Image**: Choose a raw image of a FAT32, exFAT, or NTFS partition.
2. **Probe Filesystem**: Click **"Probe & Recover Filesystem"**.
3. **Metadata Analysis**: The engine parses volume boot sectors, cluster allocation tables, or NTFS Master File Table (`$MFT`) records to recover deleted directory trees and preserved filenames without relying solely on carving.

---

### 4.5 Module 5: Fragment Reconstructor
1. **Analyze Fragmented Streams**: When files are non-contiguous, click **"Analyze Fragments"**.
2. **Bifragment Gap Bridging**: The engine analyzes header/trailer compatibility, compression dictionary markers, and entropy shifts to bridge fragmented files across cluster discontinuities.

---

### 4.6 Module 6: Tamper-Evident Forensic Auditor
1. **Audit Verification**: Click **"Verify Audit Chain"** to recalculate the cryptographic SHA-256 hash chain from the Genesis block to the current event.
2. **Tamper Detection**: If any record in `audit_log.jsonl` was modified, deleted, or reordered, the audit viewer reports the exact line index and corrupt hash.
3. **Export**: Export audit logs in certified JSONL format for evidentiary filing.

---

### 4.7 Module 7: Court-Admissible Reporting Engine
1. **Case Details**: Enter Case ID (e.g., `CASE-2026-0927`), Investigator Name, and Organization.
2. **Generate Report**:
   * **JSON Report**: Comprehensive structured data for machine ingest.
   * **HTML Report**: Styled report featuring evidence summary, methodology, carved artifact tables, and chain of custody logs.
   * **Headless PDF**: Single-click compiled PDF generated via headless Chrome/Edge.

---

### 4.8 Module 8: System Protection Dashboard
* View active protection status in real time.
* Displays detected root physical storage devices, host OS mount points, protected directories, and system file interlocks (`pagefile.sys`, `/etc`, etc.).

---

## 5. Command-Line Interface (CLI) Reference

The `forensivault_cli` utility can be operated in interactive terminal mode or executed with direct command-line arguments in automated scripts.

### 5.1 Interactive Mode
Launch the interactive forensic terminal:
```bash
forensivault_cli
# or
forensivault_cli --interactive
```

### 5.2 Direct Command Reference

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `--help`, `-h` | None | Displays the forensic command reference. |
| `--version`, `-v` | None | Displays ForensiVault engine version and architecture. |
| `--benchmark-hash` | None | Executes SHA-256 and MD5 throughput benchmarks. |
| `--detect-drives` | None | Detects system storage devices, interfaces, and root locks. |
| `--inspect-drive` | `<image_path>` | Inspects drive image properties and partition geometry. |
| `--carve` | `<source_path> [output_dir]` | Carves files from raw image, dump, or document. |
| `--fs-recover` | `<image_path> [output_dir]` | Probes and recovers FAT32, exFAT, or NTFS structures. |
| `--reconstruct` | `<image_path>` | Analyzes disjoint and fragmented file sequences. |
| `--erase-preview` | `<target_path>` | Previews file/folder sanitization non-destructively. |
| `--erase` | `<target_path> [--dod\|--random] [--confirm]` | Securely erases target file or directory tree. |
| `--sanitize-drive`| `<image_path> [--nist\|--dod\|--random] [--confirm]` | Overwrites drive image with certified standards. |
| `--audit-export` | `<output_jsonl>` | Exports the chained forensic audit log. |

### 5.3 Scripting & Batch Automation Examples

#### Example 1: Automated Evidence Carving
```bash
# Carve files from an acquired raw image into the output folder
./forensivault_cli --carve /evidence/case001.raw /evidence/recovered_case001
```

#### Example 2: Certified Scripted File Erasure
```bash
# Non-destructive preview first
./forensivault_cli --erase-preview /confidential/financial_records

# Execute DoD 5220.22-M 3-pass erasure with confirmation
./forensivault_cli --erase /confidential/financial_records --dod --confirm
```

---

## 6. Permissions, Elevation & Safety Precautions

* **Physical Storage Access**: On Windows, enumerating and reading/writing physical drives (`\\.\PhysicalDriveX`) requires running the command prompt or desktop GUI application with **Administrator privileges** (Run as Administrator). On Linux, root privileges (`sudo`) or `CAP_SYS_RAWIO` capabilities are required.
* **Operating System Safety**: ForensiVault will strictly reject any request to wipe the drive containing the operating system, regardless of elevation.
* **Evidence Integrity**: Never run sanitization commands against evidence storage. Store master disk images with write-blockers or set filesystem permissions to Read-Only before performing recovery.

