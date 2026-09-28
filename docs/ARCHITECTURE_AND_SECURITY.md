# ForensiVault: Architecture & Security Technical Specification

## 1. Executive Architecture Overview

**ForensiVault** is an enterprise-grade forensic data recovery and certified sanitization platform designed to bridge the operational gap between digital investigations and secure data destruction. The platform adheres strictly to national and international standards, including **NIST SP 800-88 Rev 1 (Guidelines for Media Sanitization)** and **DoD 5220.22-M (National Industrial Security Program Operating Manual)**.

The software architecture is decoupled into three distinct tiers:
1. **High-Performance C++17 Core Engine (`forensivault_core`)**: Headless, zero-overhead static/shared library encapsulating all low-level raw I/O, binary signature detection, structural parsing, cryptographic hashing, and sanitization routines.
2. **Unified Command-Line & Forensic Terminal (`forensivault_cli`)**: High-efficiency console interface providing scriptable automation, live sector progress monitoring, and interactive terminal workflows.
3. **Hardware-Accelerated Desktop Application (`forensivault-gui`)**: Native C++ desktop interface constructed using Dear ImGui and GLFW/OpenGL, styled with high-DPI modern typography, tactile Neumorphic cream and orange controls, and asynchronous background worker threads.

```
+---------------------------------------------------------------------------------+
|                               Presentation Tier                                 |
|  +-------------------------------------+   +---------------------------------+  |
|  |  Native Dear ImGui GUI (C++/OpenGL) |   |  Terminal / Scripting Interface |  |
|  |  (Cream #F4F0EA & Orange #FA701F)   |   |  (Interactive CLI Engine)       |  |
|  +------------------+------------------+   +----------------+----------------+  |
+---------------------|---------------------------------------|-------------------+
                      | Direct C++ API Linkage                | Direct Linkage
                      v                                       v
+---------------------------------------------------------------------------------+
|                       ForensiVault C++ High-Level API                           |
|                  (drives, carving, sanitization, reports)                       |
+---------------------------------------------------------------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------------+
|                     ForensiVault C++17 Core Engine                              |
|  +---------------------+  +---------------------+  +-------------------------+  |
|  | Drive Sanitizer     |  | File/Folder Eraser  |  | Advanced File Carver    |  |
|  | - NIST SP 800-88 R1 |  | - Multi-pass wipe   |  | - Raw stream carving    |  |
|  | - DoD 5220.22-M     |  | - 3x Name scramble  |  | - EOCD / Zip validation |  |
|  | - Cryptographic PRNG|  | - Flush & truncate  |  | - PDF, DOCX, OLE, JPEG  |  |
|  +---------------------+  +---------------------+  +-------------------------+  |
|  +---------------------+  +---------------------+  +-------------------------+  |
|  | System Protection   |  | Cryptographic Audit |  | Forensic Reporting      |  |
|  | - Root drive lock   |  | - SHA-256 Chaining  |  | - JSON / HTML Reports   |  |
|  | - Protected paths   |  | - Genesis Block     |  | - Headless Chromium PDF |  |
|  +---------------------+  +---------------------+  +-------------------------+  |
+---------------------------------------------------------------------------------+
```

---

## 2. Core Module 1: Secure Drive Eraser

The Drive Eraser module performs physical and virtual storage sanitization across HDDs, SSDs, USB flash drives, SD cards, and raw disk images (`.dd`, `.raw`, `.img`).

### 2.1 Sanitization Algorithms
* **NIST SP 800-88 Rev 1 Clear (Single-Pass Zero Fill)**:
  * Overwrites 100% of addressable logical sectors with fixed `0x00` bytes.
  * Verified for magnetic HDDs and virtual disk images to guarantee non-recoverability through standard laboratory read techniques.
* **DoD 5220.22-M 3-Pass Overwrite**:
  * Pass 1: Write fixed zero pattern `0x00` across all sectors.
  * Pass 2: Write complementary one pattern `0xFF` across all sectors.
  * Pass 3: Write cryptographically generated pseudorandom bytes (via OpenSSL/OS CSPRNG).
* **Cryptographic Random Overwrite**:
  * Single or multi-pass fill of cryptographically secure pseudorandom numbers generated via high-entropy hardware random pools (`CryptGenRandom` / `BCryptGenRandom` on Windows, `/dev/urandom` on POSIX).

### 2.2 SSD / NVMe NAND Limitations & Transparency
* Flash-based media (SSDs, NVMe drives, USB thumb drives) utilize Wear Leveling, Over-provisioning, and Garbage Collection controllers that map logical block addresses (LBAs) dynamically.
* ForensiVault transparently identifies solid-state media and warns the operator:
  > *LBA overwriting on solid-state media may leave remnant data in unallocated flash blocks or retired spare sectors. Hardware-level ATA Enhanced Secure Erase or NVMe Format (Cryptographic Erase) is recommended for physical SSD sanitization.*

### 2.3 Post-Erasure Verification Sampling
* After sanitization completes, the verification engine samples logical sectors across three distinct bands:
  1. **Lead Sectors**: First 5% of storage sectors (verifying partition table, MBR, and volume boot records are completely eradicated).
  2. **Median Sectors**: Middle 5% of storage sectors (verifying user data payload eradication).
  3. **Tail Sectors**: Final 5% of storage sectors (verifying backup partition tables, secondary GPT headers, and volume slack eradication).
* Verification fails immediately if any non-erased residual pattern is detected in the sampled sectors.

---

## 3. Core Module 2: Secure File & Folder Eraser

The File and Folder Eraser module targets individual files and complex directory trees without requiring whole-drive sanitization.

### 3.1 Data Stream Sanitization
1. **Stream Overwrite**: The target file data fork is opened with direct unbuffered I/O and overwritten in block increments matching cluster boundaries (4,096 bytes) using the designated sanitization algorithm (NIST Clear, DoD 3-Pass, or Random).
2. **Buffer Synchronization (`flushToDisk`)**:
   * Windows: Calls `FlushFileBuffers(hFile)` to force dirty OS kernel cache lines and hardware write caches directly to non-volatile media.
   * POSIX: Calls `fsync(fd)` / `fdatasync(fd)`.
3. **File Truncation**: File length is truncated to zero bytes via `SetEndOfFile` / `ftruncate`.

### 3.2 Metadata Cleansing (Directory Sanitization)
Simply deleting an unlinked file leaves timestamps, filenames, and file pointers intact in file system metadata (e.g., NTFS `$MFT` records, FAT directory entries, EXT4 inodes). ForensiVault executes a triple-pass metadata scramble:
1. **Pass 1**: Target file is renamed to a 16-character pseudo-random alphanumeric string (e.g., `_tmp_7A8f9K21mQ0x.tmp`).
2. **Pass 2**: Renamed again to a second distinct random string (e.g., `_tmp_000000000000.tmp`).
3. **Pass 3**: Renamed to a 1-character placeholder (e.g., `_`) before unlinking via `std::filesystem::remove`.
4. **Timestamp Manipulation**: File timestamps (creation, last access, last modified) are set to epoch zero before deletion.

### 3.3 Non-Destructive Safety Preview
Prior to invoking destructive eradication, ForensiVault calculates:
* Total files and nested subdirectories targeted.
* Cumulative byte volume to be sanitized.
* System protection classification (ensuring no critical system files are contained in the batch).
* Confirmation token generation (`DESTROY`).

---

## 4. Core Module 3: Advanced File Carving & Recovery

The File Carving engine bypasses corrupt, formatted, or missing file system tables by scanning raw binary byte streams directly for file header signatures, validating internal structure, and calculating mathematically precise file boundaries.

### 4.1 Raw Binary Source Agnostic
The engine accepts:
* Raw physical/virtual disk images (`.dd`, `.img`, `.raw`).
* Single files, unallocated space dumps, memory dumps, or damaged documents (`.pdf`, `.docx`, `.bin`).
* Segmented cluster captures.

### 4.2 Mathematical Boundary & Container Validation
* **ZIP / Office OpenXML (`.docx`, `.xlsx`, `.pptx`)**:
  * Carves from local file header `PK\x03\x04`.
  * Scans backward from buffer bounds for End of Central Directory (`PK\x05\x06`).
  * Mathematically validates that:
    $$\text{Offset}_{\text{CentralDirectory}} + \text{Size}_{\text{CentralDirectory}} == \text{Offset}_{\text{EOCD}}$$
  * Rejects false positives that contain corrupt directory records or arbitrary slack bytes.
* **Adobe PDF (`.pdf`)**:
  * Validates `%PDF-1.x` magic header.
  * Tracks internal object tables (`xref` / `/XRef` and `startxref`).
  * Locates the terminal `%%EOF` marker, ensuring no extraneous clusters or adjacent files are included in the recovered artifact.
* **Compound File Binary / Legacy Office (`.doc`, `.xls`, `.ppt`)**:
  * Verifies OLE CFB magic header `D0 CF 11 E0 A1 B1 1A E1`.
  * Validates sector shift parameters ($2^9 = 512$ bytes or $2^{12} = 4096$ bytes) and ensures sector count corresponds to valid FAT allocations.
* **Images (`.jpeg`, `.png`, `.gif`)**:
  * **JPEG**: Validates Start of Image `FF D8 FF`, walks variable-length marker segments (`APP0`, `APP1`, `DQT`, `SOF0`, `SOS`), and terminates precisely at End of Image `FF D9`.
  * **PNG**: Validates 8-byte header `89 50 4E 47 0D 0A 1A 0A`, parses chunks (`IHDR`, `PLTE`, `IDAT`, `IEND`), and computes 32-bit CRC checksums across each chunk's payload.
  * **GIF**: Validates `GIF87a` / `GIF89a`, parses Logical Screen Descriptor, walks image and extension blocks, and halts at trailer `0x3B`.

---

## 5. Forensic Safety Interlocks & Chain of Custody

### 5.1 Operating System Protection Guard (`SystemProtectionGuard`)
To protect against catastrophic accidental sanitization of the running host environment, ForensiVault enforces kernel-level safety checks:
1. **OS Root Physical Drive Lock**:
   * Windows: Queries system disk number via IOCTL or path resolution. `\\.\PhysicalDrive0` hosting `C:\` is permanently flagged with `is_system = true` and `safe_to_wipe = false`.
   * POSIX: Root mount device `/` and `/boot` devices are permanently protected.
2. **Protected File Paths**:
   * Sanitization immediately aborts if any target path resolves to or resides within:
     * `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\Users\<user>\AppData`
     * Virtual memory files: `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`
     * Linux: `/etc`, `/usr`, `/bin`, `/sbin`, `/boot`, `/lib`, `/sys`, `/proc`

### 5.2 Evidence Immutability Guarantee
When analyzing evidence or executing file carving:
* Evidence files are opened exclusively in read-only mode (`std::ios::in | std::ios::binary` on C++, `FILE_SHARE_READ` on Win32).
* No write handles or temporary lock files are ever created inside evidence directories.
* Cryptographic hashes (SHA-256 and MD5) are generated at ingest to verify evidence integrity throughout processing.

### 5.3 Cryptographic SHA-256 Chained Audit Trail
Every action (drive inspection, file carve, preview, or sanitization) is written to a tamper-evident audit journal (`audit_log.jsonl`):
* **Genesis Block**: Initiates with a fixed cryptographic root hash (`0000000000000000000000000000000000000000000000000000000000000000`).
* **Hash Chaining**: Each audit entry calculates its SHA-256 hash across:
  $$\text{Hash}_n = \text{SHA256}(\text{Index}_n \,\|\, \text{Timestamp}_n \,\|\, \text{EventType}_n \,\|\, \text{Details}_n \,\|\, \text{Hash}_{n-1})$$
* **Tamper Detection**: If any log entry is modified, deleted, or inserted out of order, verification fails immediately, indicating evidence tampering.

---

## 6. Forensic Reporting Engine

ForensiVault generates court-admissible forensic documentation:
* **Structured JSON Report**: Machine-readable export with case metadata, operator ID, evidence hashes, recovered artifacts table with confidence scores, and audit log chain.
* **Forensic HTML Report**: Human-readable report styled for legal presentation, including methodology, signature tables, and verification certificates.
* **Certified Headless PDF**: Automatically rendered from HTML using headless Chrome/Edge (`--headless --print-to-pdf`), embedding tamper-resistant pagination and digital signatures.
