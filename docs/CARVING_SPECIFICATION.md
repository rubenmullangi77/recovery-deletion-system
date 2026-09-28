# ForensiVault: Raw Data Carving & Confidence Scoring Specification

## 1. Carving Methodology Overview

ForensiVault's carving engine reconstructs files from unallocated clusters, memory images, damaged containers, or raw partition dumps without relying on file system metadata (such as FAT directories or NTFS Master File Tables). 

Carving proceeds in four deterministic stages:
1. **Signature Detection (Fast Window Scan)**: High-speed sliding window scan identifying header magic byte sequences.
2. **Structural Validation (Format Parsing)**: Deep semantic inspection of internal chunk headers, object tables, or segment markers.
3. **Boundary Calculation (EOCD / EOF / Length)**: Mathematical validation of exact file size to prevent cluster slack inflation or trailing file truncation.
4. **Explainable Confidence Scoring**: Algorithmic assessment (0–100%) providing defensible qualitative and quantitative ratings for forensic proceedings.

---

## 2. File Format Signatures & Boundary Validation

| Format | Extension | Header Signature (Hex) | Trailer / End Marker | Max Size Limit | Boundary Determination Technique |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PDF Document** | `.pdf` | `25 50 44 46` (`%PDF-`) | `25 25 45 4F 46` (`%%EOF`) | 100 MB | Locate terminal `%%EOF` marker, accounting for optional trailing whitespace / CR-LF. |
| **ZIP Archive** | `.zip` | `50 4B 03 04` | `50 4B 05 06` | 500 MB | Parse Central Directory records and confirm End of Central Directory (EOCD) offset equality. |
| **Word Document** | `.docx` | `50 4B 03 04` | `50 4B 05 06` | 200 MB | ZIP container with `[Content_Types].xml` or `word/` directory in central directory. |
| **Excel Spreadsheet** | `.xlsx` | `50 4B 03 04` | `50 4B 05 06` | 200 MB | ZIP container with `xl/` directory in central directory. |
| **PowerPoint** | `.pptx` | `50 4B 03 04` | `50 4B 05 06` | 200 MB | ZIP container with `ppt/` directory in central directory. |
| **Legacy Office (CFB)**| `.doc`, `.xls`, `.ppt` | `D0 CF 11 E0 A1 B1 1A E1` | N/A | 100 MB | Sector count $\times$ Sector size calculation via header shift parameters ($2^9$ or $2^{12}$). |
| **JPEG Image** | `.jpg`, `.jpeg` | `FF D8 FF` | `FF D9` | 50 MB | Walk variable-length marker segments (`APPn`, `DQT`, `SOF0`, `SOS`) to terminal `FF D9`. |
| **PNG Image** | `.png` | `89 50 4E 47 0D 0A 1A 0A` | `49 45 4E 44 AE 42 60 82` | 50 MB | Iterate sequential chunks until `IEND` chunk; calculate 32-bit CRC checksums for each chunk. |
| **GIF Image** | `.gif` | `47 49 46 38 37 61` / `39 61` | `3B` | 20 MB | Parse Logical Screen Descriptor, walk sub-blocks until trailer `0x3B`. |
| **MP3 Audio** | `.mp3` | `49 44 33` (`ID3`) / `FF FB` | Variable | 50 MB | ID3v2 tag syncsafe integer size calculation + MPEG frame synchronization. |
| **MP4 Video** | `.mp4` | `ftyp` at offset 4 | Variable | 2 GB | Sequential atom/box parsing (`ftyp`, `moov`, `mdat`) reading 32-bit/64-bit box sizes. |

---

## 3. Deep Structural Validation Specifications

### 3.1 ZIP & Office OpenXML (`.docx`, `.xlsx`, `.pptx`)
ZIP-based Office documents begin with a Local File Header signature:
```
Offset 0x00: 50 4B 03 04  (Local File Header Signature)
```
The exact boundary is resolved by scanning backward for the End of Central Directory (EOCD) signature:
```
Offset (EOCD): 50 4B 05 06  (4 bytes)
  +04: Disk number (2 bytes)
  +06: Disk where central directory starts (2 bytes)
  +08: Number of central directory records on this disk (2 bytes)
  +10: Total number of central directory records (2 bytes)
  +12: Size of central directory in bytes (4 bytes)
  +16: Offset of central directory relative to start (4 bytes)
  +20: Comment length in bytes (2 bytes)
```
**Boundary Verification Equation**:
$$\text{Calculated EOCD} = \text{Offset}_{\text{CentralDirectory}} + \text{Size}_{\text{CentralDirectory}}$$
If this equality holds, the file size is exactly:
$$\text{Carved Length} = \text{Offset}_{\text{EOCD}} + 22 + \text{CommentLength}$$
Slack space beyond this point is stripped, preventing corrupt or bloated recovered files.

### 3.2 Adobe Portable Document Format (`.pdf`)
* **Header**: Must start with `%PDF-` followed by the version specification (`1.0` through `2.0`).
* **Trailer**: The engine locates the trailer dictionary and the `startxref` line preceding `%%EOF`.
* **Validation Rule**:
  * Trailing comments or null padding after the final `%%EOF` marker are trimmed.
  * If the stream contains a subsequent file signature within the same block, carving truncates at the boundary of the next signature to prevent file bleeding.

### 3.3 Compound File Binary / OLE2 (`.doc`, `.xls`, `.ppt`)
Legacy Microsoft Office files use the Compound File Binary (CFB) format:
* **Header Signature**: `D0 CF 11 E0 A1 B1 1A E1`
* **Sector Shift Verification**: Byte offset 30 must be `0x09` (512-byte sector) or `0x0C` (4096-byte sector).
* **Directory Sector Count**: Validates that the root directory entry and mini-FAT allocation chains point to valid sectors within the calculated container bounds.

### 3.4 PNG Image Container
* **Magic Bytes**: `89 50 4E 47 0D 0A 1A 0A`
* **First Chunk**: Must be `IHDR` (`49 48 44 52`) with a payload length of 13 bytes.
* **Chunk Layout**:
  * `[4 bytes: Length N]`
  * `[4 bytes: Chunk Type]`
  * `[N bytes: Chunk Data]`
  * `[4 bytes: CRC32]`
* **Termination**: Ends with the `IEND` chunk (`49 45 4E 44`), followed by its fixed CRC `AE 42 60 82`. Carved size is the offset immediately after the `IEND` CRC.

---

## 4. Multi-Factor Explainable Confidence Scoring Model

Every carved file is evaluated against an objective, multi-factor scoring model ($S \in [0, 100]$):

### 4.1 Scoring Formula & Weights
The overall confidence score $S$ is composed of four additive components and a series of deduction penalties:

$$S = \max\Big(0, \, \min\big(100, \, S_{\text{magic}} + S_{\text{structure}} + S_{\text{boundary}} + S_{\text{entropy}} - \sum P_{\text{penalties}}\big)\Big)$$

1. **Header Magic Signature ($S_{\text{magic}}$)**: Maximum 30 points.
   * Full magic sequence match: +30
   * Partial or weak prefix: +15
2. **Structural Integrity ($S_{\text{structure}}$)**: Maximum 35 points.
   * Format-specific chunk/marker hierarchy valid: +20
   * Internal metadata / dictionary / table valid: +15
3. **Boundary & Footer Integrity ($S_{\text{boundary}}$)**: Maximum 20 points.
   * Exact validated EOF / EOCD / IEND found: +20
   * Estimated size without terminal marker: +5
4. **Internal Entropy & Consistency ($S_{\text{entropy}}$)**: Maximum 15 points.
   * Data entropy within expected format distribution (e.g., $7.2 - 7.9$ for compressed ZIP/JPEG; $4.5 - 6.5$ for PDF/text): +15
   * Uncharacteristic entropy (e.g., uniform zeroes or repetitive sequences): 0
5. **Deductions & Penalties ($P_{\text{penalties}}$)**:
   * Truncated payload before structural end: -30
   * CRC32 checksum mismatch in chunk: -25
   * Missing critical headers (e.g., JPEG missing `SOF0`): -20
   * Excess slack space or trailing noise: -10

### 4.2 Qualitative Confidence Classification

| Score Range | Classification | Forensic Admissibility & Usability |
| :---: | :---: | :--- |
| **85% – 100%** | **HIGH** | File structure, header, boundary, and internal checksums fully verified. Highly suitable for legal evidence. |
| **60% – 84%** | **MEDIUM** | Header and major structural elements intact. Minor non-critical discrepancies (e.g., missing optional metadata). File is viewable. |
| **30% – 59%** | **LOW** | Partial file recovered or truncated. May require manual hex editing or repair tools to render content. |
| **0% – 29%** | **UNCERTAIN** | Fragmentary data with matching magic bytes only. High likelihood of false positive or cluster slack artifact. |

### 4.3 Defensible Forensic Justification
The confidence score is reported alongside an **Explanation Vector** containing:
* List of validated checkpoints (e.g., `["MAGIC_MATCH", "EOCD_VERIFIED", "ZIP_ENTROPY_VALID", "CRC_CHECK_PASSED"]`).
* Explicit list of detected anomalies or missing markers.
* Hash integrity records (SHA-256 and MD5) of the extracted artifact.
