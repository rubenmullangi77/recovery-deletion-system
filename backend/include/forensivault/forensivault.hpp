#pragma once

/**
 * @file forensivault.hpp
 * @brief Main public C++ SDK header for ForensiVault Forensic Platform.
 * 
 * Includes clean, cross-platform interfaces for:
 *   - Secure File and Folder Sanitization (NIST SP 800-88 Rev 1, DoD 5220.22-M)
 *   - Certified Drive and Image Sanitization
 *   - Forensic Deep File Carving (Read-Only)
 *   - Filesystem Structure Recovery (FAT32, exFAT, NTFS)
 *   - Hardware and Device Safety Protections
 */

#include "forensivault/common/types.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include "forensivault/common/logger.hpp"
#include "forensivault/core/platform.hpp"
#include "forensivault/file_eraser.hpp"
#include "forensivault/drive_sanitizer.hpp"
#include "forensivault/carver.hpp"
#include "forensivault/fs_recovery.hpp"
