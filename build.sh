#!/usr/bin/env bash
# ==============================================================================
# ForensiVault™ Forensic Platform - Native Linux Build Script
# Pure C++17 Cross-Platform Build System
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build}"
BUILD_TYPE="Release"
RUN_TESTS=false
CLEAN_BUILD=false

print_usage() {
    cat <<EOF
Usage: ./build.sh [options]

Options:
  --release       Build in Release mode with optimizations (default)
  --debug         Build in Debug mode with debug symbols (-g)
  --test          Run automated forensic unit test suite after compilation
  --clean         Remove existing build directory before compiling
  --help, -h      Show this help message

Examples:
  ./build.sh                  # Standard release build
  ./build.sh --test           # Build and run test suite
  ./build.sh --clean --debug  # Clean debug rebuild
EOF
}

# Parse command line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            BUILD_TYPE="Release"
            shift
            ;;
        --debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --test)
            RUN_TESTS=true
            shift
            ;;
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

echo "======================================================================"
echo "          FORENSIVAULT FORENSIC INVESTIGATION PLATFORM                "
echo "                     Linux C++17 Build System                         "
echo "======================================================================"
echo "  Build Configuration: ${BUILD_TYPE}"
echo "  Build Directory:     ${BUILD_DIR}"
echo "======================================================================"

# Clean build directory if requested
if [ "${CLEAN_BUILD}" = true ] && [ -d "${BUILD_DIR}" ]; then
    echo "[*] Cleaning build directory: ${BUILD_DIR}..."
    rm -rf "${BUILD_DIR}"
fi

# Ensure build directory exists
mkdir -p "${BUILD_DIR}"

# Check for required tools
command -v cmake >/dev/null 2>&1 || { echo "[ERROR] CMake is required but not installed. Aborting." >&2; exit 1; }
if ! command -v g++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1; then
    echo "[ERROR] A C++17 compiler (g++ or clang++) is required. Aborting." >&2
    exit 1
fi

# Configure CMake
echo "[*] Configuring CMake with compile_commands.json export..."
TEST_FLAG="OFF"
if [ "${RUN_TESTS}" = true ]; then
    TEST_FLAG="ON"
fi

cmake -B "${BUILD_DIR}" \
      -G "Unix Makefiles" \
      -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      -DBUILD_TESTING="${TEST_FLAG}" \
      "${SCRIPT_DIR}"

# Ensure compile_commands.json is symlinked in project root for Clang LSP (clangd)
if [ -f "${BUILD_DIR}/compile_commands.json" ]; then
    ln -sf "${BUILD_DIR}/compile_commands.json" "${SCRIPT_DIR}/compile_commands.json"
    echo "[+] Linked compile_commands.json -> ${SCRIPT_DIR}/compile_commands.json (Clang LSP Ready)"
fi

# Determine CPU core count for parallel build
NPROC=$(nproc 2>/dev/null || echo 4)
echo "[*] Compiling ForensiVault targets using ${NPROC} parallel jobs..."
cmake --build "${BUILD_DIR}" -- -j"${NPROC}"

echo ""
echo "======================================================================"
echo "[+] Build completed successfully!"
echo "    Binaries located at: ${BUILD_DIR}/bin/"
echo "      - forensivault_cli       (Interactive Forensic Terminal)"
echo "      - forensic-inspect       (Low-Level Geometry & Sector Inspector)"
echo "      - forensic-demo          (12-Step Forensic Workflow Verification)"
if [ "${RUN_TESTS}" = true ]; then
    echo "      - forensivault_tests     (Automated Forensic Validation Suite)"
fi
echo "======================================================================"

# Run test suite if requested
if [ "${RUN_TESTS}" = true ]; then
    echo ""
    echo "[*] Running ForensiVault automated test suite..."
    "${BUILD_DIR}/bin/forensivault_tests"
fi
