@echo off
REM ==============================================================================
REM ForensiVault(TM) Forensic Platform - Native Windows Build Script
REM Pure C++17 Cross-Platform Build System (MSVC / MinGW)
REM ==============================================================================

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set BUILD_DIR=%SCRIPT_DIR%build
set BUILD_TYPE=Release
set RUN_TESTS=0
set CLEAN_BUILD=0
set GENERATOR=

REM Parse arguments
:parse_args
if "%~1"=="" goto after_args
if /I "%~1"=="--help" goto show_help
if /I "%~1"=="-h" goto show_help
if /I "%~1"=="help" goto show_help
if /I "%~1"=="--release" (
    set BUILD_TYPE=Release
    shift
    goto parse_args
)
if /I "%~1"=="release" (
    set BUILD_TYPE=Release
    shift
    goto parse_args
)
if /I "%~1"=="--debug" (
    set BUILD_TYPE=Debug
    shift
    goto parse_args
)
if /I "%~1"=="debug" (
    set BUILD_TYPE=Debug
    shift
    goto parse_args
)
if /I "%~1"=="--test" (
    set RUN_TESTS=1
    shift
    goto parse_args
)
if /I "%~1"=="test" (
    set RUN_TESTS=1
    shift
    goto parse_args
)
if /I "%~1"=="--clean" (
    set CLEAN_BUILD=1
    shift
    goto parse_args
)
if /I "%~1"=="clean" (
    set CLEAN_BUILD=1
    shift
    goto parse_args
)
echo [ERROR] Unknown option: %~1
goto show_help

:show_help
echo ======================================================================
echo           FORENSIVAULT FORENSIC INVESTIGATION PLATFORM
echo                     Windows Build Automation
echo ======================================================================
echo Usage: build.bat [options]
echo.
echo Options:
echo   --release, release       Build in Release mode with full optimizations (default)
echo   --debug, debug           Build in Debug mode with debug symbols
echo   --test, test             Run automated forensic unit test suite after compilation
echo   --clean, clean           Clean existing build directory before compiling
echo   --help, -h, help         Display this help message
echo.
echo Examples:
echo   build.bat                Build Release binaries
echo   build.bat test           Build and run all 53 automated unit tests
echo   build.bat clean release  Clean build directory and build fresh Release binaries
echo ======================================================================
exit /b 0

:after_args
echo ======================================================================
echo           FORENSIVAULT FORENSIC INVESTIGATION PLATFORM
echo                     Windows C++17 Build System
echo ======================================================================
echo   Build Configuration: %BUILD_TYPE%
echo   Build Directory:     %BUILD_DIR%
echo ======================================================================

REM Clean build directory if requested
if "%CLEAN_BUILD%"=="1" (
    if exist "%BUILD_DIR%" (
        echo [*] Cleaning build directory: %BUILD_DIR%...
        rmdir /s /q "%BUILD_DIR%"
    )
)

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Check for CMake
where cmake >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] CMake is not found in PATH.
    echo Please install CMake from https://cmake.org/download/ and add it to your PATH.
    exit /b 1
)

REM Detect Visual Studio or MinGW
set COMPILER_FOUND=0

REM Check if cl.exe (MSVC) is already initialized in this environment
where cl >nul 2>nul
if %errorlevel% equ 0 (
    echo [*] Detected MSVC compiler in current environment.
    set COMPILER_FOUND=1
    set GENERATOR="Visual Studio 17 2022"
)

REM Check if vswhere can locate Visual Studio
if "%COMPILER_FOUND%"=="0" (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist "!VSWHERE!" (
        for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
            set "VS_DIR=%%i"
        )
        if defined VS_DIR (
            if exist "!VS_DIR!\VC\Auxiliary\Build\vcvars64.bat" (
                echo [*] Initializing MSVC x64 build environment from !VS_DIR!...
                call "!VS_DIR!\VC\Auxiliary\Build\vcvars64.bat"
                set COMPILER_FOUND=1
            )
        )
    )
)

REM Check if GCC / MinGW is available
if "%COMPILER_FOUND%"=="0" (
    where gcc >nul 2>nul
    if %errorlevel% equ 0 (
        echo [*] Detected MinGW GCC in PATH.
        set COMPILER_FOUND=1
        set GENERATOR="MinGW Makefiles"
    )
)

if "%COMPILER_FOUND%"=="0" (
    echo [WARNING] Neither initialized MSVC nor MinGW was automatically detected.
    echo Defaulting to CMake's system generator selection.
)

REM Configure CMake
echo [*] Configuring CMake in %BUILD_DIR%...
cd /d "%BUILD_DIR%"
set TEST_FLAG=OFF
if "%RUN_TESTS%"=="1" set TEST_FLAG=ON

if defined GENERATOR (
    cmake -G %GENERATOR% -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTING=%TEST_FLAG% "%SCRIPT_DIR%"
) else (
    cmake -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTING=%TEST_FLAG% "%SCRIPT_DIR%"
)
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed.
    exit /b 1
)

REM Compile
echo [*] Compiling ForensiVault targets (%BUILD_TYPE%)...
cmake --build "%BUILD_DIR%" --config %BUILD_TYPE%
if %errorlevel% neq 0 (
    echo [ERROR] Build compilation failed.
    exit /b 1
)

echo.
echo ======================================================================
echo [+] Windows build completed successfully!
echo     Binaries located at: %BUILD_DIR%\bin\ (or %BUILD_DIR%\bin\%BUILD_TYPE%\)
echo       - forensivault_cli.exe       (Interactive Forensic Terminal)
echo       - forensivault_tests.exe     (Automated Forensic Validation Suite)
echo       - forensic_inspect.exe       (Low-Level Geometry & Sector Inspector)
echo       - forensic_demo.exe          (12-Step Forensic Workflow Verification)
echo ======================================================================

REM Run test suite if requested
if "%RUN_TESTS%"=="1" (
    echo.
    echo [*] Executing ForensiVault automated test suite...
    if exist "%BUILD_DIR%\bin\%BUILD_TYPE%\forensivault_tests.exe" (
        "%BUILD_DIR%\bin\%BUILD_TYPE%\forensivault_tests.exe"
    ) else if exist "%BUILD_DIR%\bin\forensivault_tests.exe" (
        "%BUILD_DIR%\bin\forensivault_tests.exe"
    ) else (
        echo [ERROR] Could not find forensivault_tests.exe binary.
        exit /b 1
    )
)

cd /d "%SCRIPT_DIR%"
exit /b 0
