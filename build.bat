@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM ForensiVault Windows C++17 Build Script
REM ============================================================

set "SCRIPT_DIR=%~dp0."
set "BUILD_DIR=%~dp0build"
set "BUILD_TYPE=Release"
set "RUN_TESTS=0"
set "CLEAN_BUILD=0"
set "GENERATOR="

REM ============================================================
REM Parse arguments
REM ============================================================

:parse_args

if "%~1"=="" goto after_args

if /I "%~1"=="--help" goto show_help
if /I "%~1"=="-h" goto show_help
if /I "%~1"=="help" goto show_help

if /I "%~1"=="release" (
    set "BUILD_TYPE=Release"
    shift
    goto parse_args
)

if /I "%~1"=="--release" (
    set "BUILD_TYPE=Release"
    shift
    goto parse_args
)

if /I "%~1"=="debug" (
    set "BUILD_TYPE=Debug"
    shift
    goto parse_args
)

if /I "%~1"=="--debug" (
    set "BUILD_TYPE=Debug"
    shift
    goto parse_args
)

if /I "%~1"=="test" (
    set "RUN_TESTS=1"
    shift
    goto parse_args
)

if /I "%~1"=="--test" (
    set "RUN_TESTS=1"
    shift
    goto parse_args
)

if /I "%~1"=="clean" (
    set "CLEAN_BUILD=1"
    shift
    goto parse_args
)

if /I "%~1"=="--clean" (
    set "CLEAN_BUILD=1"
    shift
    goto parse_args
)

echo [ERROR] Unknown option: %~1
goto show_help


REM ============================================================
REM Help
REM ============================================================

:show_help

echo ============================================================
echo             FORENSIVAULT BUILD SYSTEM
echo ============================================================
echo Usage:
echo   build.bat
echo   build.bat clean release
echo   build.bat debug
echo   build.bat test
echo.
exit /b 0


REM ============================================================
REM Build information
REM ============================================================

:after_args

echo ============================================================
echo          FORENSIVAULT FORENSIC INVESTIGATION PLATFORM
echo                    Windows C++17 Build System
echo ============================================================
echo   Build Configuration: %BUILD_TYPE%
echo   Build Directory:     %BUILD_DIR%
echo ============================================================


REM ============================================================
REM Clean
REM ============================================================

if "%CLEAN_BUILD%"=="1" (
    if exist "%BUILD_DIR%" (
        echo [*] Cleaning build directory: %BUILD_DIR%...
        rmdir /s /q "%BUILD_DIR%"
    )
)


REM ============================================================
REM Create build directory
REM ============================================================

if not exist "%BUILD_DIR%" (
    mkdir "%BUILD_DIR%"
)


REM ============================================================
REM Check CMake
REM ============================================================

where.exe cmake >nul 2>nul

if errorlevel 1 (
    echo.
    echo [ERROR] CMake was not found in PATH.
    echo.
    echo Install CMake and restart PowerShell.
    exit /b 1
)


REM ============================================================
REM Detect compiler
REM ============================================================

set "COMPILER_FOUND=0"

where.exe cl >nul 2>nul

if not errorlevel 1 (
    echo [*] Detected MSVC compiler.
    set "COMPILER_FOUND=1"
)


REM ============================================================
REM Detect MinGW
REM ============================================================

if "%COMPILER_FOUND%"=="0" (

    where.exe gcc >nul 2>nul

    if not errorlevel 1 (

        where.exe g++ >nul 2>nul

        if not errorlevel 1 (
            echo [*] Detected MinGW GCC/G++.
            set "COMPILER_FOUND=1"
            set "GENERATOR=MinGW Makefiles"
        )
    )
)


REM ============================================================
REM No compiler
REM ============================================================

if "%COMPILER_FOUND%"=="0" (
    echo.
    echo [ERROR] No C/C++ compiler was detected.
    echo.
    echo Install Visual Studio C++ or MinGW-w64.
    echo.
    exit /b 1
)


REM ============================================================
REM Configure CMake
REM ============================================================

echo.
echo [*] Configuring CMake in %BUILD_DIR%...

if defined GENERATOR (

    echo [*] Using CMake generator: %GENERATOR%

    cmake -S "%SCRIPT_DIR%" -B "%BUILD_DIR%" -G "%GENERATOR%" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTING=%RUN_TESTS%

) else (

    echo [*] Using CMake default generator.

    cmake -S "%SCRIPT_DIR%" -B "%BUILD_DIR%" -DCMAKE_BUILD_TYPE=%BUILD_TYPE% -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_TESTING=%RUN_TESTS%

)


if errorlevel 1 (
    echo.
    echo [ERROR] CMake configuration failed.
    exit /b 1
)


REM ============================================================
REM Build
REM ============================================================

echo.
echo [*] Compiling ForensiVault targets (%BUILD_TYPE%)...

cmake --build "%BUILD_DIR%" --config %BUILD_TYPE%


if errorlevel 1 (
    echo.
    echo [ERROR] Build compilation failed.
    exit /b 1
)


REM ============================================================
REM Success
REM ============================================================

echo.
echo ============================================================
echo [+] Windows build completed successfully!
echo.
echo Build directory:
echo %BUILD_DIR%
echo.
echo Binaries located at %BUILD_DIR%\bin:
echo   - forensivault-gui.exe       (Dear ImGui Desktop Graphical Interface)
echo   - forensivault_cli.exe       (Interactive Forensic Terminal)
echo   - forensic-inspect.exe       (Low-Level Geometry and Sector Inspector)
echo   - forensic-demo.exe          (12-Step Forensic Workflow Verification)
echo ============================================================
echo.


REM ============================================================
REM Run tests
REM ============================================================

if "%RUN_TESTS%"=="1" (

    echo [*] Running automated tests...

    if exist "%BUILD_DIR%\bin\%BUILD_TYPE%\forensivault_tests.exe" (

        "%BUILD_DIR%\bin\%BUILD_TYPE%\forensivault_tests.exe"

    ) else if exist "%BUILD_DIR%\bin\forensivault_tests.exe" (

        "%BUILD_DIR%\bin\forensivault_tests.exe"

    ) else (

        echo [WARNING] forensivault_tests.exe was not found.

    )
)


exit /b 0