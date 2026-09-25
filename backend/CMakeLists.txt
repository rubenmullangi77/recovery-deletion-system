# Backend CMake configuration
add_library(forensivault_core STATIC
    src/common/crypto_hash.cpp
    src/api_bridge.cpp
    ${CMAKE_SOURCE_DIR}/src/core/disk_image_reader.cpp
    ${CMAKE_SOURCE_DIR}/src/core/partition_table.cpp
    ${CMAKE_SOURCE_DIR}/src/core/storage_device_detector.cpp
    ${CMAKE_SOURCE_DIR}/src/core/portable_device_detector.cpp
    ${CMAKE_SOURCE_DIR}/src/core/binary_utils.cpp
    ${CMAKE_SOURCE_DIR}/src/core/case_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/carving/file_signature.cpp
    ${CMAKE_SOURCE_DIR}/src/carving/format_validator.cpp
    ${CMAKE_SOURCE_DIR}/src/carving/signature_scanner.cpp
    ${CMAKE_SOURCE_DIR}/src/carving/file_carver.cpp
    ${CMAKE_SOURCE_DIR}/src/carving/confidence_scorer.cpp
    ${CMAKE_SOURCE_DIR}/src/carving/fragment_reconstructor.cpp
    ${CMAKE_SOURCE_DIR}/src/filesystem/fat32_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/filesystem/exfat_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/filesystem/ntfs_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/recovery/recovery_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/system_protection.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/secure_file_eraser.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/secure_folder_eraser.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/erase_operation.cpp
    ${CMAKE_SOURCE_DIR}/src/verification/erase_verification.cpp
    ${CMAKE_SOURCE_DIR}/src/logging/audit_logger.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/sanitization_strategy.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/drive_detector.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/sanitization_verifier.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/hdd_sanitizer.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/ssd_sanitizer.cpp
    ${CMAKE_SOURCE_DIR}/src/sanitization/image_sanitizer.cpp
    ${CMAKE_SOURCE_DIR}/src/reporting/forensic_report.cpp
    ${CMAKE_SOURCE_DIR}/src/reporting/report_generator.cpp
)

target_include_directories(forensivault_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(forensivault_core PUBLIC cxx_std_17)

# Link threading support
target_link_libraries(forensivault_core PUBLIC Threads::Threads)

# Windows socket / filesystem / portable device libraries if needed
if(WIN32)
    target_link_libraries(forensivault_core PUBLIC ws2_32 ole32 oleaut32 uuid portabledeviceguids)
endif()

# ForensiVault CLI executable
add_executable(forensivault_cli
    src/main.cpp
)

target_link_libraries(forensivault_cli PRIVATE
    forensivault_core
)

# Forensic inspect diagnostic tool
add_executable(forensic_inspect
    ${CMAKE_SOURCE_DIR}/tools/forensic_inspect.cpp
)

set_target_properties(forensic_inspect PROPERTIES OUTPUT_NAME "forensic-inspect")

target_link_libraries(forensic_inspect PRIVATE
    forensivault_core
)

# Forensic demonstration tool
add_executable(forensic_demo
    ${CMAKE_SOURCE_DIR}/tools/forensic_demo.cpp
)

set_target_properties(forensic_demo PROPERTIES OUTPUT_NAME "forensic-demo")

target_link_libraries(forensic_demo PRIVATE
    forensivault_core
)


