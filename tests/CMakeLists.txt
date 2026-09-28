# Tests CMake configuration
add_executable(forensivault_tests
    test_main.cpp
    test_crypto_hash.cpp
    test_disk_image_reader.cpp
    test_binary_utils.cpp
    test_file_carver.cpp
    test_confidence_scorer.cpp
    test_fragment_reconstructor.cpp
    test_fs_analyzer.cpp
    test_sanitization.cpp
    test_drive_sanitization.cpp
    test_audit_logging.cpp
    test_reporting.cpp
    test_directory_recovery.cpp
    test_user_auth_db.cpp
    test_safety_phase0.cpp
)


target_include_directories(forensivault_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/backend/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(forensivault_tests PRIVATE
    forensivault_core
)

target_compile_features(forensivault_tests PRIVATE cxx_std_17)
add_test(NAME forensivault_tests COMMAND forensivault_tests)
set_tests_properties(forensivault_tests PROPERTIES WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")
