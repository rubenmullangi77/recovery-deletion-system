cmake_minimum_required(VERSION 3.20)
project(forensivault_gui CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# -----------------------------------------------------------------------------
# 1. GLFW Dependency (Cross-platform Windowing & Input)
# -----------------------------------------------------------------------------
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)

find_package(glfw3 3.3 QUIET)
if(NOT glfw3_FOUND AND NOT TARGET glfw)
    message(STATUS "[ForensiVault GUI] Fetching GLFW 3.3.9...")
    FetchContent_Declare(
        glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG 3.3.9
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(glfw)
endif()

if(TARGET glfw)
    set(GLFW_LIB glfw)
elseif(TARGET glfw3)
    set(GLFW_LIB glfw3)
else()
    set(GLFW_LIB ${GLFW_LIBRARIES})
endif()

# -----------------------------------------------------------------------------
# 2. Dear ImGui Dependency (Cross-platform Immediate Mode GUI)
# -----------------------------------------------------------------------------
message(STATUS "[ForensiVault GUI] Fetching Dear ImGui v1.91.8...")
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.91.8
    GIT_SHALLOW TRUE
)

FetchContent_GetProperties(imgui)
if(NOT imgui_POPULATED)
    FetchContent_Populate(imgui)

    add_library(imgui STATIC
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_demo.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
    )

    target_include_directories(imgui PUBLIC
        ${imgui_SOURCE_DIR}
        ${imgui_SOURCE_DIR}/backends
    )

    target_link_libraries(imgui PUBLIC ${GLFW_LIB})

    if(WIN32)
        target_link_libraries(imgui PUBLIC opengl32 gdi32 user32 shell32 comdlg32)
    else()
        find_package(OpenGL REQUIRED)
        target_link_libraries(imgui PUBLIC OpenGL::GL dl pthread)
    endif()
endif()

# -----------------------------------------------------------------------------
# 3. ForensiVault GUI Application
# -----------------------------------------------------------------------------
set(GUI_SOURCES
    src/main.cpp
    src/file_dialog.cpp
    src/ui_theme.cpp
    src/app_context.cpp
    src/view_dashboard.cpp
    src/view_operation_progress.cpp
    src/view_recovered_files.cpp
    src/view_settings_about.cpp
    src/view_file_eraser.cpp
    src/view_drive_sanitizer.cpp
    src/view_carver.cpp
    src/view_fs_recovery.cpp
    src/view_directory_recovery.cpp

    src/view_disk_inspect.cpp
    src/view_device_detector.cpp
    src/view_benchmark.cpp
    src/view_audit_log.cpp
    src/view_login.cpp
)

add_executable(forensivault_gui ${GUI_SOURCES})

target_include_directories(forensivault_gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

target_link_libraries(forensivault_gui PRIVATE
    forensivault_core
    imgui
    ${GLFW_LIB}
)

if(WIN32)
    target_link_libraries(forensivault_gui PRIVATE
        opengl32
        gdi32
        user32
        shell32
        comdlg32
        ole32
    )
else()
    find_package(OpenGL REQUIRED)
    target_link_libraries(forensivault_gui PRIVATE
        OpenGL::GL
        dl
        pthread
    )
endif()

set_target_properties(forensivault_gui PROPERTIES
    OUTPUT_NAME "forensivault-gui"
)
