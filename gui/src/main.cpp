#include <imgui.h>
#include <backends/imgui_impl_glfw.h>
#include <backends/imgui_impl_opengl3.h>

#include <GLFW/glfw3.h>

#include "ui_theme.hpp"
#include "app_context.hpp"
#include "view_dashboard.hpp"
#include "view_operation_progress.hpp"
#include "view_recovered_files.hpp"
#include "view_settings_about.hpp"
#include "view_file_eraser.hpp"
#include "view_drive_sanitizer.hpp"
#include "view_carver.hpp"
#include "view_fs_recovery.hpp"
#include "view_directory_recovery.hpp"

#include "view_disk_inspect.hpp"
#include "view_device_detector.hpp"
#include "view_benchmark.hpp"
#include "view_audit_log.hpp"
#include "view_login.hpp"

#include <iostream>
#include <cstdio>
#include <iomanip>
#include <sstream>

static void glfwErrorCallback(int error, const char* description) {
    std::fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    glfwSetErrorCallback(glfwErrorCallback);
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return 1;
    }

    // Decide GL+GLSL versions
#if defined(__APPLE__)
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif

    // Create window with graphics context
    GLFWwindow* window = glfwCreateWindow(1420, 880,
        "ForensiVault — Forensic Data Recovery & Certified Sanitization Platform", nullptr, nullptr);
    if (!window) {
        glfwTerminate();
        return 1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable VSync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Query display DPI content scale (for 1080p, 1440p, 4K crisp rendering)
    float xscale = 1.0f, yscale = 1.0f;
    glfwGetWindowContentScale(window, &xscale, &yscale);
    float dpiScale = (xscale > 0.0f) ? xscale : 1.0f;

    // Load Crisp High-DPI Modern Fonts (Roboto-Medium + Monospace + System TrueType)
    forensivault::gui::UITheme::loadFonts(io, dpiScale);

    // Apply ForensiVault Neumorphic Cream & Orange theme
    forensivault::gui::UITheme::applyNeumorphicCreamTheme();
    if (dpiScale > 1.05f) {
        ImGui::GetStyle().ScaleAllSizes(dpiScale);
    }

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Initialize App State
    auto& appCtx = forensivault::gui::AppContext::getInstance();
    appCtx.initialize();

    // Instantiate View modules
    forensivault::gui::ViewDashboard viewDashboard;
    forensivault::gui::ViewOperationProgress viewOperationProgress;
    forensivault::gui::ViewRecoveredFiles viewRecoveredFiles;
    forensivault::gui::ViewSettingsAbout viewSettingsAbout;
    forensivault::gui::ViewFileEraser viewFileEraser;
    forensivault::gui::ViewDriveSanitizer viewDriveSanitizer;
    forensivault::gui::ViewCarver viewCarver;
    forensivault::gui::ViewFsRecovery viewFsRecovery;
    forensivault::gui::ViewDirectoryRecovery viewDirectoryRecovery;
    forensivault::gui::ViewDiskInspect viewDiskInspect;
    forensivault::gui::ViewDeviceDetector viewDeviceDetector;
    forensivault::gui::ViewAuditLog viewAuditLog;
    forensivault::gui::ViewLogin viewLogin;

    // Main loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        // Start Dear ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Fullscreen dockable background window
        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);

        ImGuiWindowFlags windowFlags = ImGuiWindowFlags_NoTitleBar |
                                       ImGuiWindowFlags_NoCollapse |
                                       ImGuiWindowFlags_NoResize |
                                       ImGuiWindowFlags_NoMove |
                                       ImGuiWindowFlags_NoBringToFrontOnFocus |
                                       ImGuiWindowFlags_NoNavFocus |
                                       ImGuiWindowFlags_NoScrollbar |
                                       ImGuiWindowFlags_NoScrollWithMouse;

        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.0f, 16.0f));
        ImGui::Begin("MainWindow", nullptr, windowFlags);
        ImGui::PopStyleVar(3);

        // -------------------------------------------------------------
        // 1. Top Header Navbar (Elevated Neumorphic Brand Container)
        // -------------------------------------------------------------
        ImGui::PushStyleColor(ImGuiCol_ChildBg, forensivault::gui::UITheme::COLOR_CREAM_CARD);
        ImGui::PushStyleColor(ImGuiCol_Border, forensivault::gui::UITheme::COLOR_CARD_BORDER);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18.0f, 11.0f));

        float headerBarHeight = std::max(56.0f, ImGui::GetFontSize() * 3.2f);
        ImGui::BeginChild("TopNavbar", ImVec2(0, headerBarHeight), true,
                          ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        // Measure Right Status & Actions Area upfront to guarantee zero collision
        float rightItemsWidth = 0.0f;
        std::string opText;
        if (appCtx.currentOperation.isRunning) {
            std::stringstream opSs;
            opSs << "[RUNNING " << std::fixed << std::setprecision(0)
                 << (appCtx.currentOperation.progress * 100.0f) << "%]";
            opText = opSs.str();
            rightItemsWidth += ImGui::CalcTextSize(opText.c_str()).x + 32.0f;
        }

        std::string platBadge = "[" + appCtx.platformName + "]";
        rightItemsWidth += ImGui::CalcTextSize(platBadge.c_str()).x + 32.0f;

        const char* elevBadge = appCtx.isElevated ? "[ELEVATED - ADMIN]" : "[STANDARD USER]";
        rightItemsWidth += ImGui::CalcTextSize(elevBadge).x + 32.0f;

        const char* elevateBtnText = "Unlock Root / Admin...";
        float elevateBtnWidth = 0.0f;
        if (!appCtx.isElevated) {
            elevateBtnWidth = ImGui::CalcTextSize(elevateBtnText).x + 28.0f;
            rightItemsWidth += elevateBtnWidth + 12.0f;
        }

        float availableW = ImGui::GetWindowWidth();
        float targetX = availableW - rightItemsWidth - 22.0f;

        // A. Left Brand Area
        forensivault::gui::UITheme::renderBadge("FV", forensivault::gui::UITheme::COLOR_ORANGE);
        ImGui::SameLine(0.0f, 12.0f);

        if (forensivault::gui::UITheme::fontHeader) ImGui::PushFont(forensivault::gui::UITheme::fontHeader);
        ImGui::TextColored(forensivault::gui::UITheme::COLOR_TEXT_PRIMARY, "FORENSIVAULT");
        if (forensivault::gui::UITheme::fontHeader) ImGui::PopFont();

        float leftX = ImGui::GetCursorPosX();
        float spaceRemaining = targetX - leftX - 16.0f;

        const char* fullTagline = "Forensic Recovery & Certified Sanitization Platform";
        float fullTaglineW = ImGui::CalcTextSize(fullTagline).x + 30.0f;

        if (spaceRemaining >= fullTaglineW) {
            ImGui::SameLine(0.0f, 12.0f);
            ImGui::TextColored(forensivault::gui::UITheme::COLOR_TEXT_MUTED, "•");
            ImGui::SameLine(0.0f, 12.0f);
            ImGui::TextColored(forensivault::gui::UITheme::COLOR_TEXT_SECONDARY, "%s", fullTagline);
        } else if (spaceRemaining >= 180.0f) {
            ImGui::SameLine(0.0f, 12.0f);
            ImGui::TextColored(forensivault::gui::UITheme::COLOR_TEXT_MUTED, "•");
            ImGui::SameLine(0.0f, 12.0f);
            ImGui::TextColored(forensivault::gui::UITheme::COLOR_TEXT_SECONDARY, "Forensic Workstation");
        }

        if (targetX > ImGui::GetCursorPosX() + 16.0f) {
            ImGui::SameLine(targetX);
        } else {
            ImGui::SameLine();
        }

        // Render Active operation indicator
        if (appCtx.currentOperation.isRunning) {
            forensivault::gui::UITheme::renderBadge(opText.c_str(), forensivault::gui::UITheme::COLOR_ORANGE);
            ImGui::SameLine(0.0f, 8.0f);
        }

        // Render Examiner badge & Lock Station button if authenticated
        if (appCtx.isAuthenticated) {
            std::string userBadge = "Examiner: " + appCtx.currentUsername;
            forensivault::gui::UITheme::renderBadge(userBadge.c_str(), forensivault::gui::UITheme::COLOR_GREEN);
            ImGui::SameLine(0.0f, 8.0f);

            if (forensivault::gui::UITheme::renderSecondaryButton("Lock Station", ImVec2(105.0f, 28.0f))) {
                appCtx.logout();
                viewLogin.resetFields();
            }
            ImGui::SameLine(0.0f, 8.0f);
        }

        // Render Platform badge
        forensivault::gui::UITheme::renderBadge(platBadge.c_str(), forensivault::gui::UITheme::COLOR_BLUE);
        ImGui::SameLine(0.0f, 8.0f);

        // Render Elevation badge
        if (appCtx.isElevated) {
            forensivault::gui::UITheme::renderBadge(elevBadge, forensivault::gui::UITheme::COLOR_GREEN);
        } else {
            forensivault::gui::UITheme::renderBadge(elevBadge, forensivault::gui::UITheme::COLOR_YELLOW);
            ImGui::SameLine(0.0f, 10.0f);

            // Styled Neumorphic "Unlock Root / Admin..." Button
            ImGui::PushStyleColor(ImGuiCol_Button, forensivault::gui::UITheme::COLOR_ORANGE_TINT);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, forensivault::gui::UITheme::COLOR_ORANGE);
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, forensivault::gui::UITheme::COLOR_ORANGE_ACTIVE);
            ImGui::PushStyleColor(ImGuiCol_Border, forensivault::gui::UITheme::COLOR_ORANGE);
            ImGui::PushStyleColor(ImGuiCol_Text, forensivault::gui::UITheme::COLOR_TEXT_PRIMARY);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 7.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 4.0f));

            if (forensivault::gui::UITheme::fontBold) ImGui::PushFont(forensivault::gui::UITheme::fontBold);
            if (ImGui::Button(elevateBtnText, ImVec2(elevateBtnWidth, 28.0f))) {
                appCtx.requestElevation();
            }
            if (forensivault::gui::UITheme::fontBold) ImGui::PopFont();

            ImGui::PopStyleVar(3);
            ImGui::PopStyleColor(5);
        }

        ImGui::EndChild();
        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);

        ImGui::Dummy(ImVec2(0, 10.0f));

        // -------------------------------------------------------------
        // 2. Notifications Row
        // -------------------------------------------------------------
        appCtx.renderNotifications();

        // -------------------------------------------------------------
        // Authentication Gatekeeper (Blocks all views until login)
        // -------------------------------------------------------------
        if (!appCtx.isAuthenticated) {
            viewLogin.render();
            ImGui::End();

            ImGui::Render();
            int display_w, display_h;
            glfwGetFramebufferSize(window, &display_w, &display_h);
            glViewport(0, 0, display_w, display_h);
            glClearColor(forensivault::gui::UITheme::COLOR_CREAM_BG.x,
                         forensivault::gui::UITheme::COLOR_CREAM_BG.y,
                         forensivault::gui::UITheme::COLOR_CREAM_BG.z, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            glfwSwapBuffers(window);
            continue;
        }

        // -------------------------------------------------------------
        // 3. Navigation Sidebar + Main Workspace View
        // -------------------------------------------------------------
        float sidebarWidth = 280.0f;
        float contentHeight = ImGui::GetContentRegionAvail().y - 32.0f;

        // Sidebar
        ImGui::PushStyleColor(ImGuiCol_ChildBg, forensivault::gui::UITheme::COLOR_CREAM_CARD);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 14.0f));
        ImGui::BeginChild("Sidebar", ImVec2(sidebarWidth, contentHeight), true);

        auto renderNavSectionTitle = [](const char* title, const ImVec4& color = forensivault::gui::UITheme::COLOR_TEXT_MUTED) {
            ImGui::Dummy(ImVec2(0, 6.0f));
            if (forensivault::gui::UITheme::fontSmall) ImGui::PushFont(forensivault::gui::UITheme::fontSmall);
            ImGui::TextColored(color, "%s", title);
            if (forensivault::gui::UITheme::fontSmall) ImGui::PopFont();
            ImGui::Dummy(ImVec2(0, 4.0f));
        };

        auto renderNavButton = [&](const char* label, forensivault::gui::ModuleTab tab, const ImVec4& activeCol = forensivault::gui::UITheme::COLOR_ORANGE) {
            bool isActive = (appCtx.activeTab == tab);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);

            if (isActive) {
                ImGui::PushStyleColor(ImGuiCol_Button, activeCol);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(std::min(1.0f, activeCol.x + 0.08f), std::min(1.0f, activeCol.y + 0.08f), std::min(1.0f, activeCol.z + 0.08f), 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(std::max(0.0f, activeCol.x - 0.08f), std::max(0.0f, activeCol.y - 0.08f), std::max(0.0f, activeCol.z - 0.08f), 1.0f));
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
            } else {
                ImGui::PushStyleColor(ImGuiCol_Button, forensivault::gui::UITheme::COLOR_CREAM_CARD);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, (activeCol.z > 0.5f) ? forensivault::gui::UITheme::COLOR_BLUE_TINT : forensivault::gui::UITheme::COLOR_ORANGE_TINT);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, forensivault::gui::UITheme::COLOR_CREAM_INSET);
                ImGui::PushStyleColor(ImGuiCol_Text, forensivault::gui::UITheme::COLOR_TEXT_PRIMARY);
            }

            if (forensivault::gui::UITheme::fontBold && isActive) {
                ImGui::PushFont(forensivault::gui::UITheme::fontBold);
            }

            if (ImGui::Button(label, ImVec2(-1, 38))) {
                appCtx.activeTab = tab;
            }

            if (forensivault::gui::UITheme::fontBold && isActive) {
                ImGui::PopFont();
            }

            ImGui::PopStyleColor(4);
            ImGui::PopStyleVar();
            ImGui::Dummy(ImVec2(0, 2.0f));
        };

        renderNavSectionTitle("WORKSTATION & MONITOR");
        renderNavButton("Dashboard", forensivault::gui::ModuleTab::DASHBOARD);
        renderNavButton("Scan / Operation Progress", forensivault::gui::ModuleTab::OPERATION_PROGRESS);

        renderNavSectionTitle("RECOVERY DOMAIN (PRESERVE)", forensivault::gui::UITheme::COLOR_BLUE);
        renderNavButton("Deleted File & Folder Recovery", forensivault::gui::ModuleTab::DIRECTORY_RECOVERY, forensivault::gui::UITheme::COLOR_BLUE);
        renderNavButton("Forensic Disk Image Recovery", forensivault::gui::ModuleTab::FS_RECOVERY, forensivault::gui::UITheme::COLOR_BLUE);
        renderNavButton("Raw File Carving", forensivault::gui::ModuleTab::FILE_CARVER, forensivault::gui::UITheme::COLOR_BLUE);
        renderNavButton("Recovered Files Browser", forensivault::gui::ModuleTab::RECOVERED_FILES, forensivault::gui::UITheme::COLOR_BLUE);
        renderNavButton("Evidence Geometry & Hashes", forensivault::gui::ModuleTab::DISK_INSPECT, forensivault::gui::UITheme::COLOR_BLUE);

        renderNavSectionTitle("DELETION DOMAIN (DESTROY)", forensivault::gui::UITheme::COLOR_ORANGE);
        renderNavButton("Secure Drive Eraser", forensivault::gui::ModuleTab::DRIVE_SANITIZER, forensivault::gui::UITheme::COLOR_ORANGE);
        renderNavButton("Secure File & Folder Eraser", forensivault::gui::ModuleTab::FILE_ERASER, forensivault::gui::UITheme::COLOR_ORANGE);
        renderNavButton("Storage Devices & Root Locks", forensivault::gui::ModuleTab::DEVICE_DETECTOR, forensivault::gui::UITheme::COLOR_ORANGE);

        renderNavSectionTitle("AUDIT & SETTINGS");
        renderNavButton("Operation History (Audit)", forensivault::gui::ModuleTab::AUDIT_LOG);
        renderNavButton("Settings & Compliance", forensivault::gui::ModuleTab::SETTINGS_ABOUT);

        ImGui::EndChild();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor();

        ImGui::SameLine();

        // Content Area - Single Unified Scrolling Surface
        ImGui::PushStyleColor(ImGuiCol_ChildBg, forensivault::gui::UITheme::COLOR_CREAM_CARD);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24.0f, 22.0f));
        ImGui::BeginChild("ContentArea", ImVec2(0, contentHeight), true);

        switch (appCtx.activeTab) {
            case forensivault::gui::ModuleTab::DASHBOARD:
                viewDashboard.render();
                break;
            case forensivault::gui::ModuleTab::DIRECTORY_RECOVERY:
                viewDirectoryRecovery.render();
                break;
            case forensivault::gui::ModuleTab::OPERATION_PROGRESS:
                viewOperationProgress.render();
                break;
            case forensivault::gui::ModuleTab::DRIVE_SANITIZER:
                viewDriveSanitizer.render();
                break;
            case forensivault::gui::ModuleTab::FILE_ERASER:
                viewFileEraser.render();
                break;
            case forensivault::gui::ModuleTab::FS_RECOVERY:
                viewFsRecovery.render();
                break;
            case forensivault::gui::ModuleTab::FILE_CARVER:
                viewCarver.render();
                break;
            case forensivault::gui::ModuleTab::RECOVERED_FILES:
                viewRecoveredFiles.render();
                break;
            case forensivault::gui::ModuleTab::DEVICE_DETECTOR:
                viewDeviceDetector.render();
                break;
            case forensivault::gui::ModuleTab::DISK_INSPECT:
                viewDiskInspect.render();
                break;
            case forensivault::gui::ModuleTab::AUDIT_LOG:
                viewAuditLog.render();
                break;
            case forensivault::gui::ModuleTab::SETTINGS_ABOUT:
            case forensivault::gui::ModuleTab::CRYPTO_BENCHMARK:
                viewSettingsAbout.render();
                break;
        }

        ImGui::EndChild();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor();

        // -------------------------------------------------------------
        // 4. Bottom Compliance Status Bar
        // -------------------------------------------------------------
        ImGui::Spacing();
        ImGui::TextColored(forensivault::gui::UITheme::COLOR_TEXT_MUTED,
            "Compliance: NIST SP 800-88 Rev 1 | DoD 5220.22-M | ISO/IEC 27040 | Tamper-Evident SHA-256 Audit Trail");

        ImGui::SameLine(ImGui::GetWindowWidth() - 150.0f);
        if (appCtx.currentOperation.isRunning) {
            ImGui::TextColored(forensivault::gui::UITheme::COLOR_ORANGE, "• Processing...");
        } else {
            ImGui::TextColored(forensivault::gui::UITheme::COLOR_GREEN, "• Status: Ready");
        }

        ImGui::End();

        // Rendering with active theme background clear color
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(forensivault::gui::UITheme::COLOR_CREAM_BG.x,
                     forensivault::gui::UITheme::COLOR_CREAM_BG.y,
                     forensivault::gui::UITheme::COLOR_CREAM_BG.z, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
