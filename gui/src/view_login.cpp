#include "view_login.hpp"
#include "ui_theme.hpp"
#include "app_context.hpp"
#include "core/user_auth_db.hpp"

#include <imgui.h>
#include <cstring>
#include <vector>
#include <algorithm>

namespace forensivault::gui {

namespace {

const std::vector<std::string> ROLES = {
    "Lead Forensic Examiner",
    "Digital Forensics Lab Director",
    "Forensic Investigator",
    "Chain-of-Custody Auditor"
};

} // anonymous namespace

ViewLogin::ViewLogin() {
    resetFields();
}

void ViewLogin::resetFields() {
    std::memset(usernameBuffer_, 0, sizeof(usernameBuffer_));
    std::memset(passwordBuffer_, 0, sizeof(passwordBuffer_));
    std::memset(confirmPasswordBuffer_, 0, sizeof(confirmPasswordBuffer_));
    errorMessage_.clear();
    statusMessage_.clear();
    lockoutSecondsRemaining_ = 0;
    selectedRoleIndex_ = 0;

    auto& authDb = core::UserAuthDB::getInstance();
    isEnrollmentMode_ = !authDb.hasUsers();
}

void ViewLogin::handleLogin() {
    errorMessage_.clear();
    statusMessage_.clear();

    std::string user(usernameBuffer_);
    std::string pass(passwordBuffer_);

    if (user.empty()) {
        errorMessage_ = "Examiner username is required.";
        return;
    }
    if (pass.empty()) {
        errorMessage_ = "Password is required.";
        return;
    }

    auto& authDb = core::UserAuthDB::getInstance();
    auto res = authDb.authenticate(user, pass);

    if (res.status == core::AuthStatus::SUCCESS) {
        // Clear sensitive password buffers from memory
        std::memset(passwordBuffer_, 0, sizeof(passwordBuffer_));
        std::memset(confirmPasswordBuffer_, 0, sizeof(confirmPasswordBuffer_));
        AppContext::getInstance().login(res.user.username, res.user.role);
    } else if (res.status == core::AuthStatus::ACCOUNT_LOCKED) {
        lockoutSecondsRemaining_ = res.lockRemainingSeconds;
        errorMessage_ = res.message;
    } else {
        errorMessage_ = res.message;
    }
}

void ViewLogin::handleEnrollment() {
    errorMessage_.clear();
    statusMessage_.clear();

    std::string user(usernameBuffer_);
    std::string pass(passwordBuffer_);
    std::string confirm(confirmPasswordBuffer_);
    std::string role = (selectedRoleIndex_ >= 0 && selectedRoleIndex_ < static_cast<int>(ROLES.size()))
                           ? ROLES[selectedRoleIndex_]
                           : "Forensic Examiner";

    if (user.empty()) {
        errorMessage_ = "Examiner username is required.";
        return;
    }
    if (pass.empty()) {
        errorMessage_ = "Password is required.";
        return;
    }
    if (pass != confirm) {
        errorMessage_ = "Passwords do not match. Please verify both fields.";
        return;
    }

    std::string complexityErr;
    if (!core::UserAuthDB::validatePasswordComplexity(pass, &complexityErr)) {
        errorMessage_ = complexityErr;
        return;
    }

    auto& authDb = core::UserAuthDB::getInstance();
    std::string regErr;
    if (authDb.registerUser(user, pass, role, &regErr)) {
        // Clear password buffers immediately
        std::memset(passwordBuffer_, 0, sizeof(passwordBuffer_));
        std::memset(confirmPasswordBuffer_, 0, sizeof(confirmPasswordBuffer_));
        AppContext::getInstance().login(user, role);
    } else {
        errorMessage_ = regErr.empty() ? "User registration failed." : regErr;
    }
}

void ViewLogin::render() {
    auto& authDb = core::UserAuthDB::getInstance();
    if (!authDb.hasUsers()) {
        isEnrollmentMode_ = true;
    }

    ImVec2 viewportSize = ImGui::GetWindowSize();
    float cardWidth = isEnrollmentMode_ ? 540.0f : 480.0f;
    float cardHeight = isEnrollmentMode_ ? 560.0f : 430.0f;

    float posX = std::max(20.0f, (viewportSize.x - cardWidth) * 0.5f);
    float posY = std::max(20.0f, (viewportSize.y - cardHeight) * 0.42f);

    ImGui::SetCursorPos(ImVec2(posX, posY));

    ImGui::PushStyleColor(ImGuiCol_ChildBg, UITheme::COLOR_CREAM_CARD);
    ImGui::PushStyleColor(ImGuiCol_Border, UITheme::COLOR_CARD_BORDER);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.5f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(32.0f, 28.0f));

    ImGui::BeginChild("LoginCard", ImVec2(cardWidth, cardHeight), true,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    // Header Title & Brand Icon
    if (UITheme::fontBold) ImGui::PushFont(UITheme::fontBold);
    if (isEnrollmentMode_) {
        ImGui::TextColored(UITheme::COLOR_ORANGE, "FORENSIVAULT — INITIAL EXAMINER SETUP");
    } else {
        ImGui::TextColored(UITheme::COLOR_ORANGE, "FORENSIVAULT — EXAMINER AUTHENTICATION");
    }
    if (UITheme::fontBold) ImGui::PopFont();

    ImGui::Spacing();
    if (isEnrollmentMode_) {
        UITheme::renderWrappedText(
            "No forensic examiner accounts exist in the security vault. "
            "Please initialize the primary Administrator / Examiner account to continue.",
            UITheme::COLOR_TEXT_SECONDARY);
    } else {
        UITheme::renderWrappedText(
            "Workstation locked for forensic evidence integrity. "
            "Please enter your examiner credentials to access the recovery and sanitization suite.",
            UITheme::COLOR_TEXT_SECONDARY);
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Error / Lockout Banner
    if (!errorMessage_.empty()) {
        UITheme::renderDangerBanner(errorMessage_.c_str());
        ImGui::Spacing();
    }

    // Input: Examiner Username
    ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Examiner Username:");
    ImGui::PushItemWidth(-1);
    bool enterUser = ImGui::InputText("##LoginUser", usernameBuffer_, sizeof(usernameBuffer_),
                                      ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::PopItemWidth();

    ImGui::Spacing();

    // Input: Role (in Enrollment mode)
    if (isEnrollmentMode_) {
        ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Forensic Role & Title:");
        ImGui::PushItemWidth(-1);
        const char* currentRole = ROLES[selectedRoleIndex_].c_str();
        if (ImGui::BeginCombo("##RoleCombo", currentRole)) {
            for (int i = 0; i < static_cast<int>(ROLES.size()); ++i) {
                bool isSelected = (selectedRoleIndex_ == i);
                if (ImGui::Selectable(ROLES[i].c_str(), isSelected)) {
                    selectedRoleIndex_ = i;
                }
                if (isSelected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
        ImGui::PopItemWidth();
        ImGui::Spacing();
    }

    // Input: Password
    ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, isEnrollmentMode_ ? "Master Password (min 8 chars):" : "Password:");
    ImGui::PushItemWidth(-1);
    bool enterPass = ImGui::InputText("##LoginPass", passwordBuffer_, sizeof(passwordBuffer_),
                                      ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::PopItemWidth();

    // Input: Confirm Password (in Enrollment mode)
    bool enterConfirm = false;
    if (isEnrollmentMode_) {
        ImGui::Spacing();
        ImGui::TextColored(UITheme::COLOR_TEXT_PRIMARY, "Confirm Master Password:");
        ImGui::PushItemWidth(-1);
        enterConfirm = ImGui::InputText("##LoginConfirm", confirmPasswordBuffer_, sizeof(confirmPasswordBuffer_),
                                        ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopItemWidth();

        // Password requirements visual indicators
        ImGui::Spacing();
        std::string curPass(passwordBuffer_);
        std::string curConf(confirmPasswordBuffer_);
        bool hasLen = curPass.length() >= 8;
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        for (char c : curPass) {
            if (std::isupper(static_cast<unsigned char>(c))) hasUpper = true;
            else if (std::islower(static_cast<unsigned char>(c))) hasLower = true;
            else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit = true;
            else hasSpecial = true;
        }
        bool match = !curPass.empty() && (curPass == curConf);

        auto renderCheck = [](const char* label, bool ok) {
            ImVec4 col = ok ? UITheme::COLOR_GREEN : UITheme::COLOR_TEXT_MUTED;
            const char* sym = ok ? "[OK] " : "[  ] ";
            ImGui::TextColored(col, "%s%s", sym, label);
        };

        ImGui::Columns(2, "PassCheckCols", false);
        renderCheck("8+ Characters", hasLen);
        renderCheck("Uppercase (A-Z)", hasUpper);
        renderCheck("Lowercase (a-z)", hasLower);
        ImGui::NextColumn();
        renderCheck("Digit (0-9)", hasDigit);
        renderCheck("Special (!@#$)", hasSpecial);
        renderCheck("Passwords Match", match);
        ImGui::Columns(1);
    }

    ImGui::Spacing();
    ImGui::Spacing();

    // Action Buttons
    if (isEnrollmentMode_) {
        if (UITheme::renderPrimaryButton("Create Account & Unlock Station", ImVec2(-1, 40)) ||
            enterUser || enterPass || enterConfirm) {
            handleEnrollment();
        }

        if (authDb.hasUsers()) {
            ImGui::Spacing();
            if (UITheme::renderSecondaryButton("Cancel & Return to Login", ImVec2(-1, 32))) {
                isEnrollmentMode_ = false;
                errorMessage_.clear();
            }
        }
    } else {
        if (UITheme::renderPrimaryButton("Authenticate Examiner", ImVec2(-1, 40)) ||
            enterUser || enterPass) {
            handleLogin();
        }

        ImGui::Spacing();
        ImGui::Dummy(ImVec2(0, 4.0f));

        // Security footer badges
        UITheme::renderBadge("PBKDF2-HMAC-SHA256", UITheme::COLOR_BLUE);
        ImGui::SameLine();
        UITheme::renderBadge("CSPRNG Salt (256-bit)", UITheme::COLOR_GREEN);
        ImGui::SameLine();
        UITheme::renderBadge("Tamper Proof (0600)", UITheme::COLOR_ORANGE);
    }

    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
}

} // namespace forensivault::gui
