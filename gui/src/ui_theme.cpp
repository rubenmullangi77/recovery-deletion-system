#include "ui_theme.hpp"
#include <filesystem>
#include <cstdio>
#include <cmath>
#include <cstring>

namespace fs = std::filesystem;

namespace forensivault::gui {

// Font Pointers
ImFont* UITheme::fontRegular = nullptr;
ImFont* UITheme::fontBold    = nullptr;
ImFont* UITheme::fontHeader  = nullptr;
ImFont* UITheme::fontMono    = nullptr;
ImFont* UITheme::fontSmall   = nullptr;

// Minimalist Cream & Orange Palette Constants
const ImVec4 UITheme::COLOR_CREAM_BG       = ImVec4(0.955f, 0.940f, 0.918f, 1.00f); // #F4F0EA - Clean Linen
const ImVec4 UITheme::COLOR_CREAM_CARD     = ImVec4(0.980f, 0.968f, 0.950f, 1.00f); // #FAF7F2 - Soft Elevated Card
const ImVec4 UITheme::COLOR_CREAM_INSET    = ImVec4(0.925f, 0.898f, 0.860f, 1.00f); // #ECE4DA - Sunken Input / Table Well
const ImVec4 UITheme::COLOR_CARD_BORDER    = ImVec4(0.865f, 0.835f, 0.795f, 0.85f); // #DDD5CB - Crisp Divider
const ImVec4 UITheme::COLOR_SHADOW_LIGHT   = ImVec4(1.000f, 1.000f, 1.000f, 0.85f); // Highlight bevel
const ImVec4 UITheme::COLOR_SHADOW_DARK    = ImVec4(0.810f, 0.770f, 0.720f, 0.50f); // Ambient shadow

const ImVec4 UITheme::COLOR_ORANGE         = ImVec4(0.980f, 0.440f, 0.120f, 1.00f); // #FA701F - Radiant Warm Orange
const ImVec4 UITheme::COLOR_ORANGE_HOVER   = ImVec4(1.000f, 0.535f, 0.220f, 1.00f); // #FF8838 - Glow Orange
const ImVec4 UITheme::COLOR_ORANGE_ACTIVE  = ImVec4(0.880f, 0.350f, 0.050f, 1.00f); // #E0590D - Deep Pressed
const ImVec4 UITheme::COLOR_ORANGE_TINT    = ImVec4(0.995f, 0.945f, 0.895f, 1.00f); // #FEEDDE - Subtle Orange Wash
const ImVec4 UITheme::COLOR_CYAN           = UITheme::COLOR_ORANGE;                  // Orange map for consistency

const ImVec4 UITheme::COLOR_TEXT_PRIMARY   = ImVec4(0.110f, 0.100f, 0.090f, 1.00f); // #1C1917 - High-contrast Deep Espresso
const ImVec4 UITheme::COLOR_TEXT_SECONDARY = ImVec4(0.340f, 0.325f, 0.305f, 1.00f); // #57534E - Taupe Stone
const ImVec4 UITheme::COLOR_TEXT_MUTED     = ImVec4(0.540f, 0.505f, 0.460f, 1.00f); // #8A8175 - Muted Caption
const ImVec4 UITheme::COLOR_BG_PANEL       = UITheme::COLOR_CREAM_CARD;

const ImVec4 UITheme::COLOR_GREEN          = ImVec4(0.086f, 0.640f, 0.290f, 1.00f); // #16A34A - Emerald Forest
const ImVec4 UITheme::COLOR_GREEN_TINT     = ImVec4(0.920f, 0.970f, 0.935f, 1.00f); // #EBF7EE
const ImVec4 UITheme::COLOR_YELLOW         = ImVec4(0.850f, 0.467f, 0.024f, 1.00f); // #D97706 - Amber Warning
const ImVec4 UITheme::COLOR_YELLOW_TINT    = ImVec4(0.995f, 0.970f, 0.925f, 1.00f); // #FEF8EC
const ImVec4 UITheme::COLOR_RED            = ImVec4(0.863f, 0.150f, 0.150f, 1.00f); // #DC2626 - Crimson
const ImVec4 UITheme::COLOR_RED_TINT       = ImVec4(0.995f, 0.925f, 0.920f, 1.00f); // #FEECEB
const ImVec4 UITheme::COLOR_BLUE           = ImVec4(0.008f, 0.518f, 0.780f, 1.00f); // #0284C7 - Sky Blue
const ImVec4 UITheme::COLOR_BLUE_TINT      = ImVec4(0.918f, 0.960f, 0.988f, 1.00f); // #EAF5FC

void UITheme::loadFonts(ImGuiIO& io) {
    ImFontConfig config;
    config.OversampleH = 3;
    config.OversampleV = 2;
    config.PixelSnapH = true;

    // Candidate fonts for Windows and Linux
    std::string regularPath = "C:\\Windows\\Fonts\\segoeui.ttf";
    std::string boldPath    = "C:\\Windows\\Fonts\\segoeuib.ttf";
    std::string monoPath    = "C:\\Windows\\Fonts\\consola.ttf";

    if (!fs::exists(regularPath)) {
        // Try Linux font locations
        if (fs::exists("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")) {
            regularPath = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf";
            boldPath    = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf";
            monoPath    = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf";
        } else if (fs::exists("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf")) {
            regularPath = "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf";
            boldPath    = "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf";
            monoPath    = "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf";
        }
    }

    if (fs::exists(regularPath)) {
        fontRegular = io.Fonts->AddFontFromFileTTF(regularPath.c_str(), 16.5f, &config);
        fontSmall   = io.Fonts->AddFontFromFileTTF(regularPath.c_str(), 13.5f, &config);

        if (fs::exists(boldPath)) {
            fontBold   = io.Fonts->AddFontFromFileTTF(boldPath.c_str(), 16.5f, &config);
            fontHeader = io.Fonts->AddFontFromFileTTF(boldPath.c_str(), 21.0f, &config);
        } else {
            fontBold   = fontRegular;
            fontHeader = fontRegular;
        }

        if (fs::exists(monoPath)) {
            fontMono = io.Fonts->AddFontFromFileTTF(monoPath.c_str(), 14.5f, &config);
        } else {
            fontMono = fontRegular;
        }
    } else {
        fontRegular = io.Fonts->AddFontDefault();
        fontBold    = fontRegular;
        fontHeader  = fontRegular;
        fontMono    = fontRegular;
        fontSmall   = fontRegular;
    }
}

void UITheme::applyNeumorphicCreamTheme() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    // Window & Panels
    colors[ImGuiCol_WindowBg]             = COLOR_CREAM_BG;
    colors[ImGuiCol_ChildBg]              = COLOR_CREAM_CARD;
    colors[ImGuiCol_PopupBg]              = ImVec4(0.990f, 0.982f, 0.970f, 0.98f);
    colors[ImGuiCol_Border]               = COLOR_CARD_BORDER;
    colors[ImGuiCol_BorderShadow]         = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);

    // Typography (High-readability deep espresso & taupe)
    colors[ImGuiCol_Text]                 = COLOR_TEXT_PRIMARY;
    colors[ImGuiCol_TextDisabled]         = COLOR_TEXT_MUTED;

    // Headers & Nav items
    colors[ImGuiCol_Header]               = COLOR_ORANGE_TINT;
    colors[ImGuiCol_HeaderHovered]        = ImVec4(0.995f, 0.880f, 0.770f, 1.00f);
    colors[ImGuiCol_HeaderActive]         = COLOR_ORANGE;

    // Buttons
    colors[ImGuiCol_Button]               = COLOR_CREAM_CARD;
    colors[ImGuiCol_ButtonHovered]        = COLOR_ORANGE_TINT;
    colors[ImGuiCol_ButtonActive]         = COLOR_CREAM_INSET;

    // Inset Frames (Text inputs, Combos, Sliders)
    colors[ImGuiCol_FrameBg]              = COLOR_CREAM_INSET;
    colors[ImGuiCol_FrameBgHovered]       = ImVec4(0.940f, 0.915f, 0.880f, 1.00f);
    colors[ImGuiCol_FrameBgActive]        = ImVec4(0.895f, 0.865f, 0.825f, 1.00f);

    // Tabs
    colors[ImGuiCol_Tab]                  = COLOR_CREAM_CARD;
    colors[ImGuiCol_TabHovered]           = COLOR_ORANGE_TINT;
    colors[ImGuiCol_TabActive]            = COLOR_CREAM_BG;
    colors[ImGuiCol_TabUnfocused]         = COLOR_CREAM_INSET;
    colors[ImGuiCol_TabUnfocusedActive]  = COLOR_CREAM_CARD;

    // Controls & Accents
    colors[ImGuiCol_SliderGrab]           = COLOR_ORANGE;
    colors[ImGuiCol_SliderGrabActive]     = COLOR_ORANGE_ACTIVE;
    colors[ImGuiCol_CheckMark]            = COLOR_ORANGE;
    colors[ImGuiCol_PlotHistogram]        = COLOR_ORANGE;
    colors[ImGuiCol_PlotHistogramHovered] = COLOR_ORANGE_HOVER;

    // Tables
    colors[ImGuiCol_TableHeaderBg]        = COLOR_CREAM_INSET;
    colors[ImGuiCol_TableBorderStrong]    = COLOR_CARD_BORDER;
    colors[ImGuiCol_TableBorderLight]     = ImVec4(0.880f, 0.845f, 0.800f, 0.65f);
    colors[ImGuiCol_TableRowBg]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]        = ImVec4(0.935f, 0.910f, 0.875f, 0.35f);

    // Scrollbars
    colors[ImGuiCol_ScrollbarBg]          = COLOR_CREAM_INSET;
    colors[ImGuiCol_ScrollbarGrab]        = ImVec4(0.780f, 0.740f, 0.690f, 0.75f);
    colors[ImGuiCol_ScrollbarGrabHovered] = COLOR_ORANGE;
    colors[ImGuiCol_ScrollbarGrabActive]  = COLOR_ORANGE_ACTIVE;

    // Separators
    colors[ImGuiCol_Separator]            = COLOR_CARD_BORDER;
    colors[ImGuiCol_SeparatorHovered]     = COLOR_ORANGE;
    colors[ImGuiCol_SeparatorActive]      = COLOR_ORANGE_ACTIVE;

    // Ergonomic Neumorphic Geometry
    style.WindowPadding     = ImVec2(16.0f, 16.0f);
    style.FramePadding      = ImVec2(12.0f, 7.0f);
    style.ItemSpacing       = ImVec2(12.0f, 9.0f);
    style.ItemInnerSpacing  = ImVec2(8.0f, 6.0f);
    style.IndentSpacing     = 20.0f;
    style.ScrollbarSize     = 13.0f;

    // Clean, modern soft radii (avoiding excessive rounded blob shapes)
    style.WindowRounding    = 10.0f;
    style.ChildRounding     = 9.0f;
    style.FrameRounding     = 7.0f;
    style.PopupRounding     = 9.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding      = 5.0f;
    style.TabRounding       = 7.0f;

    style.WindowBorderSize  = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.PopupBorderSize   = 1.0f;
    style.FrameBorderSize   = 1.0f;
}

bool UITheme::beginCard(const char* cardId, const char* title, const char* badgeText,
                        const ImVec4& badgeColor, float minHeight) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_CREAM_CARD);
    ImGui::PushStyleColor(ImGuiCol_Border, COLOR_CARD_BORDER);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 9.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.0f, 14.0f));

    bool open = ImGui::BeginChild(cardId, ImVec2(0, minHeight), true, ImGuiWindowFlags_None);

    if (title) {
        if (fontBold) ImGui::PushFont(fontBold);
        ImGui::TextColored(COLOR_TEXT_PRIMARY, "%s", title);
        if (fontBold) ImGui::PopFont();

        if (badgeText) {
            float badgeWidth = ImGui::CalcTextSize(badgeText).x + 22.0f;
            ImGui::SameLine(ImGui::GetWindowWidth() - badgeWidth - 16.0f);
            renderBadge(badgeText, badgeColor);
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    return open;
}

void UITheme::endCard() {
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
    ImGui::Spacing();
}

void UITheme::renderCardHeader(const char* title, const char* subtitle) {
    ImGui::Spacing();
    if (fontHeader) ImGui::PushFont(fontHeader);
    ImGui::TextColored(COLOR_ORANGE, "%s", title);
    if (fontHeader) ImGui::PopFont();

    if (subtitle) {
        ImGui::TextColored(COLOR_TEXT_SECONDARY, "%s", subtitle);
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
}

void UITheme::renderSectionHeader(const char* title, const char* subtitle) {
    ImGui::Spacing();
    if (fontBold) ImGui::PushFont(fontBold);
    ImGui::TextColored(COLOR_TEXT_PRIMARY, "%s", title);
    if (fontBold) ImGui::PopFont();

    if (subtitle) {
        ImGui::TextColored(COLOR_TEXT_MUTED, "%s", subtitle);
    }
    ImGui::Spacing();
}

void UITheme::renderMetricTile(const char* label, const char* value, const char* subtitle,
                               const ImVec4& valueColor, float width) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_CREAM_INSET);
    ImGui::PushStyleColor(ImGuiCol_Border, COLOR_CARD_BORDER);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 12.0f));

    ImGui::BeginChild(label, ImVec2(width, 92.0f), true, ImGuiWindowFlags_NoScrollbar);

    ImGui::TextColored(COLOR_TEXT_SECONDARY, "%s", label);
    ImGui::Spacing();

    if (fontBold) ImGui::PushFont(fontBold);
    ImGui::TextColored(valueColor, "%s", value);
    if (fontBold) ImGui::PopFont();

    if (subtitle) {
        ImGui::TextColored(COLOR_TEXT_MUTED, "%s", subtitle);
    }

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

void UITheme::renderBadge(const char* label, const ImVec4& color) {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(color.x, color.y, color.z, 0.14f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(color.x, color.y, color.z, 0.22f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(color.x, color.y, color.z, 0.28f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(color.x, color.y, color.z, 0.45f));
    ImGui::PushStyleColor(ImGuiCol_Text, color);

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 3.5f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);

    if (fontSmall) ImGui::PushFont(fontSmall);
    ImGui::Button(label);
    if (fontSmall) ImGui::PopFont();

    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(5);
}

void UITheme::renderStatusPill(const char* statusText, bool isSuccess) {
    const ImVec4& col = isSuccess ? COLOR_GREEN : COLOR_RED;
    renderBadge(statusText, col);
}

bool UITheme::renderPrimaryButton(const char* label, const ImVec2& size) {
    ImGui::PushStyleColor(ImGuiCol_Button, COLOR_ORANGE);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, COLOR_ORANGE_HOVER);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, COLOR_ORANGE_ACTIVE);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.00f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16.0f, 8.0f));

    if (fontBold) ImGui::PushFont(fontBold);
    bool clicked = ImGui::Button(label, size);
    if (fontBold) ImGui::PopFont();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(4);
    return clicked;
}

bool UITheme::renderRecoveryButton(const char* label, const ImVec2& size) {
    ImGui::PushStyleColor(ImGuiCol_Button, COLOR_BLUE);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.05f, 0.60f, 0.88f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.01f, 0.44f, 0.68f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.00f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16.0f, 8.0f));

    if (fontBold) ImGui::PushFont(fontBold);
    bool clicked = ImGui::Button(label, size);
    if (fontBold) ImGui::PopFont();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(4);
    return clicked;
}

bool UITheme::renderSecondaryButton(const char* label, const ImVec2& size) {
    ImGui::PushStyleColor(ImGuiCol_Button, COLOR_CREAM_CARD);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, COLOR_ORANGE_TINT);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, COLOR_CREAM_INSET);
    ImGui::PushStyleColor(ImGuiCol_Border, COLOR_CARD_BORDER);
    ImGui::PushStyleColor(ImGuiCol_Text, COLOR_TEXT_PRIMARY);

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14.0f, 8.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);

    bool clicked = ImGui::Button(label, size);

    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(5);
    return clicked;
}

bool UITheme::renderDestructiveButton(const char* label, const ImVec2& size) {
    ImGui::PushStyleColor(ImGuiCol_Button, COLOR_RED);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.95f, 0.28f, 0.28f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.75f, 0.10f, 0.10f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.00f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16.0f, 8.0f));

    if (fontBold) ImGui::PushFont(fontBold);
    bool clicked = ImGui::Button(label, size);
    if (fontBold) ImGui::PopFont();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(4);
    return clicked;
}

bool UITheme::renderGhostButton(const char* label, const ImVec2& size) {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, COLOR_ORANGE_TINT);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, COLOR_CREAM_INSET);
    ImGui::PushStyleColor(ImGuiCol_Text, COLOR_ORANGE);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 6.0f));

    bool clicked = ImGui::Button(label, size);

    ImGui::PopStyleVar(1);
    ImGui::PopStyleColor(4);
    return clicked;
}

void UITheme::renderProgressBar(float fraction, const char* overlayText, const char* subText) {
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, COLOR_ORANGE);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, COLOR_CREAM_INSET);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 7.0f);

    ImGui::ProgressBar(fraction, ImVec2(-1, 22.0f), overlayText);

    ImGui::PopStyleVar();
    ImGui::PopStyleColor(2);

    if (subText && std::strlen(subText) > 0) {
        ImGui::Spacing();
        ImGui::TextColored(COLOR_TEXT_MUTED, "%s", subText);
    }
}

void UITheme::renderDangerBanner(const char* message) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_RED_TINT);
    ImGui::PushStyleColor(ImGuiCol_Border, COLOR_RED);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 10.0f));

    ImGui::BeginChild("DangerBanner", ImVec2(0, 0), true, ImGuiWindowFlags_AlwaysAutoResize);
    if (fontBold) ImGui::PushFont(fontBold);
    ImGui::TextColored(COLOR_RED, "[!] %s", message);
    if (fontBold) ImGui::PopFont();
    ImGui::EndChild();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
    ImGui::Spacing();
}

void UITheme::renderWarningBanner(const char* message) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_YELLOW_TINT);
    ImGui::PushStyleColor(ImGuiCol_Border, COLOR_YELLOW);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 10.0f));

    ImGui::BeginChild("WarningBanner", ImVec2(0, 0), true, ImGuiWindowFlags_AlwaysAutoResize);
    ImGui::TextColored(COLOR_YELLOW, "[!] %s", message);
    ImGui::EndChild();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
    ImGui::Spacing();
}

void UITheme::renderSuccessBanner(const char* message) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_GREEN_TINT);
    ImGui::PushStyleColor(ImGuiCol_Border, COLOR_GREEN);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 10.0f));

    ImGui::BeginChild("SuccessBanner", ImVec2(0, 0), true, ImGuiWindowFlags_AlwaysAutoResize);
    if (fontBold) ImGui::PushFont(fontBold);
    ImGui::TextColored(COLOR_GREEN, "[OK] %s", message);
    if (fontBold) ImGui::PopFont();
    ImGui::EndChild();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
    ImGui::Spacing();
}

void UITheme::renderInfoBanner(const char* message) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_BLUE_TINT);
    ImGui::PushStyleColor(ImGuiCol_Border, COLOR_BLUE);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 10.0f));

    ImGui::BeginChild("InfoBanner", ImVec2(0, 0), true, ImGuiWindowFlags_AlwaysAutoResize);
    ImGui::TextColored(COLOR_BLUE, "[i] %s", message);
    ImGui::EndChild();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
    ImGui::Spacing();
}

void UITheme::renderHelpMarker(const char* desc) {
    ImGui::TextDisabled("(?)");
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

void UITheme::renderCardShadow(const ImVec2& minPos, const ImVec2& maxPos, float rounding) {
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    if (!drawList) return;

    // Subtle dual-tone bevel
    drawList->AddRect(
        ImVec2(minPos.x - 1.0f, minPos.y - 1.0f),
        ImVec2(maxPos.x + 1.0f, maxPos.y + 1.0f),
        ImColor(COLOR_SHADOW_LIGHT),
        rounding, 0, 1.0f);

    drawList->AddRect(
        ImVec2(minPos.x + 1.0f, minPos.y + 1.0f),
        ImVec2(maxPos.x + 2.0f, maxPos.y + 2.0f),
        ImColor(COLOR_SHADOW_DARK),
        rounding, 0, 1.0f);
}

} // namespace forensivault::gui
