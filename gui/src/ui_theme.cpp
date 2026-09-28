#include "ui_theme.hpp"
#include "embedded_fonts.hpp"
#include <filesystem>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <cstdarg>
#include <vector>
#include <utility>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

namespace forensivault::gui {

// Font Pointers
ImFont* UITheme::fontRegular = nullptr;
ImFont* UITheme::fontBold    = nullptr;
ImFont* UITheme::fontHeader  = nullptr;
ImFont* UITheme::fontMono    = nullptr;
ImFont* UITheme::fontSmall   = nullptr;

static bool s_isDarkTheme = false;

// Dynamic Palette Initializers (Defaults to Light Warm Cream)
ImVec4 UITheme::COLOR_CREAM_BG       = ImVec4(0.955f, 0.940f, 0.918f, 1.00f); // #F4F0EA - Clean Linen
ImVec4 UITheme::COLOR_CREAM_CARD     = ImVec4(0.980f, 0.968f, 0.950f, 1.00f); // #FAF7F2 - Soft Elevated Card
ImVec4 UITheme::COLOR_CREAM_INSET    = ImVec4(0.925f, 0.898f, 0.860f, 1.00f); // #ECE4DA - Sunken Input / Table Well
ImVec4 UITheme::COLOR_CARD_BORDER    = ImVec4(0.865f, 0.835f, 0.795f, 0.85f); // #DDD5CB - Crisp Divider
ImVec4 UITheme::COLOR_SHADOW_LIGHT   = ImVec4(1.000f, 1.000f, 1.000f, 0.85f); // Highlight bevel
ImVec4 UITheme::COLOR_SHADOW_DARK    = ImVec4(0.810f, 0.770f, 0.720f, 0.50f); // Ambient shadow

ImVec4 UITheme::COLOR_ORANGE         = ImVec4(0.980f, 0.440f, 0.120f, 1.00f); // #FA701F - Radiant Warm Orange
ImVec4 UITheme::COLOR_ORANGE_HOVER   = ImVec4(1.000f, 0.535f, 0.220f, 1.00f); // #FF8838 - Glow Orange
ImVec4 UITheme::COLOR_ORANGE_ACTIVE  = ImVec4(0.880f, 0.350f, 0.050f, 1.00f); // #E0590D - Deep Pressed
ImVec4 UITheme::COLOR_ORANGE_TINT    = ImVec4(0.995f, 0.945f, 0.895f, 1.00f); // #FEEDDE - Subtle Orange Wash
ImVec4 UITheme::COLOR_CYAN           = ImVec4(0.980f, 0.440f, 0.120f, 1.00f); // Orange map for consistency

ImVec4 UITheme::COLOR_TEXT_PRIMARY   = ImVec4(0.110f, 0.100f, 0.090f, 1.00f); // #1C1917 - High-contrast Deep Espresso
ImVec4 UITheme::COLOR_TEXT_SECONDARY = ImVec4(0.340f, 0.325f, 0.305f, 1.00f); // #57534E - Taupe Stone
ImVec4 UITheme::COLOR_TEXT_MUTED     = ImVec4(0.540f, 0.505f, 0.460f, 1.00f); // #8A8175 - Muted Caption
ImVec4 UITheme::COLOR_BG_PANEL       = ImVec4(0.980f, 0.968f, 0.950f, 1.00f);

ImVec4 UITheme::COLOR_GREEN          = ImVec4(0.086f, 0.640f, 0.290f, 1.00f); // #16A34A - Emerald Forest
ImVec4 UITheme::COLOR_GREEN_TINT     = ImVec4(0.920f, 0.970f, 0.935f, 1.00f); // #EBF7EE
ImVec4 UITheme::COLOR_YELLOW         = ImVec4(0.850f, 0.467f, 0.024f, 1.00f); // #D97706 - Amber Warning
ImVec4 UITheme::COLOR_YELLOW_TINT    = ImVec4(0.995f, 0.970f, 0.925f, 1.00f); // #FEF8EC
ImVec4 UITheme::COLOR_RED            = ImVec4(0.863f, 0.150f, 0.150f, 1.00f); // #DC2626 - Crimson
ImVec4 UITheme::COLOR_RED_TINT       = ImVec4(0.995f, 0.925f, 0.920f, 1.00f); // #FEECEB
ImVec4 UITheme::COLOR_BLUE           = ImVec4(0.008f, 0.518f, 0.780f, 1.00f); // #0284C7 - Sky Blue
ImVec4 UITheme::COLOR_BLUE_TINT      = ImVec4(0.918f, 0.960f, 0.988f, 1.00f); // #EAF5FC

void UITheme::loadFonts(ImGuiIO& io, float dpiScale) {
    if (dpiScale <= 0.1f) dpiScale = 1.0f;

    ImFontConfig config;
    config.OversampleH = 3;
    config.OversampleV = 2;
    config.PixelSnapH = true;

    // Multi-tier candidate search for system sans-serif fonts
    std::string regularPath;
    std::string boldPath;
    std::string monoPath;

#if defined(_WIN32)
    std::vector<std::pair<std::string, std::string>> winCandidates = {
        {"C:\\Windows\\Fonts\\segoeui.ttf", "C:\\Windows\\Fonts\\segoeuib.ttf"},
        {"C:\\Windows\\Fonts\\arial.ttf", "C:\\Windows\\Fonts\\arialbd.ttf"}
    };
    for (const auto& pair : winCandidates) {
        if (fs::exists(pair.first)) {
            regularPath = pair.first;
            boldPath = pair.second;
            break;
        }
    }
    if (fs::exists("C:\\Windows\\Fonts\\consola.ttf")) {
        monoPath = "C:\\Windows\\Fonts\\consola.ttf";
    } else if (fs::exists("C:\\Windows\\Fonts\\cascadia.ttf")) {
        monoPath = "C:\\Windows\\Fonts\\cascadia.ttf";
    }
#else
    // Linux / POSIX candidate font locations
    std::vector<std::pair<std::string, std::string>> linuxCandidates = {
        {"/usr/share/fonts/inter/Inter-Regular.ttf", "/usr/share/fonts/inter/Inter-Bold.ttf"},
        {"/usr/share/fonts/Adwaita/AdwaitaSans-Regular.ttf", "/usr/share/fonts/Adwaita/AdwaitaSans-Bold.ttf"},
        {"/usr/share/fonts/noto/NotoSans-Regular.ttf", "/usr/share/fonts/noto/NotoSans-Bold.ttf"},
        {"/usr/share/fonts/TTF/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"},
        {"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"},
        {"/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"}
    };

    for (const auto& pair : linuxCandidates) {
        if (fs::exists(pair.first)) {
            regularPath = pair.first;
            boldPath = pair.second;
            break;
        }
    }

    std::vector<std::string> linuxMonoCandidates = {
        "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Regular.ttf",
        "/usr/share/fonts/TTF/JetBrainsMono-Regular.ttf",
        "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"
    };

    for (const auto& m : linuxMonoCandidates) {
        if (fs::exists(m)) {
            monoPath = m;
            break;
        }
    }
#endif

    float regularSize = std::round(16.0f * dpiScale);
    float smallSize   = std::round(13.0f * dpiScale);
    float boldSize    = std::round(16.0f * dpiScale);
    float headerSize  = std::round(21.0f * dpiScale);
    float monoSize    = std::round(14.5f * dpiScale);

    // 1. Try loading premium system sans font if located
    if (!regularPath.empty() && fs::exists(regularPath)) {
        fontRegular = io.Fonts->AddFontFromFileTTF(regularPath.c_str(), regularSize, &config);
        fontSmall   = io.Fonts->AddFontFromFileTTF(regularPath.c_str(), smallSize, &config);

        if (!boldPath.empty() && fs::exists(boldPath)) {
            fontBold   = io.Fonts->AddFontFromFileTTF(boldPath.c_str(), boldSize, &config);
            fontHeader = io.Fonts->AddFontFromFileTTF(boldPath.c_str(), headerSize, &config);
        } else {
            fontBold   = fontRegular;
            fontHeader = fontRegular;
        }
    } else {
        // Fallback to Embedded Compressed Roboto-Medium (guaranteed modern, high-DPI font)
        fontRegular = io.Fonts->AddFontFromMemoryCompressedTTF(
            fonts::roboto_medium_compressed_data, fonts::roboto_medium_compressed_size,
            regularSize, &config);
        fontSmall = io.Fonts->AddFontFromMemoryCompressedTTF(
            fonts::roboto_medium_compressed_data, fonts::roboto_medium_compressed_size,
            smallSize, &config);
        fontBold = io.Fonts->AddFontFromMemoryCompressedTTF(
            fonts::roboto_medium_compressed_data, fonts::roboto_medium_compressed_size,
            boldSize, &config);
        fontHeader = io.Fonts->AddFontFromMemoryCompressedTTF(
            fonts::roboto_medium_compressed_data, fonts::roboto_medium_compressed_size,
            headerSize, &config);
    }

    // 2. Load Monospace font (System or Embedded Cousine-Regular)
    if (!monoPath.empty() && fs::exists(monoPath)) {
        fontMono = io.Fonts->AddFontFromFileTTF(monoPath.c_str(), monoSize, &config);
    } else {
        fontMono = io.Fonts->AddFontFromMemoryCompressedTTF(
            fonts::cousine_regular_compressed_data, fonts::cousine_regular_compressed_size,
            monoSize, &config);
    }

    // Absolute fallback safety (should never be reached, but guarantees no null font pointers)
    if (!fontRegular) fontRegular = io.Fonts->AddFontDefault();
    if (!fontSmall)   fontSmall   = fontRegular;
    if (!fontBold)    fontBold    = fontRegular;
    if (!fontHeader)  fontHeader  = fontRegular;
    if (!fontMono)    fontMono    = fontRegular;
}

bool UITheme::isDarkTheme() {
    return s_isDarkTheme;
}

void UITheme::applyNeumorphicCreamTheme() {
    applyTheme(false);
}

void UITheme::applyDarkTheme() {
    applyTheme(true);
}

void UITheme::toggleTheme() {
    applyTheme(!s_isDarkTheme);
}

void UITheme::applyTheme(bool isDark) {
    s_isDarkTheme = isDark;

    if (isDark) {
        // Obsidian Charcoal & Vibrant Amber/Orange Palette
        COLOR_CREAM_BG       = ImVec4(0.065f, 0.075f, 0.090f, 1.00f); // #111317 - Deep Slate Canvas
        COLOR_CREAM_CARD     = ImVec4(0.102f, 0.114f, 0.137f, 1.00f); // #1A1D23 - Elevated Dark Slate Card
        COLOR_CREAM_INSET    = ImVec4(0.078f, 0.086f, 0.105f, 1.00f); // #14161B - Sunken Dark Well
        COLOR_CARD_BORDER    = ImVec4(0.190f, 0.215f, 0.255f, 0.85f); // #303741 - Subtle Crisp Border
        COLOR_SHADOW_LIGHT   = ImVec4(0.180f, 0.200f, 0.240f, 0.25f);
        COLOR_SHADOW_DARK    = ImVec4(0.015f, 0.018f, 0.025f, 0.60f);

        COLOR_ORANGE         = ImVec4(1.000f, 0.450f, 0.140f, 1.00f); // #FF7324 - Radiant Warm Orange
        COLOR_ORANGE_HOVER   = ImVec4(1.000f, 0.550f, 0.250f, 1.00f);
        COLOR_ORANGE_ACTIVE  = ImVec4(0.880f, 0.380f, 0.080f, 1.00f);
        COLOR_ORANGE_TINT    = ImVec4(1.000f, 0.450f, 0.140f, 0.18f); // Translucent orange wash
        COLOR_CYAN           = COLOR_ORANGE;

        COLOR_TEXT_PRIMARY   = ImVec4(0.950f, 0.955f, 0.965f, 1.00f); // #F3F4F6 - Crisp Off-White
        COLOR_TEXT_SECONDARY = ImVec4(0.680f, 0.710f, 0.760f, 1.00f); // #AEB5C2 - Sleek Silver
        COLOR_TEXT_MUTED     = ImVec4(0.480f, 0.510f, 0.570f, 1.00f); // #7A8291 - Slate Caption
        COLOR_BG_PANEL       = COLOR_CREAM_CARD;

        COLOR_GREEN          = ImVec4(0.180f, 0.800f, 0.440f, 1.00f); // #2ECC71 - Vibrant Emerald
        COLOR_GREEN_TINT     = ImVec4(0.180f, 0.800f, 0.440f, 0.18f);
        COLOR_YELLOW         = ImVec4(0.960f, 0.650f, 0.140f, 1.00f); // #F5A623 - Bright Amber
        COLOR_YELLOW_TINT    = ImVec4(0.960f, 0.650f, 0.140f, 0.18f);
        COLOR_RED            = ImVec4(0.950f, 0.280f, 0.280f, 1.00f); // #F24747 - Bright Crimson
        COLOR_RED_TINT       = ImVec4(0.950f, 0.280f, 0.280f, 0.18f);
        COLOR_BLUE           = ImVec4(0.220f, 0.680f, 0.980f, 1.00f); // #38BDF8 - Sky Blue
        COLOR_BLUE_TINT      = ImVec4(0.220f, 0.680f, 0.980f, 0.18f);
    } else {
        // Warm Cream Palette
        COLOR_CREAM_BG       = ImVec4(0.955f, 0.940f, 0.918f, 1.00f); // #F4F0EA - Clean Linen
        COLOR_CREAM_CARD     = ImVec4(0.980f, 0.968f, 0.950f, 1.00f); // #FAF7F2 - Soft Elevated Card
        COLOR_CREAM_INSET    = ImVec4(0.925f, 0.898f, 0.860f, 1.00f); // #ECE4DA - Sunken Input / Table Well
        COLOR_CARD_BORDER    = ImVec4(0.865f, 0.835f, 0.795f, 0.85f); // #DDD5CB - Crisp Divider
        COLOR_SHADOW_LIGHT   = ImVec4(1.000f, 1.000f, 1.000f, 0.85f); // Highlight bevel
        COLOR_SHADOW_DARK    = ImVec4(0.810f, 0.770f, 0.720f, 0.50f); // Ambient shadow

        COLOR_ORANGE         = ImVec4(0.980f, 0.440f, 0.120f, 1.00f); // #FA701F - Radiant Warm Orange
        COLOR_ORANGE_HOVER   = ImVec4(1.000f, 0.535f, 0.220f, 1.00f); // #FF8838 - Glow Orange
        COLOR_ORANGE_ACTIVE  = ImVec4(0.880f, 0.350f, 0.050f, 1.00f); // #E0590D - Deep Pressed
        COLOR_ORANGE_TINT    = ImVec4(0.995f, 0.945f, 0.895f, 1.00f); // #FEEDDE - Subtle Orange Wash
        COLOR_CYAN           = COLOR_ORANGE;

        COLOR_TEXT_PRIMARY   = ImVec4(0.110f, 0.100f, 0.090f, 1.00f); // #1C1917 - High-contrast Deep Espresso
        COLOR_TEXT_SECONDARY = ImVec4(0.340f, 0.325f, 0.305f, 1.00f); // #57534E - Taupe Stone
        COLOR_TEXT_MUTED     = ImVec4(0.540f, 0.505f, 0.460f, 1.00f); // #8A8175 - Muted Caption
        COLOR_BG_PANEL       = COLOR_CREAM_CARD;

        COLOR_GREEN          = ImVec4(0.086f, 0.640f, 0.290f, 1.00f); // #16A34A - Emerald Forest
        COLOR_GREEN_TINT     = ImVec4(0.920f, 0.970f, 0.935f, 1.00f); // #EBF7EE
        COLOR_YELLOW         = ImVec4(0.850f, 0.467f, 0.024f, 1.00f); // #D97706 - Amber Warning
        COLOR_YELLOW_TINT    = ImVec4(0.995f, 0.970f, 0.925f, 1.00f); // #FEF8EC
        COLOR_RED            = ImVec4(0.863f, 0.150f, 0.150f, 1.00f); // #DC2626 - Crimson
        COLOR_RED_TINT       = ImVec4(0.995f, 0.925f, 0.920f, 1.00f); // #FEECEB
        COLOR_BLUE           = ImVec4(0.008f, 0.518f, 0.780f, 1.00f); // #0284C7 - Sky Blue
        COLOR_BLUE_TINT      = ImVec4(0.918f, 0.960f, 0.988f, 1.00f); // #EAF5FC
    }

    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    // Window & Panels
    colors[ImGuiCol_WindowBg]             = COLOR_CREAM_BG;
    colors[ImGuiCol_ChildBg]              = COLOR_CREAM_CARD;
    colors[ImGuiCol_PopupBg]              = isDark ? ImVec4(0.12f, 0.14f, 0.17f, 0.98f) : ImVec4(0.990f, 0.982f, 0.970f, 0.98f);
    colors[ImGuiCol_Border]               = COLOR_CARD_BORDER;
    colors[ImGuiCol_BorderShadow]         = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);

    // Typography
    colors[ImGuiCol_Text]                 = COLOR_TEXT_PRIMARY;
    colors[ImGuiCol_TextDisabled]         = COLOR_TEXT_MUTED;

    // Headers & Nav items
    colors[ImGuiCol_Header]               = COLOR_ORANGE_TINT;
    colors[ImGuiCol_HeaderHovered]        = isDark ? ImVec4(0.24f, 0.28f, 0.34f, 1.0f) : ImVec4(0.995f, 0.880f, 0.770f, 1.00f);
    colors[ImGuiCol_HeaderActive]         = COLOR_ORANGE;

    // Buttons
    colors[ImGuiCol_Button]               = COLOR_CREAM_CARD;
    colors[ImGuiCol_ButtonHovered]        = COLOR_ORANGE_TINT;
    colors[ImGuiCol_ButtonActive]         = COLOR_CREAM_INSET;

    // Inset Frames (Text inputs, Combos, Sliders)
    colors[ImGuiCol_FrameBg]              = COLOR_CREAM_INSET;
    colors[ImGuiCol_FrameBgHovered]       = isDark ? ImVec4(0.15f, 0.17f, 0.22f, 1.0f) : ImVec4(0.940f, 0.915f, 0.880f, 1.00f);
    colors[ImGuiCol_FrameBgActive]        = isDark ? ImVec4(0.18f, 0.21f, 0.27f, 1.0f) : ImVec4(0.895f, 0.865f, 0.825f, 1.00f);

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
    colors[ImGuiCol_TableBorderLight]     = isDark ? ImVec4(0.20f, 0.23f, 0.28f, 0.65f) : ImVec4(0.880f, 0.845f, 0.800f, 0.65f);
    colors[ImGuiCol_TableRowBg]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]        = isDark ? ImVec4(0.12f, 0.14f, 0.18f, 0.40f) : ImVec4(0.935f, 0.910f, 0.875f, 0.35f);

    // Scrollbars
    colors[ImGuiCol_ScrollbarBg]          = COLOR_CREAM_INSET;
    colors[ImGuiCol_ScrollbarGrab]        = isDark ? ImVec4(0.28f, 0.31f, 0.38f, 0.75f) : ImVec4(0.780f, 0.740f, 0.690f, 0.75f);
    colors[ImGuiCol_ScrollbarGrabHovered] = COLOR_ORANGE;
    colors[ImGuiCol_ScrollbarGrabActive]  = COLOR_ORANGE_ACTIVE;

    // Separators
    colors[ImGuiCol_Separator]            = COLOR_CARD_BORDER;
    colors[ImGuiCol_SeparatorHovered]     = COLOR_ORANGE;
    colors[ImGuiCol_SeparatorActive]      = COLOR_ORANGE_ACTIVE;

    // Ergonomic Neumorphic Geometry - Spacious, Clean & Modern
    style.WindowPadding     = ImVec2(22.0f, 18.0f);
    style.FramePadding      = ImVec2(14.0f, 9.0f);
    style.ItemSpacing       = ImVec2(16.0f, 13.0f);
    style.ItemInnerSpacing  = ImVec2(10.0f, 8.0f);
    style.IndentSpacing     = 22.0f;
    style.ScrollbarSize     = 10.0f;

    style.WindowRounding    = 10.0f;
    style.ChildRounding     = 10.0f;
    style.FrameRounding     = 7.0f;
    style.PopupRounding     = 10.0f;
    style.ScrollbarRounding = 8.0f;
    style.GrabRounding      = 6.0f;
    style.TabRounding       = 7.0f;

    style.WindowBorderSize  = 1.0f;
    style.ChildBorderSize   = 1.0f;
    style.PopupBorderSize   = 1.0f;
    style.FrameBorderSize   = 1.0f;
}

bool UITheme::beginCard(const char* cardId, const char* title, const char* badgeText,
                        const ImVec4& badgeColor, float minHeight) {
    (void)minHeight; // Cards dynamically auto-resize to fit their content
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_CREAM_CARD);
    ImGui::PushStyleColor(ImGuiCol_Border, COLOR_CARD_BORDER);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20.0f, 16.0f));

    // Cards automatically resize vertically to fit their contents and never generate internal scrollbars.
    // The main content area handles all scrolling smoothly.
    ImGuiChildFlags childFlags = ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY;
    ImGuiWindowFlags windowFlags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

    bool open = ImGui::BeginChild(cardId, ImVec2(0, 0), childFlags, windowFlags);

    if (title) {
        float badgeWidth = badgeText ? (ImGui::CalcTextSize(badgeText).x + 22.0f) : 0.0f;

        if (fontBold) ImGui::PushFont(fontBold);
        ImGui::TextColored(COLOR_TEXT_PRIMARY, "%s", title);
        if (fontBold) ImGui::PopFont();

        if (badgeText) {
            float targetX = ImGui::GetWindowWidth() - badgeWidth - 20.0f;
            if (targetX > ImGui::GetCursorPosX() + 16.0f) {
                ImGui::SameLine(targetX);
                renderBadge(badgeText, badgeColor);
            } else {
                ImGui::SameLine(0.0f, 8.0f);
                renderBadge(badgeText, badgeColor);
            }
        }

        ImGui::Dummy(ImVec2(0.0f, 4.0f));
    }

    return open;
}

void UITheme::endCard() {
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
    ImGui::Dummy(ImVec2(0.0f, 12.0f)); // Clean spacious margin between stacked cards
}

void UITheme::renderCardHeader(const char* title, const char* subtitle) {
    ImGui::Dummy(ImVec2(0.0f, 4.0f));
    if (fontHeader) ImGui::PushFont(fontHeader);
    ImGui::TextColored(COLOR_ORANGE, "%s", title);
    if (fontHeader) ImGui::PopFont();

    if (subtitle) {
        ImGui::Spacing();
        ImGui::TextColored(COLOR_TEXT_SECONDARY, "%s", subtitle);
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Dummy(ImVec2(0.0f, 10.0f));
}

void UITheme::renderSectionHeader(const char* title, const char* subtitle) {
    ImGui::Dummy(ImVec2(0.0f, 4.0f));
    if (fontBold) ImGui::PushFont(fontBold);
    ImGui::TextColored(COLOR_TEXT_PRIMARY, "%s", title);
    if (fontBold) ImGui::PopFont();

    if (subtitle) {
        ImGui::Spacing();
        ImGui::TextColored(COLOR_TEXT_MUTED, "%s", subtitle);
    }
    ImGui::Dummy(ImVec2(0.0f, 6.0f));
}

void UITheme::renderMetricTile(const char* label, const char* value, const char* subtitle,
                               const ImVec4& valueColor, float width) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, COLOR_CREAM_INSET);
    ImGui::PushStyleColor(ImGuiCol_Border, COLOR_CARD_BORDER);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 9.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.0f, 14.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 3.0f));

    ImGuiChildFlags childFlags = ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY;
    ImGuiWindowFlags windowFlags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

    ImGui::BeginChild(label, ImVec2(width, 0), childFlags, windowFlags);

    renderWrappedText(label, COLOR_TEXT_SECONDARY);
    ImGui::Dummy(ImVec2(0.0f, 2.0f));

    if (fontBold) ImGui::PushFont(fontBold);
    renderWrappedText(value, valueColor);
    if (fontBold) ImGui::PopFont();

    if (subtitle) {
        ImGui::Dummy(ImVec2(0.0f, 3.0f));
        renderWrappedText(subtitle, COLOR_TEXT_MUTED);
    }

    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
}

void UITheme::renderWrappedText(const char* text, const ImVec4& color) {
    if (!text || *text == '\0') return;
    float availW = ImGui::GetContentRegionAvail().x;
    if (availW > 10.0f) {
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + availW);
        ImGui::TextColored(color, "%s", text);
        ImGui::PopTextWrapPos();
    } else {
        ImGui::TextColored(color, "%s", text);
    }
}

void UITheme::renderWrappedFormatted(const ImVec4& color, const char* fmt, ...) {
    if (!fmt || *fmt == '\0') return;
    va_list args;
    va_start(args, fmt);
    char buf[2048];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    renderWrappedText(buf, color);
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

void UITheme::renderBanner(const char* prefix, const char* message,
                           const ImVec4& textColor, const ImVec4& bgColor, const ImVec4& borderColor) {
    if (!message || !*message) return;

    float availW = ImGui::GetContentRegionAvail().x;
    if (availW <= 10.0f) return;

    ImVec2 padding(14.0f, 10.0f);
    float wrapWidth = availW - (padding.x * 2.0f);
    if (wrapWidth <= 10.0f) wrapWidth = 10.0f;

    std::string fullText = (prefix && *prefix) ? (std::string(prefix) + " " + message) : std::string(message);

    if (fontBold) ImGui::PushFont(fontBold);
    ImVec2 textSize = ImGui::CalcTextSize(fullText.c_str(), nullptr, false, wrapWidth);
    float boxH = textSize.y + (padding.y * 2.0f);

    ImVec2 p0 = ImGui::GetCursorScreenPos();
    ImVec2 p1 = ImVec2(p0.x + availW, p0.y + boxH);

    ImDrawList* drawList = ImGui::GetWindowDrawList();
    if (drawList) {
        drawList->AddRectFilled(p0, p1, ImColor(bgColor), 8.0f);
        drawList->AddRect(p0, p1, ImColor(borderColor), 8.0f, 0, 1.0f);
    }

    ImGui::SetCursorScreenPos(ImVec2(p0.x + padding.x, p0.y + padding.y));
    ImGui::PushTextWrapPos(p0.x + padding.x + wrapWidth);
    ImGui::TextColored(textColor, "%s", fullText.c_str());
    ImGui::PopTextWrapPos();
    if (fontBold) ImGui::PopFont();

    ImGui::SetCursorScreenPos(ImVec2(p0.x, p1.y));
    ImGui::Dummy(ImVec2(availW, 8.0f));
}

void UITheme::renderDangerBanner(const char* message) {
    renderBanner("[!]", message, COLOR_RED, COLOR_RED_TINT, COLOR_RED);
}

void UITheme::renderWarningBanner(const char* message) {
    renderBanner("[!]", message, COLOR_YELLOW, COLOR_YELLOW_TINT, COLOR_YELLOW);
}

void UITheme::renderSuccessBanner(const char* message) {
    renderBanner("[OK]", message, COLOR_GREEN, COLOR_GREEN_TINT, COLOR_GREEN);
}

void UITheme::renderInfoBanner(const char* message) {
    renderBanner("[i]", message, COLOR_BLUE, COLOR_BLUE_TINT, COLOR_BLUE);
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

std::string UITheme::formatByteSize(uint64_t bytes) {
    const double KB = 1024.0;
    const double MB = KB * 1024.0;
    const double GB = MB * 1024.0;
    const double TB = GB * 1024.0;

    std::ostringstream ss;
    ss << std::fixed;
    if (bytes >= TB) {
        ss << std::setprecision(2) << (bytes / TB) << " TB";
    } else if (bytes >= GB) {
        ss << std::setprecision(2) << (bytes / GB) << " GB";
    } else if (bytes >= MB) {
        ss << std::setprecision(2) << (bytes / MB) << " MB";
    } else if (bytes >= KB) {
        ss << std::setprecision(1) << (bytes / KB) << " KB";
    } else {
        ss << bytes << " B";
    }
    return ss.str();
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
