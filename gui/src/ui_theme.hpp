#pragma once

#include <imgui.h>
#include <string>
#include <cstdint>

namespace forensivault::gui {

class UITheme {
public:
    static void applyTheme(bool dark);
    static void applyNeumorphicCreamTheme();
    static void applyDarkTheme();
    static bool isDarkTheme();
    static void toggleTheme();
    static void loadFonts(ImGuiIO& io, float dpiScale = 1.0f);

    // Font Pointers
    static ImFont* fontRegular;
    static ImFont* fontBold;
    static ImFont* fontHeader;
    static ImFont* fontMono;
    static ImFont* fontSmall;

    // Palette Colors (dynamically updated when theme changes)
    static ImVec4 COLOR_CREAM_BG;        // Base window canvas
    static ImVec4 COLOR_CREAM_CARD;      // Elevated neumorphic card surface
    static ImVec4 COLOR_CREAM_INSET;     // Sunken wells for inputs & tables
    static ImVec4 COLOR_CARD_BORDER;     // Crisp 1px card boundary
    static ImVec4 COLOR_SHADOW_LIGHT;    // Soft top-left highlight
    static ImVec4 COLOR_SHADOW_DARK;     // Soft bottom-right ambient shadow

    static ImVec4 COLOR_ORANGE;          // Radiant warm orange brand accent
    static ImVec4 COLOR_ORANGE_HOVER;    // Lighter orange for hover states
    static ImVec4 COLOR_ORANGE_ACTIVE;   // Deeper pressed orange
    static ImVec4 COLOR_ORANGE_TINT;     // Translucent orange wash for pills & tabs
    static ImVec4 COLOR_CYAN;            // Maps to Orange for harmony

    static ImVec4 COLOR_TEXT_PRIMARY;    // High-contrast deep espresso / clean white
    static ImVec4 COLOR_TEXT_SECONDARY;  // Muted taupe stone / sleek silver
    static ImVec4 COLOR_TEXT_MUTED;      // Muted caption / slate
    static ImVec4 COLOR_BG_PANEL;        // Alias for COLOR_CREAM_CARD

    // Semantic Status Colors
    static ImVec4 COLOR_GREEN;           // Emerald Forest
    static ImVec4 COLOR_GREEN_TINT;
    static ImVec4 COLOR_YELLOW;          // Amber Warning
    static ImVec4 COLOR_YELLOW_TINT;
    static ImVec4 COLOR_RED;             // Crimson Destructive
    static ImVec4 COLOR_RED_TINT;
    static ImVec4 COLOR_BLUE;            // Forensic Info Sky
    static ImVec4 COLOR_BLUE_TINT;

    // Neumorphic Card & Container Components
    static bool beginCard(const char* cardId, const char* title = nullptr,
                          const char* badgeText = nullptr, const ImVec4& badgeColor = COLOR_ORANGE,
                          float minHeight = 0.0f);
    static void endCard();

    // Typography & Section Headers
    static void renderCardHeader(const char* title, const char* subtitle = nullptr);
    static void renderSectionHeader(const char* title, const char* subtitle = nullptr);
    static void renderMetricTile(const char* label, const char* value, const char* subtitle = nullptr,
                                 const ImVec4& valueColor = COLOR_ORANGE, float width = 0.0f);
    static void renderWrappedText(const char* text, const ImVec4& color = COLOR_TEXT_PRIMARY);
    static void renderWrappedFormatted(const ImVec4& color, const char* fmt, ...);
    static void renderHelpMarker(const char* desc);

    // Badges & Pills
    static void renderBadge(const char* label, const ImVec4& color);
    static void renderStatusPill(const char* statusText, bool isSuccess);

    // Buttons
    static bool renderPrimaryButton(const char* label, const ImVec2& size = ImVec2(0, 0));
    static bool renderRecoveryButton(const char* label, const ImVec2& size = ImVec2(0, 0));
    static bool renderSecondaryButton(const char* label, const ImVec2& size = ImVec2(0, 0));
    static bool renderDestructiveButton(const char* label, const ImVec2& size = ImVec2(0, 0));
    static bool renderGhostButton(const char* label, const ImVec2& size = ImVec2(0, 0));

    // Progress & Status Indicators
    static void renderProgressBar(float fraction, const char* overlayText, const char* subText = nullptr);

    // Alert & Notification Banners
    static void renderBanner(const char* prefix, const char* message, const ImVec4& textColor, const ImVec4& bgColor, const ImVec4& borderColor);
    static void renderDangerBanner(const char* message);
    static void renderWarningBanner(const char* message);
    static void renderSuccessBanner(const char* message);
    static void renderInfoBanner(const char* message);

    // Formatting Helpers
    static std::string formatByteSize(uint64_t bytes);

    // Neumorphic Elevation & Sunken Shadow Effects
    static void renderCardShadow(const ImVec2& minPos, const ImVec2& maxPos, float rounding = 12.0f);
    static void renderSunkenShadow(const ImVec2& minPos, const ImVec2& maxPos, float rounding = 8.0f);

    // Responsive Fluid Layout Helpers (guarantees zero boundary overflow)
    static bool renderInputWithButton(const char* inputId, char* buffer, size_t bufferSize,
                                      const char* buttonLabel, float buttonWidth = 140.0f,
                                      bool isPassword = false, ImGuiInputTextFlags extraFlags = 0);

    static void renderInputWithTwoButtons(const char* inputId, char* buffer, size_t bufferSize,
                                          const char* btn1Label, float btn1W, bool* btn1Clicked,
                                          const char* btn2Label, float btn2W, bool* btn2Clicked,
                                          ImGuiInputTextFlags extraFlags = 0);

    static void renderResponsiveButtonPair(const char* btn1Label, bool (*btn1Func)(const char*, const ImVec2&),
                                           float btn1W, bool* btn1Clicked,
                                           const char* btn2Label, bool (*btn2Func)(const char*, const ImVec2&),
                                           float btn2W, bool* btn2Clicked,
                                           float minAvailW = 520.0f, float btnH = 36.0f);
};

} // namespace forensivault::gui
