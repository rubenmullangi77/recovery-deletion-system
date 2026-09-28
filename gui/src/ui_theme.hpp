#pragma once

#include <imgui.h>
#include <string>

namespace forensivault::gui {

class UITheme {
public:
    static void applyNeumorphicCreamTheme();
    static void applyForensicDarkTheme() { applyNeumorphicCreamTheme(); } // Alias for compatibility
    static void loadFonts(ImGuiIO& io);

    // Font Pointers
    static ImFont* fontRegular;
    static ImFont* fontBold;
    static ImFont* fontHeader;
    static ImFont* fontMono;
    static ImFont* fontSmall;

    // Minimalist Cream & Orange Palette Constants
    static const ImVec4 COLOR_CREAM_BG;        // Base window canvas
    static const ImVec4 COLOR_CREAM_CARD;      // Elevated neumorphic card surface
    static const ImVec4 COLOR_CREAM_INSET;     // Sunken wells for inputs & tables
    static const ImVec4 COLOR_CARD_BORDER;     // Crisp 1px card boundary
    static const ImVec4 COLOR_SHADOW_LIGHT;    // Soft top-left highlight
    static const ImVec4 COLOR_SHADOW_DARK;     // Soft bottom-right ambient shadow

    static const ImVec4 COLOR_ORANGE;          // Radiant warm orange brand accent
    static const ImVec4 COLOR_ORANGE_HOVER;    // Lighter orange for hover states
    static const ImVec4 COLOR_ORANGE_ACTIVE;   // Deeper pressed orange
    static const ImVec4 COLOR_ORANGE_TINT;     // Translucent orange wash for pills & tabs
    static const ImVec4 COLOR_CYAN;            // Maps to Orange for harmony

    static const ImVec4 COLOR_TEXT_PRIMARY;    // High-contrast deep espresso (#1C1917)
    static const ImVec4 COLOR_TEXT_SECONDARY;  // Muted taupe stone (#57534E)
    static const ImVec4 COLOR_TEXT_MUTED;      // Muted caption (#8A8175)
    static const ImVec4 COLOR_BG_PANEL;        // Alias for COLOR_CREAM_CARD

    // Semantic Status Colors
    static const ImVec4 COLOR_GREEN;           // Emerald Forest (#16A34A)
    static const ImVec4 COLOR_GREEN_TINT;
    static const ImVec4 COLOR_YELLOW;          // Amber Warning (#D97706)
    static const ImVec4 COLOR_YELLOW_TINT;
    static const ImVec4 COLOR_RED;             // Crimson Destructive (#DC2626)
    static const ImVec4 COLOR_RED_TINT;
    static const ImVec4 COLOR_BLUE;            // Forensic Info Sky (#0284C7)
    static const ImVec4 COLOR_BLUE_TINT;

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
    static void renderDangerBanner(const char* message);
    static void renderWarningBanner(const char* message);
    static void renderSuccessBanner(const char* message);
    static void renderInfoBanner(const char* message);

    // Card Shadow Effect
    static void renderCardShadow(const ImVec2& minPos, const ImVec2& maxPos, float rounding = 12.0f);
};

} // namespace forensivault::gui
