#pragma once

#include <string>

namespace forensivault::gui {

class ViewLogin {
public:
    ViewLogin();
    ~ViewLogin() = default;

    void render();
    void resetFields();

private:
    char usernameBuffer_[128] = {0};
    char passwordBuffer_[128] = {0};
    char confirmPasswordBuffer_[128] = {0};
    int selectedRoleIndex_ = 0;

    std::string errorMessage_;
    std::string statusMessage_;
    int lockoutSecondsRemaining_ = 0;
    bool isEnrollmentMode_ = false;

    void handleLogin();
    void handleEnrollment();
};

} // namespace forensivault::gui
