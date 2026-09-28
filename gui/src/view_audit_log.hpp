#pragma once

#include <logging/audit_logger.hpp>
#include <vector>
#include <string>

namespace forensivault::gui {

class ViewAuditLog {
public:
    ViewAuditLog();

    void render();

private:
    void refreshLog();

    std::vector<forensivault::logging::AuditEntry> entries_;
};

} // namespace forensivault::gui
