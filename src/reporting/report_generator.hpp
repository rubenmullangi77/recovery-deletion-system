#pragma once

#include "reporting/report_types.hpp"
#include <string>

namespace forensivault {
namespace reporting {

struct ReportPackageResult {
    bool json_saved = false;
    bool html_saved = false;
    bool pdf_saved = false;
    std::string json_path;
    std::string html_path;
    std::string pdf_path;
    std::string error_message;
};

class ReportGenerator {
public:
    /**
     * @brief Generate structured, court-admissible JSON report.
     */
    static std::string generateJson(const ForensicReport& report);

    /**
     * @brief Generate self-contained, human-readable HTML forensic report with print styling.
     */
    static std::string generateHtml(const ForensicReport& report);

    /**
     * @brief Generate vector PDF from HTML report using Microsoft Edge headless engine.
     */
    static bool generatePdf(const std::string& htmlPath, const std::string& pdfOutputPath);

    /**
     * @brief Compiles and writes the complete forensic report package (JSON, HTML, and PDF).
     */
    static ReportPackageResult saveReportPackage(const ForensicReport& report,
                                                const std::string& outputDirectory,
                                                bool generatePdfCopy = true);

private:
    static std::string escapeHtml(const std::string& s);
    static std::string escapeJson(const std::string& s);
};

} // namespace reporting
} // namespace forensivault
