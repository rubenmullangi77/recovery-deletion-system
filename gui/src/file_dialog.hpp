#pragma once

#include <string>

namespace forensivault::gui {

class FileDialog {
public:
    /**
     * @brief Opens a system native dialog to select a single file.
     * @param title Title of the dialog window.
     * @param filterDesc Description of file types, e.g. "Disk Images (*.img;*.dd;*.raw)"
     * @param filterExt Extension pattern, e.g. "*.img;*.dd;*.raw;*.*"
     * @return Absolute path of selected file, or empty string if canceled.
     */
    static std::string openFile(const std::string& title = "Select File",
                                const std::string& filterDesc = "All Files (*.*)",
                                const std::string& filterExt = "*.*");

    /**
     * @brief Opens a system native dialog to select a directory/folder.
     * @param title Title of the dialog window.
     * @return Absolute path of selected directory, or empty string if canceled.
     */
    static std::string openFolder(const std::string& title = "Select Folder");

    /**
     * @brief Opens a system native dialog to select a save file path.
     * @param title Title of the dialog window.
     * @param defaultFileName Default file name suggested in dialog.
     * @param filterDesc Description of file types.
     * @param filterExt Extension pattern.
     * @return Absolute path of save destination, or empty string if canceled.
     */
    static std::string saveFile(const std::string& title = "Save File As",
                                const std::string& defaultFileName = "export.jsonl",
                                const std::string& filterDesc = "All Files (*.*)",
                                const std::string& filterExt = "*.*");

    static void openFolderInExplorer(const std::string& folderPath);
};

} // namespace forensivault::gui
