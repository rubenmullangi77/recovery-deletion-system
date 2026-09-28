#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <cstdint>
#include <chrono>

namespace forensivault::core {

struct UserRecord {
    std::string username;
    std::string role;                      // "Forensic Examiner", "Administrator", "Auditor"
    std::string salt_hex;                  // 32-byte CSPRNG random salt (64 hex characters)
    std::string hash_hex;                  // PBKDF2-HMAC-SHA256 (100,000 iterations)
    std::string created_timestamp_iso;
    std::string last_login_timestamp_iso;
    uint32_t failed_attempts = 0;
    int64_t locked_until_epoch = 0;        // Unix epoch timestamp in seconds
};

enum class AuthStatus {
    SUCCESS,
    INVALID_CREDENTIALS,
    ACCOUNT_LOCKED,
    USER_NOT_FOUND,
    INTERNAL_ERROR
};

struct AuthResult {
    AuthStatus status = AuthStatus::INVALID_CREDENTIALS;
    std::string message;
    int lockRemainingSeconds = 0;
    UserRecord user;
};

class UserAuthDB {
public:
    explicit UserAuthDB(const std::string& customPath = "");
    ~UserAuthDB() = default;

    // Singleton access for application-wide session management
    static UserAuthDB& getInstance();

    // Resolves default DB path: ~/.config/forensicvault/users.db or %APPDATA%\forensicvault\users.db
    static std::string getDefaultDbPath();

    // Password complexity requirements: >=8 chars, uppercase, lowercase, number, special char
    static bool validatePasswordComplexity(const std::string& password, std::string* reason = nullptr);

    // Initialization & persistence
    bool load();
    bool save();

    // Query state
    bool hasUsers() const;
    size_t userCount() const;
    std::vector<UserRecord> listUsers() const;
    bool userExists(const std::string& username) const;

    // Authentication & Enrollment
    AuthResult authenticate(const std::string& username, const std::string& password);
    bool registerUser(const std::string& username, const std::string& password,
                      const std::string& role, std::string* errorMsg = nullptr);
    bool changePassword(const std::string& username, const std::string& oldPassword,
                        const std::string& newPassword, std::string* errorMsg = nullptr);

    // Maintenance / Reset
    void clear();

private:
    std::string dbPath_;
    mutable std::mutex mutex_;
    std::vector<UserRecord> users_;

    static std::string currentTimestampIso();
    static int64_t currentEpochSeconds();
    std::string computeChecksum(const UserRecord& rec) const;
};

} // namespace forensivault::core
