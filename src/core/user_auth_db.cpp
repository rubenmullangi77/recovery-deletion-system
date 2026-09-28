#include "core/user_auth_db.hpp"
#include "forensivault/common/crypto_hash.hpp"
#include "forensivault/core/platform.hpp"
#include "logging/audit_logger.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <ctime>
#include <cctype>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;

namespace forensivault::core {

namespace {

std::string bytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

} // anonymous namespace

UserAuthDB& UserAuthDB::getInstance() {
    static UserAuthDB instance;
    return instance;
}

std::string UserAuthDB::getDefaultDbPath() {
    Platform::ensureConfigDirectories();
    return (fs::path(Platform::getConfigDirectory()) / "users.db").string();
}

UserAuthDB::UserAuthDB(const std::string& customPath) {
    if (customPath.empty()) {
        dbPath_ = getDefaultDbPath();
    } else {
        dbPath_ = customPath;
    }
    load();
}

std::string UserAuthDB::currentTimestampIso() {
    return logging::AuditLogger::currentTimestampIso();
}

int64_t UserAuthDB::currentEpochSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string UserAuthDB::computeChecksum(const UserRecord& rec) const {
    std::string data = rec.username + "|" + rec.role + "|" + rec.salt_hex + "|" + rec.hash_hex;
    return CryptoHash::sha256(data);
}

bool UserAuthDB::validatePasswordComplexity(const std::string& password, std::string* reason) {
    if (password.length() < 8) {
        if (reason) *reason = "Password must be at least 8 characters in length.";
        return false;
    }

    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;

    for (char c : password) {
        if (std::isupper(static_cast<unsigned char>(c))) hasUpper = true;
        else if (std::islower(static_cast<unsigned char>(c))) hasLower = true;
        else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit = true;
        else hasSpecial = true;
    }

    if (!hasUpper) {
        if (reason) *reason = "Password must contain at least one uppercase letter (A-Z).";
        return false;
    }
    if (!hasLower) {
        if (reason) *reason = "Password must contain at least one lowercase letter (a-z).";
        return false;
    }
    if (!hasDigit) {
        if (reason) *reason = "Password must contain at least one numerical digit (0-9).";
        return false;
    }
    if (!hasSpecial) {
        if (reason) *reason = "Password must contain at least one special character (!@#$%^&*...).";
        return false;
    }

    return true;
}

bool UserAuthDB::load() {
    std::lock_guard<std::mutex> lock(mutex_);
    users_.clear();

    if (!fs::exists(dbPath_)) {
        return true; // Clean state on fresh install
    }

    std::ifstream ifs(dbPath_);
    if (!ifs.is_open()) return false;

    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty() || line[0] == '#') continue;

        // Format: USER:<username>|<role>|<salt>|<hash>|<created>|<last_login>|<failed_attempts>|<locked_until>|<chk>
        if (line.rfind("USER:", 0) != 0) continue;
        std::string payload = line.substr(5);

        std::vector<std::string> parts;
        std::stringstream ss(payload);
        std::string part;
        while (std::getline(ss, part, '|')) {
            parts.push_back(part);
        }

        if (parts.size() >= 8) {
            UserRecord u;
            u.username = parts[0];
            u.role = parts[1];
            u.salt_hex = parts[2];
            u.hash_hex = parts[3];
            u.created_timestamp_iso = parts[4];
            u.last_login_timestamp_iso = parts[5];
            try {
                u.failed_attempts = static_cast<uint32_t>(std::stoul(parts[6]));
                u.locked_until_epoch = std::stoll(parts[7]);
            } catch (...) {
                u.failed_attempts = 0;
                u.locked_until_epoch = 0;
            }

            // Verify integrity checksum if present
            if (parts.size() >= 9) {
                std::string expectedChk = computeChecksum(u);
                if (!CryptoHash::constantTimeEquals(parts[8], expectedChk)) {
                    // Checksum mismatch: entry has been tampered with
                    continue;
                }
            }

            users_.push_back(u);
        }
    }

    return true;
}

bool UserAuthDB::save() {
    std::error_code ec;
    fs::path parent = fs::path(dbPath_).parent_path();
    fs::create_directories(parent, ec);

    std::string tmpPath = dbPath_ + ".tmp";
    std::ofstream ofs(tmpPath, std::ios::out | std::ios::trunc);
    if (!ofs.is_open()) return false;

    ofs << "# ForensiVault Cryptographic User Database v1.0\n";
    ofs << "# CONFIDENTIAL: Stored strictly in user config directory with 0600 permissions\n";
    ofs << "# Format: USER:<username>|<role>|<salt>|<hash>|<created>|<last_login>|<failed>|<locked_until>|<checksum>\n\n";

    for (const auto& u : users_) {
        std::string chk = computeChecksum(u);
        ofs << "USER:"
            << u.username << "|"
            << u.role << "|"
            << u.salt_hex << "|"
            << u.hash_hex << "|"
            << u.created_timestamp_iso << "|"
            << u.last_login_timestamp_iso << "|"
            << u.failed_attempts << "|"
            << u.locked_until_epoch << "|"
            << chk << "\n";
    }
    ofs.flush();
    ofs.close();

#if !defined(_WIN32)
    // Enforce strict file permissions 0600 (owner read/write only)
    ::chmod(tmpPath.c_str(), S_IRUSR | S_IWUSR);
#endif

    // Atomic replacement
    fs::rename(tmpPath, dbPath_, ec);
    if (ec) {
        fs::copy_file(tmpPath, dbPath_, fs::copy_options::overwrite_existing, ec);
        fs::remove(tmpPath, ec);
    }

#if !defined(_WIN32)
    ::chmod(dbPath_.c_str(), S_IRUSR | S_IWUSR);
#endif

    return true;
}

bool UserAuthDB::hasUsers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !users_.empty();
}

size_t UserAuthDB::userCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return users_.size();
}

std::vector<UserRecord> UserAuthDB::listUsers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return users_;
}

bool UserAuthDB::userExists(const std::string& username) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& u : users_) {
        if (u.username == username) return true;
    }
    return false;
}

AuthResult UserAuthDB::authenticate(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(mutex_);
    AuthResult res;

    int64_t now = currentEpochSeconds();
    UserRecord* foundUser = nullptr;

    for (auto& u : users_) {
        if (u.username == username) {
            foundUser = &u;
            break;
        }
    }

    if (!foundUser) {
        res.status = AuthStatus::USER_NOT_FOUND;
        res.message = "Authentication failed: User does not exist.";
        // Mitigate user enumeration timing attack by performing dummy PBKDF2 hash computation
        CryptoHash::pbkdf2Sha256(password, "dummy_salt_for_timing_mitigation_32bytes", 100000);
        return res;
    }

    // Check account lockout
    if (foundUser->locked_until_epoch > now) {
        res.status = AuthStatus::ACCOUNT_LOCKED;
        res.lockRemainingSeconds = static_cast<int>(foundUser->locked_until_epoch - now);
        res.message = "Account locked due to consecutive failed attempts. Retry in " +
                      std::to_string(res.lockRemainingSeconds) + " seconds.";
        return res;
    }

    // Derive password hash using user's stored salt
    std::string candidateHash = CryptoHash::pbkdf2Sha256(password, foundUser->salt_hex, 100000);

    if (CryptoHash::constantTimeEquals(candidateHash, foundUser->hash_hex)) {
        // Success
        foundUser->failed_attempts = 0;
        foundUser->locked_until_epoch = 0;
        foundUser->last_login_timestamp_iso = currentTimestampIso();
        save();

        res.status = AuthStatus::SUCCESS;
        res.message = "Authentication successful.";
        res.user = *foundUser;

        // Log forensic authentication success
        logging::AuditLogger::getInstance().logEvent(
            "USER_LOGIN", "SECURE_AUTH_VAULT", "PBKDF2-HMAC-SHA256", "SUCCESS",
            "Examiner '" + username + "' (" + foundUser->role + ") successfully authenticated.");
    } else {
        // Password mismatch
        foundUser->failed_attempts++;
        if (foundUser->failed_attempts >= 5) {
            foundUser->locked_until_epoch = now + 60; // 60 second lockout
            res.status = AuthStatus::ACCOUNT_LOCKED;
            res.lockRemainingSeconds = 60;
            res.message = "Too many failed attempts. Account locked for 60 seconds.";
        } else {
            res.status = AuthStatus::INVALID_CREDENTIALS;
            res.message = "Authentication failed: Invalid password (" +
                          std::to_string(5 - foundUser->failed_attempts) + " attempts remaining before lockout).";
        }
        save();

        // Log forensic authentication failure
        logging::AuditLogger::getInstance().logEvent(
            "USER_LOGIN_FAILED", "SECURE_AUTH_VAULT", "PBKDF2-HMAC-SHA256", "FAILED",
            "Failed login attempt for user '" + username + "'. Consecutive failures: " +
            std::to_string(foundUser->failed_attempts));
    }

    return res;
}

bool UserAuthDB::registerUser(const std::string& username, const std::string& password,
                              const std::string& role, std::string* errorMsg) {
    if (username.empty() || username.length() < 3) {
        if (errorMsg) *errorMsg = "Username must be at least 3 characters long.";
        return false;
    }

    // Check for valid alphanumeric username
    for (char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
            if (errorMsg) *errorMsg = "Username can only contain alphanumeric characters, underscores, and dashes.";
            return false;
        }
    }

    std::string complexityReason;
    if (!validatePasswordComplexity(password, &complexityReason)) {
        if (errorMsg) *errorMsg = complexityReason;
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& u : users_) {
        if (u.username == username) {
            if (errorMsg) *errorMsg = "User '" + username + "' already exists.";
            return false;
        }
    }

    // Generate 32 bytes CSPRNG salt
    uint8_t saltBytes[32];
    if (!Platform::getRandomBytes(saltBytes, sizeof(saltBytes))) {
        if (errorMsg) *errorMsg = "Internal error: Failed to obtain cryptographically secure random salt.";
        return false;
    }
    std::string saltHex = bytesToHex(saltBytes, sizeof(saltBytes));

    // Derive PBKDF2 hash (100,000 rounds)
    std::string hashHex = CryptoHash::pbkdf2Sha256(password, saltHex, 100000);

    UserRecord newRec;
    newRec.username = username;
    newRec.role = role.empty() ? "Forensic Examiner" : role;
    newRec.salt_hex = saltHex;
    newRec.hash_hex = hashHex;
    newRec.created_timestamp_iso = currentTimestampIso();
    newRec.last_login_timestamp_iso = "NEVER";
    newRec.failed_attempts = 0;
    newRec.locked_until_epoch = 0;

    users_.push_back(newRec);
    bool ok = save();

    if (ok) {
        logging::AuditLogger::getInstance().logEvent(
            "USER_REGISTERED", "SECURE_AUTH_VAULT", "PBKDF2-HMAC-SHA256", "SUCCESS",
            "New forensic user '" + username + "' (" + newRec.role + ") enrolled.");
    } else {
        if (errorMsg) *errorMsg = "Failed to persist user to database on disk.";
    }

    return ok;
}

bool UserAuthDB::changePassword(const std::string& username, const std::string& oldPassword,
                                const std::string& newPassword, std::string* errorMsg) {
    std::string complexityReason;
    if (!validatePasswordComplexity(newPassword, &complexityReason)) {
        if (errorMsg) *errorMsg = complexityReason;
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& u : users_) {
        if (u.username == username) {
            std::string oldHash = CryptoHash::pbkdf2Sha256(oldPassword, u.salt_hex, 100000);
            if (!CryptoHash::constantTimeEquals(oldHash, u.hash_hex)) {
                if (errorMsg) *errorMsg = "Current password is incorrect.";
                return false;
            }

            // Generate fresh salt
            uint8_t saltBytes[32];
            Platform::getRandomBytes(saltBytes, sizeof(saltBytes));
            u.salt_hex = bytesToHex(saltBytes, sizeof(saltBytes));
            u.hash_hex = CryptoHash::pbkdf2Sha256(newPassword, u.salt_hex, 100000);
            u.failed_attempts = 0;
            u.locked_until_epoch = 0;
            return save();
        }
    }

    if (errorMsg) *errorMsg = "User not found.";
    return false;
}

void UserAuthDB::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    users_.clear();
    std::error_code ec;
    fs::remove(dbPath_, ec);
}

} // namespace forensivault::core
