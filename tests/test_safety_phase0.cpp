#include "test_framework.hpp"
#include "forensivault/core/platform.hpp"
#include "sanitization/system_protection.hpp"
#include "sanitization/sanitization_types.hpp"
#include <fstream>
#include <filesystem>
#include <cstdlib>

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace forensivault;
using namespace forensivault::sanitization;

FV_TEST(SafetyPhase0, ElevationTokenCannotModifyOrTruncateFiles) {
    // 1. Create a sensitive dummy file with non-zero content
    fs::path tempDir = fs::temp_directory_path() / "fv_elev_test";
    fs::create_directories(tempDir);
    fs::path targetFile = tempDir / "sensitive_system_target.txt";

    const std::string originalContent = "CRITICAL_SYSTEM_DATA_DO_NOT_TRUNCATE_987654321";
    {
        std::ofstream ofs(targetFile, std::ios::binary | std::ios::trunc);
        ofs << originalContent;
    }

    std::error_code ec;
    uint64_t initialSize = fs::file_size(targetFile, ec);
    ASSERT_EQ(initialSize, originalContent.size());

    // 2. Point FORENSIVAULT_ELEV_TOKEN at our target file
#if defined(_WIN32)
    _putenv_s("FORENSIVAULT_ELEV_TOKEN", targetFile.string().c_str());
#else
    setenv("FORENSIVAULT_ELEV_TOKEN", targetFile.string().c_str(), 1);
#endif

    // 3. Call Platform::isElevated()
    bool elevated = core::Platform::isElevated();
    (void)elevated;

    // 4. Verify file was NOT modified, truncated, deleted, or touched
    ASSERT_TRUE(fs::exists(targetFile, ec));
    uint64_t postSize = fs::file_size(targetFile, ec);
    ASSERT_EQ(postSize, originalContent.size());

    std::string postContent;
    {
        std::ifstream ifs(targetFile, std::ios::binary);
        std::getline(ifs, postContent);
    }
    ASSERT_EQ(postContent, originalContent);

    // Clean up
#if defined(_WIN32)
    _putenv_s("FORENSIVAULT_ELEV_TOKEN", "");
#else
    unsetenv("FORENSIVAULT_ELEV_TOKEN");
#endif
    fs::remove_all(tempDir, ec);
}

FV_TEST(SafetyPhase0, SystemProtectionBlocksAttackerBypassNames) {
    std::string reason;

    // Attacker attempting to bypass system protection with FORENSIVAULT_TEST_DELETE
    ASSERT_TRUE(SystemProtectionGuard::isProtected("/etc/FORENSIVAULT_TEST_DELETE", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("/etc/FORENSIVAULT_TEST_DELETE/shadow", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\Windows\\FORENSIVAULT_TEST_DELETE", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\Windows\\System32\\FORENSIVAULT_TEST_DELETE\\kernel32.dll", reason));

    // Attacker attempting to bypass system protection with TEST_DATA/DISPOSABLE
    ASSERT_TRUE(SystemProtectionGuard::isProtected("/bin/TEST_DATA/DISPOSABLE", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("/usr/bin/TEST_DATA/DISPOSABLE/bash", reason));
    ASSERT_TRUE(SystemProtectionGuard::isProtected("C:\\Program Files\\TEST_DATA\\DISPOSABLE", reason));

    // Application binary self-deletion must be blocked
    std::string exePath = core::Platform::getExecutablePath();
    if (!exePath.empty()) {
        ASSERT_TRUE(SystemProtectionGuard::isProtected(exePath, reason));
    }

    // Legitimate user workspace file should be permitted
    ASSERT_FALSE(SystemProtectionGuard::isProtected("user_workspace/documents/notes.txt", reason));
}

FV_TEST(SafetyPhase0, TargetObjectModelClassificationAndIdentity) {
    // 1. Classification
    ASSERT_EQ(probeTargetType("/dev/sda"), TargetType::PHYSICAL_BLOCK_DEVICE);
    ASSERT_EQ(probeTargetType("/dev/nvme0n1"), TargetType::PHYSICAL_BLOCK_DEVICE);
    ASSERT_EQ(probeTargetType("\\\\.\\PhysicalDrive0"), TargetType::PHYSICAL_BLOCK_DEVICE);

    ASSERT_EQ(probeTargetType("case1/image.raw"), TargetType::DISK_IMAGE);
    ASSERT_EQ(probeTargetType("case1/image.img"), TargetType::DISK_IMAGE);
    ASSERT_EQ(probeTargetType("case1/image.dd"), TargetType::DISK_IMAGE);

    ASSERT_EQ(probeTargetType("user/document.pdf"), TargetType::REGULAR_FILE);
    ASSERT_EQ(probeTargetType("user/data.bin"), TargetType::DISK_IMAGE); // .bin is container image

    // 2. Identity capture on real file
    fs::path tempDir = fs::temp_directory_path() / "fv_identity_test";
    fs::create_directories(tempDir);
    fs::path testFile1 = tempDir / "file1.txt";
    fs::path testFile2 = tempDir / "file2.txt";

    {
        std::ofstream ofs1(testFile1);
        ofs1 << "DATA_FILE_1";
        std::ofstream ofs2(testFile2);
        ofs2 << "DATA_FILE_2";
    }

#if !defined(_WIN32)
    int fd1 = ::open(testFile1.c_str(), O_RDONLY);
    ASSERT_TRUE(fd1 >= 0);
    auto id1 = captureIdentityFromFd(fd1, testFile1.string(), TargetType::REGULAR_FILE);
    ::close(fd1);

    int fd1_again = ::open(testFile1.c_str(), O_RDONLY);
    ASSERT_TRUE(fd1_again >= 0);
    auto id1_again = captureIdentityFromFd(fd1_again, testFile1.string(), TargetType::REGULAR_FILE);
    ::close(fd1_again);

    int fd2 = ::open(testFile2.c_str(), O_RDONLY);
    ASSERT_TRUE(fd2 >= 0);
    auto id2 = captureIdentityFromFd(fd2, testFile2.string(), TargetType::REGULAR_FILE);
    ::close(fd2);

    ASSERT_TRUE(id1.valid);
    ASSERT_TRUE(id1_again.valid);
    ASSERT_TRUE(id2.valid);

    // Matching same file
    ASSERT_TRUE(id1.matches(id1_again));
    // Different file must NOT match
    ASSERT_FALSE(id1.matches(id2));

    // Test size-invariance of TargetIdentity:
    // Truncate testFile1: mutable size changes, but inode/device identity remains identical
    {
        std::ofstream ofs_trunc(testFile1, std::ios::trunc);
        ofs_trunc << "X"; // 1 byte instead of DATA_FILE_1 (11 bytes)
    }
    int fd1_trunc = ::open(testFile1.c_str(), O_RDONLY);
    ASSERT_TRUE(fd1_trunc >= 0);
    auto id1_trunc = captureIdentityFromFd(fd1_trunc, testFile1.string(), TargetType::REGULAR_FILE);
    ::close(fd1_trunc);

    ASSERT_TRUE(id1_trunc.valid);
    ASSERT_NE(id1.size_bytes, id1_trunc.size_bytes);
    // Identity comparison MUST succeed despite mutable size change
    ASSERT_TRUE(id1.matches(id1_trunc));
#endif

    std::error_code ec;
    fs::remove_all(tempDir, ec);
}

FV_TEST(SafetyPhase0, BlockDeviceTopologyDetectionAllTopologies) {
    fs::path tempDir = fs::temp_directory_path() / "fv_topo_test";
    fs::create_directories(tempDir);

    fs::path mockSysfs = tempDir / "sys_class_block";
    fs::create_directories(mockSysfs);

    // Helper lambda to create mock sysfs block directory
    auto createMockBlockNode = [&](const std::string& name, const std::string& parentDiskName,
                                   const std::vector<std::string>& slaves, bool isPartition) {
        fs::path nodeDir = mockSysfs / name;
        fs::create_directories(nodeDir);
        if (isPartition) {
            std::ofstream(nodeDir / "partition") << "1\n";
        }
        if (!parentDiskName.empty()) {
            // Create symlink pointing into parent disk dir
            fs::path parentDir = tempDir / "devices" / parentDiskName;
            fs::create_directories(parentDir);
            fs::path subPart = parentDir / name;
            fs::create_directories(subPart);
            std::error_code ec;
            fs::remove(nodeDir, ec);
            fs::create_directory_symlink(subPart, nodeDir, ec);
        }
        if (!slaves.empty()) {
            fs::path slavesDir = nodeDir / "slaves";
            fs::create_directories(slavesDir);
            for (const auto& slave : slaves) {
                std::error_code ec;
                fs::path slaveTarget = mockSysfs / slave;
                fs::create_directory_symlink(slaveTarget, slavesDir / slave, ec);
            }
        }
    };

    // 1. Plain disk: sda
    createMockBlockNode("sda", "", {}, false);
    // 2. Partition: sda2 -> parent sda
    createMockBlockNode("sda2", "sda", {}, true);
    // 3. NVMe disk: nvme0n1
    createMockBlockNode("nvme0n1", "", {}, false);
    // 4. NVMe partition: nvme0n1p2 -> parent nvme0n1
    createMockBlockNode("nvme0n1p2", "nvme0n1", {}, true);
    // 5. LVM volume: dm-0 with slave sda2
    createMockBlockNode("dm-0", "", {"sda2"}, false);
    // 6. LUKS volume: dm-1 with slave nvme0n1p3
    createMockBlockNode("nvme0n1p3", "nvme0n1", {}, true);
    createMockBlockNode("dm-1", "", {"nvme0n1p3"}, false);
    // 7. LVM on LUKS: dm-2 with slave dm-3, and dm-3 has slave sda4 -> sda
    createMockBlockNode("sda4", "sda", {}, true);
    createMockBlockNode("dm-3", "", {"sda4"}, false);
    createMockBlockNode("dm-2", "", {"dm-3"}, false);
    // 8. Secondary data disk: sdb (not part of root)
    createMockBlockNode("sdb", "", {}, false);
    createMockBlockNode("sdb1", "sdb", {}, true);

    // Test Case 1: Plain disk / partition root (/dev/sda2 mounted as /)
    {
        fs::path mounts1 = tempDir / "mounts_plain.txt";
        std::ofstream(mounts1) << "/dev/sda2 / ext4 rw 0 0\n";
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/sda", mounts1.string(), mockSysfs.string()));
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/sda2", mounts1.string(), mockSysfs.string()));
        ASSERT_FALSE(core::Platform::isMainSystemDrive("/dev/sdb", mounts1.string(), mockSysfs.string()));
    }

    // Test Case 2: NVMe root (/dev/nvme0n1p2 mounted as /)
    {
        fs::path mounts2 = tempDir / "mounts_nvme.txt";
        std::ofstream(mounts2) << "/dev/nvme0n1p2 / ext4 rw 0 0\n";
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/nvme0n1", mounts2.string(), mockSysfs.string()));
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/nvme0n1p2", mounts2.string(), mockSysfs.string()));
        ASSERT_FALSE(core::Platform::isMainSystemDrive("/dev/sdb", mounts2.string(), mockSysfs.string()));
    }

    // Test Case 3: LVM root (/dev/dm-0 mounted as /)
    {
        fs::path mounts3 = tempDir / "mounts_lvm.txt";
        std::ofstream(mounts3) << "/dev/dm-0 / ext4 rw 0 0\n";
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/sda", mounts3.string(), mockSysfs.string()));
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/sda2", mounts3.string(), mockSysfs.string()));
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/dm-0", mounts3.string(), mockSysfs.string()));
        ASSERT_FALSE(core::Platform::isMainSystemDrive("/dev/sdb", mounts3.string(), mockSysfs.string()));
    }

    // Test Case 4: LUKS root (/dev/dm-1 mounted as /)
    {
        fs::path mounts4 = tempDir / "mounts_luks.txt";
        std::ofstream(mounts4) << "/dev/dm-1 / ext4 rw 0 0\n";
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/nvme0n1", mounts4.string(), mockSysfs.string()));
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/nvme0n1p3", mounts4.string(), mockSysfs.string()));
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/dm-1", mounts4.string(), mockSysfs.string()));
        ASSERT_FALSE(core::Platform::isMainSystemDrive("/dev/sdb", mounts4.string(), mockSysfs.string()));
    }

    // Test Case 5: LVM-on-LUKS root (/dev/dm-2 mounted as /)
    {
        fs::path mounts5 = tempDir / "mounts_nested.txt";
        std::ofstream(mounts5) << "/dev/dm-2 / ext4 rw 0 0\n";
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/sda", mounts5.string(), mockSysfs.string()));
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/sda4", mounts5.string(), mockSysfs.string()));
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/dm-2", mounts5.string(), mockSysfs.string()));
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/dm-3", mounts5.string(), mockSysfs.string()));
        ASSERT_FALSE(core::Platform::isMainSystemDrive("/dev/sdb", mounts5.string(), mockSysfs.string()));
    }

    // Test Case 6: Fail-closed on missing / unreadable mounts
    {
        fs::path nonExistentMounts = tempDir / "does_not_exist.txt";
        ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/sdb", nonExistentMounts.string(), mockSysfs.string()));
    }

    std::error_code ec;
    fs::remove_all(tempDir, ec);
}

FV_TEST(SafetyPhase0, BlockDeviceTopologyCyclicTermination) {
    fs::path tempDir = fs::temp_directory_path() / "fv_cyclic_topo_test";
    fs::create_directories(tempDir);
    fs::path mockSysfs = tempDir / "sys_class_block";
    fs::create_directories(mockSysfs);

    // Create cyclic block topology:
    // nodeA has slave nodeB
    // nodeB has slave nodeA (mutual cycle)
    // nodeC has slave nodeC (self cycle)
    fs::path nodeA = mockSysfs / "loopA";
    fs::path nodeB = mockSysfs / "loopB";
    fs::path nodeC = mockSysfs / "loopC";
    fs::create_directories(nodeA / "slaves");
    fs::create_directories(nodeB / "slaves");
    fs::create_directories(nodeC / "slaves");

    std::error_code ec;
    fs::create_directory_symlink(nodeB, nodeA / "slaves" / "loopB", ec);
    fs::create_directory_symlink(nodeA, nodeB / "slaves" / "loopA", ec);
    fs::create_directory_symlink(nodeC, nodeC / "slaves" / "loopC", ec);

    // Traversal of mutual cyclic topology must terminate cleanly without stack overflow
    std::set<std::string> outDisksAB;
    core::Platform::resolveBlockDeviceSlaves("loopA", outDisksAB, mockSysfs.string());
    ASSERT_TRUE(outDisksAB.count("loopA") > 0);
    ASSERT_TRUE(outDisksAB.count("loopB") > 0);
    ASSERT_TRUE(outDisksAB.count("/dev/loopA") > 0);
    ASSERT_TRUE(outDisksAB.count("/dev/loopB") > 0);

    // Traversal of self-cyclic node must also terminate cleanly
    std::set<std::string> outDisksC;
    core::Platform::resolveBlockDeviceSlaves("loopC", outDisksC, mockSysfs.string());
    ASSERT_TRUE(outDisksC.count("loopC") > 0);
    ASSERT_TRUE(outDisksC.count("/dev/loopC") > 0);

    // System drive detection over cyclic topology must terminate safely
    fs::path mounts = tempDir / "mounts.txt";
    std::ofstream(mounts) << "/dev/loopA / ext4 rw 0 0\n";
    ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/loopB", mounts.string(), mockSysfs.string()));
    ASSERT_TRUE(core::Platform::isMainSystemDrive("/dev/loopA", mounts.string(), mockSysfs.string()));

    fs::remove_all(tempDir, ec);
}

FV_TEST(SafetyPhase0, HardlinkTargetIndistinguishableFromO_NOFOLLOW) {
    fs::path tempDir = fs::temp_directory_path() / "fv_hardlink_test";
    fs::create_directories(tempDir);
    fs::path originFile = tempDir / "sensitive_origin.txt";
    fs::path hardlinkFile = tempDir / "innocent_hardlink.txt";

    {
        std::ofstream ofs(originFile);
        ofs << "CRITICAL_COLLATERAL_DATA_DO_NOT_CORRUPT";
    }

    std::error_code ec;
    fs::create_hard_link(originFile, hardlinkFile, ec);
    ASSERT_FALSE(ec);

#if !defined(_WIN32)
    // 1. Attacker or unsuspecting caller opens via O_NOFOLLOW
    // O_NOFOLLOW ONLY detects symlinks; it does NOT reject hardlinks!
    int fd = ::open(hardlinkFile.c_str(), O_RDWR | O_NOFOLLOW);
    ASSERT_TRUE(fd >= 0);

    // 2. Query object identity via fd
    auto id_link = captureIdentityFromFd(fd, hardlinkFile.string(), TargetType::REGULAR_FILE);
    ::close(fd);

    ASSERT_TRUE(id_link.valid);
    // 3. Demonstrate that O_NOFOLLOW did NOT reject it, but hard_link_count is > 1
    ASSERT_TRUE(id_link.hard_link_count > 1);

    // 4. Inode and device match the origin file (shared underlying data blocks)
    int fd_orig = ::open(originFile.c_str(), O_RDONLY);
    ASSERT_TRUE(fd_orig >= 0);
    auto id_orig = captureIdentityFromFd(fd_orig, originFile.string(), TargetType::REGULAR_FILE);
    ::close(fd_orig);

    ASSERT_TRUE(id_orig.valid);
    ASSERT_TRUE(id_link.matches(id_orig));

    // 5. This test locks in the Phase 1 invariant:
    // Destructive sanitization must inspect fd hard_link_count == 1 and fail closed
    // if hard_link_count > 1 to prevent destructive overwriting of shared inodes.
#endif

    fs::remove_all(tempDir, ec);
}

