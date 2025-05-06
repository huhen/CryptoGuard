#include <gtest/gtest.h>
#include <vector>

#include "../include/cmd_options.h"

class CmdArgsCreator {
public:
    explicit CmdArgsCreator(const std::initializer_list<std::string_view> &args)
        : strings_{args}, args_(makeArgv(strings_)) {}

    int GetArgC() const noexcept { return static_cast<int>(args_.size()); }
    char **GetArgV() const noexcept { return const_cast<char **>(args_.data()); }

private:
    std::vector<std::string_view> strings_;
    std::vector<char *> args_;

    static std::vector<char *> makeArgv(const std::vector<std::string_view> &strings) {
        std::vector<char *> result;
        result.reserve(strings.size());
        for (const auto &str : strings) {
            result.push_back(const_cast<char *>(str.data()));
        }
        return result;
    }
};

TEST(ProgramOptions, ValidEncrypt) {
    CmdArgsCreator args{"./CryptoGuard", "-i",        "input.txt", "-o", "encrypted.txt", "-p",
                        "1234",          "--command", "encrypt"};

    CryptoGuard::ProgramOptions po;
    EXPECT_TRUE(po.Parse(args.GetArgC(), args.GetArgV()));

    EXPECT_EQ(po.GetInputFile(), "input.txt");
    EXPECT_EQ(po.GetOutputFile(), "encrypted.txt");
    EXPECT_EQ(po.GetPassword(), "1234");
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, ValidDecrypt) {
    CmdArgsCreator args{"./CryptoGuard", "-i",        "encrypted.txt", "-o", "decrypted.txt", "-p",
                        "1234",          "--command", "decrypt"};

    CryptoGuard::ProgramOptions po;
    EXPECT_TRUE(po.Parse(args.GetArgC(), args.GetArgV()));

    EXPECT_EQ(po.GetInputFile(), "encrypted.txt");
    EXPECT_EQ(po.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(po.GetPassword(), "1234");
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptions, ValidChecksum) {
    CmdArgsCreator args{"./CryptoGuard", "-i", "input.txt", "--command", "checksum"};

    CryptoGuard::ProgramOptions po;
    EXPECT_TRUE(po.Parse(args.GetArgC(), args.GetArgV()));

    EXPECT_EQ(po.GetInputFile(), "input.txt");
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, ValidHelp) {
    CmdArgsCreator args{"./CryptoGuard", "--help"};

    CryptoGuard::ProgramOptions po;
    EXPECT_FALSE(po.Parse(args.GetArgC(), args.GetArgV()));
}

TEST(ProgramOptions, BadCommand) {
    CmdArgsCreator args{"./CryptoGuard", "-i", "encrypted.txt", "-o", "decrypted.txt", "-p", "1234",
                        "--command",     "bad"};

    CryptoGuard::ProgramOptions po;
    EXPECT_FALSE(po.Parse(args.GetArgC(), args.GetArgV()));
}

TEST(ProgramOptions, BadInput) {
    CmdArgsCreator args{"./CryptoGuard", "-i", "-o", "decrypted.txt", "-p", "1234", "--command", "decrypt"};

    CryptoGuard::ProgramOptions po;
    EXPECT_FALSE(po.Parse(args.GetArgC(), args.GetArgV()));
}

TEST(ProgramOptions, BadNoOutput) {
    CmdArgsCreator args{"./CryptoGuard", "-i", "encrypted.txt", "-p", "1234", "--command", "decrypt"};

    CryptoGuard::ProgramOptions po;
    EXPECT_FALSE(po.Parse(args.GetArgC(), args.GetArgV()));
}

TEST(ProgramOptions, BadDoubleOutput) {
    CmdArgsCreator args{"./CryptoGuard", "-i",        "encrypted.txt", "-o", "decrypted.txt", "-p",
                        "1234",          "--command", "decrypt",       "-o", "decrypted2.txt"};

    CryptoGuard::ProgramOptions po;
    EXPECT_FALSE(po.Parse(args.GetArgC(), args.GetArgV()));
}

TEST(ProgramOptions, BadUnknownOption) {
    CmdArgsCreator args{"./CryptoGuard", "-i",        "encrypted.txt", "-o", "decrypted.txt", "-p",
                        "1234",          "--command", "decrypt",       "-e", "decrypted2.txt"};

    CryptoGuard::ProgramOptions po;
    EXPECT_FALSE(po.Parse(args.GetArgC(), args.GetArgV()));
}