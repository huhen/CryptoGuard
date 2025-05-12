#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>

#include "../include/cmd_options.h"

TEST(ProgramOptions, ValidEncrypt) {
    std::vector<const char *> args{"./CryptoGuard", "-i",        "input.txt", "-o", "encrypted.txt", "-p",
                                   "1234",          "--command", "encrypt"};

    CryptoGuard::ProgramOptions po;
    EXPECT_TRUE(po.Parse(args.size(), const_cast<char **>(args.data())));

    EXPECT_EQ(po.GetInputFile(), "input.txt");
    EXPECT_EQ(po.GetOutputFile(), "encrypted.txt");
    EXPECT_EQ(po.GetPassword(), "1234");
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, ValidDecrypt) {
    std::vector<const char *> args{"./CryptoGuard", "-i",        "encrypted.txt", "-o", "decrypted.txt", "-p",
                                   "1234",          "--command", "decrypt"};

    CryptoGuard::ProgramOptions po;
    EXPECT_TRUE(po.Parse(args.size(), const_cast<char **>(args.data())));

    EXPECT_EQ(po.GetInputFile(), "encrypted.txt");
    EXPECT_EQ(po.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(po.GetPassword(), "1234");
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptions, ValidChecksum) {
    std::vector<const char *> args{"./CryptoGuard", "-i", "input.txt", "--command", "checksum"};

    CryptoGuard::ProgramOptions po;
    EXPECT_TRUE(po.Parse(args.size(), const_cast<char **>(args.data())));

    EXPECT_EQ(po.GetInputFile(), "input.txt");
    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, ValidHelp) {
    std::vector<const char *> args{"./CryptoGuard", "--help"};

    CryptoGuard::ProgramOptions po;
    EXPECT_FALSE(po.Parse(args.size(), const_cast<char **>(args.data())));
}

TEST(ProgramOptions, BadCommand) {
    std::vector<const char *> args{"./CryptoGuard", "-i", "encrypted.txt", "-o", "decrypted.txt", "-p", "1234",
                                   "--command",     "bad"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THROW(po.Parse(args.size(), const_cast<char **>(args.data())), std::invalid_argument);
}

TEST(ProgramOptions, BadInput) {
    std::vector<const char *> args{"./CryptoGuard", "-i", "-o", "decrypted.txt", "-p", "1234", "--command", "decrypt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THROW(po.Parse(args.size(), const_cast<char **>(args.data())),
                 boost::program_options::invalid_command_line_syntax);
}

TEST(ProgramOptions, BadNoOutput) {
    std::vector<const char *> args{"./CryptoGuard", "-i", "encrypted.txt", "-p", "1234", "--command", "decrypt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THROW(po.Parse(args.size(), const_cast<char **>(args.data())), std::invalid_argument);
}

TEST(ProgramOptions, BadDoubleOutput) {
    std::vector<const char *> args{"./CryptoGuard", "-i",        "encrypted.txt", "-o", "decrypted.txt", "-p",
                                   "1234",          "--command", "decrypt",       "-o", "decrypted2.txt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THROW(po.Parse(args.size(), const_cast<char **>(args.data())), boost::program_options::multiple_occurrences);
}

TEST(ProgramOptions, BadUnknownOption) {
    std::vector<const char *> args{"./CryptoGuard", "-i",        "encrypted.txt", "-o", "decrypted.txt", "-p",
                                   "1234",          "--command", "decrypt",       "-e", "decrypted2.txt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THROW(po.Parse(args.size(), const_cast<char **>(args.data())), boost::program_options::unknown_option);
}