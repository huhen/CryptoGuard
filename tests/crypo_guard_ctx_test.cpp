#include <gtest/gtest.h>
#include <sstream>

#include "../include/crypto_guard_ctx.h"

TEST(CryptoGuardCtx, EncryptEmptyInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{""};
    std::stringstream ostream;

    ctx.EncryptFile(istream, ostream, "1234");

    EXPECT_NE(istream.str(), ostream.str());
}

TEST(CryptoGuardCtx, EncryptEmptyPassword) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::stringstream ostream;

    ctx.EncryptFile(istream, ostream, "");

    EXPECT_NE(istream.str(), ostream.str());
}

TEST(CryptoGuardCtx, EncryptShortInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::stringstream ostream;

    ctx.EncryptFile(istream, ostream, "1234");

    EXPECT_NE(istream.str(), ostream.str());
}

TEST(CryptoGuardCtx, EncryptLongInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream;
    std::stringstream ostream;

    for (int i = 0; i != 4096; ++i) {
        istream << "12341234";
    }

    ctx.EncryptFile(istream, ostream, "1234");

    EXPECT_NE(istream.str(), ostream.str());
}

TEST(CryptoGuardCtx, EncryptBadInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::stringstream ostream;

    istream.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.EncryptFile(istream, ostream, "1234"), std::runtime_error);
}

TEST(CryptoGuardCtx, EncryptBadOutput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::stringstream ostream;

    ostream.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.EncryptFile(istream, ostream, "1234"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptBadInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::stringstream estream;
    std::stringstream ostream;

    ctx.EncryptFile(istream, estream, "1234");

    estream.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.DecryptFile(estream, ostream, "1234"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptBadOutput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::stringstream estream;
    std::stringstream ostream;

    ctx.EncryptFile(istream, estream, "1234");

    ostream.setstate(std::ios::badbit);

    ASSERT_THROW(ctx.DecryptFile(estream, ostream, "1234"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptEmptyInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{""};
    std::stringstream ostream;

    ASSERT_THROW(ctx.DecryptFile(istream, ostream, "1234"), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptEmptyPassword) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::stringstream estream;
    std::stringstream ostream;

    ctx.EncryptFile(istream, estream, "");

    ctx.DecryptFile(estream, ostream, "");

    EXPECT_EQ(istream.str(), ostream.str());
}

TEST(CryptoGuardCtx, DecryptShortInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::stringstream estream;
    std::stringstream ostream;

    ctx.EncryptFile(istream, estream, "1234");

    ctx.DecryptFile(estream, ostream, "1234");

    EXPECT_EQ(istream.str(), ostream.str());
}

TEST(CryptoGuardCtx, DecryptLongInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream;
    std::stringstream estream;
    std::stringstream ostream;

    for (int i = 0; i != 4096; ++i) {
        istream << "12341234";
    }

    ctx.EncryptFile(istream, estream, "1234");

    ctx.DecryptFile(estream, ostream, "1234");

    EXPECT_EQ(istream.str(), ostream.str());
}

TEST(CryptoGuardCtx, DecryptWrongPassword) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::stringstream estream;
    std::stringstream ostream;

    ctx.EncryptFile(istream, estream, "1234");

    ASSERT_THROW(
        {
            ctx.DecryptFile(estream, ostream, "1233");
            if (istream.str() != ostream.str()) {
                throw std::runtime_error("Password mismatch");
            }
        },
        std::runtime_error);
}

TEST(CryptoGuardCtx, ChecksumEmptyInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{""};
    std::string actual{"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"};

    std::string expected = ctx.CalculateChecksum(istream);
    EXPECT_EQ(actual, expected);
}

TEST(CryptoGuardCtx, ChecksumShortInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};
    std::string actual{"1718C24B10AEB8099E3FC44960AB6949AB76A267352459F203EA1036BEC382C2"};

    std::string expected = ctx.CalculateChecksum(istream);
    EXPECT_EQ(actual, expected);
}

TEST(CryptoGuardCtx, ChecksumBadInput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream istream{"12341234"};

    istream.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.CalculateChecksum(istream), std::runtime_error);
}