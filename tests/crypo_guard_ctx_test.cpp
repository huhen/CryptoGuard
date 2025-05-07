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