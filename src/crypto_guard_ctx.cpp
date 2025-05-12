#include "crypto_guard_ctx.h"

#include <array>
#include <iomanip>
#include <ios>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <vector>

namespace CryptoGuard {

using EvpCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;
using EvpMdCtx = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

constexpr size_t BUFFER_SIZE = 4096;

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    Impl() {
        // Deprecated in OpenSSL 1.1.0+ and should not be used.
        OpenSSL_add_all_algorithms();
    }

    ~Impl() {
        // Deprecated in OpenSSL 1.1.0+ and should not be used.
        EVP_cleanup();
    }

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;

    Impl(Impl &&) noexcept = default;
    Impl &operator=(Impl &&) noexcept = default;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
        ProcessFile(inStream, outStream, CreateChiperParamsFromPassword(password, true));
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
        ProcessFile(inStream, outStream, CreateChiperParamsFromPassword(password, false));
    }

    std::string CalculateChecksum(std::iostream &inStream) const {
        EvpMdCtx ctx{EVP_MD_CTX_new()};

        if (!ctx) {
            throw std::runtime_error{std::format("Message digest create failed\nOpenSSL {}", GetOpenSslErrorMessage())};
        }

        if (!EVP_DigestInit_ex2(ctx.get(), EVP_sha256(), NULL)) {
            throw std::runtime_error{
                std::format("Message digest initialization failed\nOpenSSL {}", GetOpenSslErrorMessage())};
        }

        std::vector<unsigned char> inBuf(BUFFER_SIZE);

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE);
            auto bytesRead = inStream.gcount();

            if (bytesRead > 0) {
                if (!EVP_DigestUpdate(ctx.get(), inBuf.data(), static_cast<size_t>(bytesRead))) {
                    throw std::runtime_error{
                        std::format("Message digest update failed\nOpenSSL {}", GetOpenSslErrorMessage())};
                }
            }
        }

        if (!inStream.eof()) {
            throw std::runtime_error{"Error occurred while reading from input stream"};
        }

        unsigned int md_len;
        std::array<unsigned char, EVP_MAX_MD_SIZE> md_value;
        if (!EVP_DigestFinal_ex(ctx.get(), md_value.data(), &md_len)) {
            throw std::runtime_error{
                std::format("Message digest finalization failed\nOpenSSL {}", GetOpenSslErrorMessage())};
        }

        std::stringstream ss;
        ss << std::hex << std::uppercase;

        for (size_t i = 0; i != md_len; ++i) {
            ss << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);
        }

        return ss.str();
    }

private:
    static std::string GetOpenSslErrorMessage() {
        std::array<char, ERR_MAX_DATA_SIZE> buff;

        auto e = ERR_get_error();
        ERR_error_string_n(e, buff.data(), buff.size());

        return std::string(buff.data());
    }

    static void ProcessFile(std::iostream &inStream, std::iostream &outStream, const AesCipherParams &params) {
        if (&inStream == &outStream) {
            throw std::runtime_error{"Input and output streams must not match"};
        }

        EvpCipherCtx ctx{EVP_CIPHER_CTX_new()};
        if (!ctx) {
            throw std::runtime_error{
                std::format("Failed to create cipher context\nOpenSSL {}", GetOpenSslErrorMessage())};
        }

        // Инициализируем cipher
        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error{
                std::format("Failed to initialize cipher context\nOpenSSL {}", GetOpenSslErrorMessage())};
        }

        std::vector<unsigned char> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(BUFFER_SIZE);

        int outLen;

        auto write_data = [&](const unsigned char *data, int length) {
            if (length > 0) {
                outStream.write(reinterpret_cast<const char *>(data), length);
                if (!outStream) {
                    throw std::runtime_error{"Error occurred while writing to output stream"};
                }
            }
        };

        while (inStream) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE);
            int bytesRead = static_cast<int>(inStream.gcount());

            if (bytesRead > 0) {
                // Обрабатываем данные
                if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), bytesRead)) {
                    throw std::runtime_error{std::format("Cipher update failed\nOpenSSL {}", GetOpenSslErrorMessage())};
                }

                write_data(outBuf.data(), outLen);
            }
        }

        if (!inStream.eof()) {
            throw std::runtime_error{"Error occurred while reading from input stream"};
        }

        // Заканчиваем работу с cipher
        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error{std::format("Cipher finalization failed\nOpenSSL {}", GetOpenSslErrorMessage())};
        }

        write_data(outBuf.data(), outLen);
    }

    static AesCipherParams CreateChiperParamsFromPassword(std::string_view password, bool isEncrypt) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{
                std::format("Failed to create a key from password\nOpenSSL {}", GetOpenSslErrorMessage())};
        }

        params.encrypt = isEncrypt ? 1 : 0;

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const {
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
