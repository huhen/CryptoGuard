#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>

static std::fstream GetInStream(const std::string &inFileName) {
    std::fstream inStream(inFileName, std::ios::in | std::ios::binary);
    if (!inStream) {
        throw std::runtime_error{std::format("Failed to open input file:{}", inFileName)};
    }

    return inStream;
};

static std::fstream GetOutStream(const std::string &outFileName) {
    std::fstream outStream(outFileName, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!outStream) {
        throw std::runtime_error{std::format("Failed to open output file:{}", outFileName)};
    }

    return outStream;
};

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        if (!options.Parse(argc, argv)) {
            return 1;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            auto inStream = GetInStream(options.GetInputFile());
            auto outStream = GetOutStream(options.GetOutputFile());

            cryptoCtx.EncryptFile(inStream, outStream, options.GetPassword());

            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            auto inStream = GetInStream(options.GetInputFile());
            auto outStream = GetOutStream(options.GetOutputFile());

            cryptoCtx.DecryptFile(inStream, outStream, options.GetPassword());

            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            auto inStream = GetInStream(options.GetInputFile());

            auto checksum = cryptoCtx.CalculateChecksum(inStream);

            std::print("Checksum: {}\n", checksum);
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
