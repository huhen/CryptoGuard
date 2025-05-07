#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        if (!options.Parse(argc, argv)) {
            return 1;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            std::print("File encoded successfully\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}