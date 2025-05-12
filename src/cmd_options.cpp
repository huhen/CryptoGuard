#include "cmd_options.h"

#include <iostream>
#include <print>
#include <string>

namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // clang-format off
    desc_.add_options()
        ("help", "Print this message and exit.")
        ("command,c", po::value<std::string>(), "Command [encrypt, decrypt, checksum].")
        ("input,i", po::value<std::string>(), "Input file path.")
        ("output,o", po::value<std::string>(), "Output file path.")
        ("password,p", po::value<std::string>(), "Password for encrypt and decrypt.")
    ;
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;

    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.contains("help")) {
        desc_.print(std::cout);
        return false;
    }

    if (const auto &it = vm.find("command"); it != vm.end()) {
        const auto &command = it->second.as<std::string>();
        if (const auto &it = commandMapping_.find(command); it != commandMapping_.end()) {
            command_ = it->second;
        } else {
            throw std::invalid_argument{std::format("the unknown argument for option '--command' '{}'", command)};
        }
    } else {
        throw std::invalid_argument{"the required option '--command' is missing"};
    }

    if (const auto &it = vm.find("input"); it != vm.end()) {
        inputFile_ = it->second.as<std::string>();
    } else {
        throw std::invalid_argument{"the required option '--input' is missing"};
    }

    if (const auto &it = vm.find("output"); it != vm.end()) {
        outputFile_ = it->second.as<std::string>();
    }

    if (const auto &it = vm.find("password"); it != vm.end()) {
        password_ = it->second.as<std::string>();
    }

    if (command_ == ProgramOptions::COMMAND_TYPE::CHECKSUM) {
        if (!outputFile_.empty()) {
            throw std::invalid_argument{"the option '--output' cannot be used"};
        }
        if (!password_.empty()) {
            throw std::invalid_argument{"the option '--password' cannot be used"};
        }
    } else {
        if (inputFile_ == outputFile_) {
            throw std::invalid_argument{"input and output file must not match"};
        }
        if (outputFile_.empty()) {
            throw std::invalid_argument{"the required option '--output' is missing"};
        }
        if (password_.empty()) {
            throw std::invalid_argument{"the required option '--password' is missing"};
        }
    }

    return true;
}

}  // namespace CryptoGuard
