#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard {

namespace po = boost::program_options;
/// help
/// command
/// input
/// output
/// password
ProgramOptions::ProgramOptions() : command_(COMMAND_TYPE::INDEFINITE), inputFile_(""), outputFile_(""), password_(""), 
desc_("Allowed options") {
    desc_.add_options()("help", "show help message")("command,c", po::value<std::string>(),
                                                     "perform an action:\n"
                                                     "    encrypt\n"
                                                     "    decrypt\n"
                                                     "    checksum\n")("input,i", po::value<std::string>(),
                                                                       "input file path")(
        "output,o", po::value<std::string>(), "output file path")("password,p", po::value<std::string>(),
                                                                  "password for encrypting and decrypting");
                                                                  }

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    store(parse_command_line(argc, argv, desc_), vm);
    notify(vm);

    if (vm.count("help")) {
        command_ = COMMAND_TYPE::HELP;
        std::cout << desc_ << std::endl;
    }
    else {
        if (vm.count("command")) {
            auto it = commandMapping_.find(vm["command"].as<std::string>());
            if (it == commandMapping_.end()) {
                throw std::runtime_error("Error: invalid command type");
            }
            command_ = commandMapping_.at(vm["command"].as<std::string>());
        }

        if (vm.count("input")) {
            inputFile_ = vm["input"].as<std::string>();
        }

        if (vm.count("output")) {
            outputFile_ = vm["output"].as<std::string>();
        }

        if (vm.count("password")) {
            password_ = vm["password"].as<std::string>();
        }
    }
}
}  // namespace CryptoGuard
