#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <iostream>
#include <fstream>
#include <print>
#include <stdexcept>
#include <string>
#include <sstream>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        std::cout << "input " << options.GetInputFile() << std::endl;
        std::cout << "output " << options.GetOutputFile() << std::endl;
        std::cout << "password " << options.GetPassword() << std::endl;
                auto c = options.GetCommand();
        std::cout << "command " << static_cast<int>(c) << std::endl;

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}