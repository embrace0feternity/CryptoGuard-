#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <print>
#include <stdexcept>
#include <filesystem>



int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        CryptoGuard::CryptoGuardCtx ctx;
        switch (options.GetCommand())
        {
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT:
        {
            auto inFileName = options.GetInputFile();
            if (!std::filesystem::exists(inFileName)) {
                throw std::runtime_error("File does not exist: " + inFileName);
            }
            auto outFileName = options.GetOutputFile();
            if (!std::filesystem::exists(outFileName)) {
                throw std::runtime_error("File does not exist: " + outFileName);
            }
            std::fstream in(inFileName, std::ios::in | std::ios::binary);
            std::fstream out(outFileName, std::ios::out | std::ios::binary);
            if (!(in.is_open() | out.is_open())) {
                throw std::runtime_error("file open problem");        
            }
            ctx.EncryptFile(in, out, options.GetPassword());
        }
            break;
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT:
        {
            auto inFileName = options.GetInputFile();
            if (!std::filesystem::exists(inFileName)) {
                throw std::runtime_error("File does not exist: " + inFileName);
            }
            auto outFileName = options.GetOutputFile();
            if (!std::filesystem::exists(outFileName)) {
                throw std::runtime_error("File does not exist: " + outFileName);
            }
            std::fstream in(inFileName, std::ios::in | std::ios::binary);
            std::fstream out(outFileName, std::ios::out | std::ios::binary);
            if (!(in.is_open() | out.is_open())) {
                throw std::runtime_error("file open problem");        
            }
            ctx.DecryptFile(in, out, options.GetPassword());
        }
            break;
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM:
        {
            auto inFileName = options.GetInputFile();
            if (!std::filesystem::exists(inFileName)) {
                throw std::runtime_error("File does not exist: " + inFileName);
            }
            std::fstream in(inFileName, std::ios::in | std::ios::binary);
            if (!(in.is_open())) {
                throw std::runtime_error("file open problem");        
            }
            std::print(std::cout, "Cs: {}\n", ctx.CalculateChecksum(in));
        }
            break;
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::HELP:
            /// do nothing :)
            break;
        default:
            throw std::runtime_error("invalid command");  
            break;
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}