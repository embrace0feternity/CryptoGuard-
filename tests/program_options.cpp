#include "cmd_options.h"
#include <gtest/gtest.h>
#include <sstream>

struct MockProgramOptions : public CryptoGuard::ProgramOptions {
    void reset() {
        command_ = COMMAND_TYPE::INDEFINITE;
        inputFile_.clear();
        outputFile_.clear();
        password_.clear();
    }
};

class ProgramOptionsTestGroup : public testing::Test {
protected:
    MockProgramOptions programOptions;

    std::vector<char *> cmd(std::vector<std::string> &v) {
        std::vector<char *> c;
        for (auto &i : v) {
            static_assert(std::is_same_v<decltype(i.data()), char *>);
            c.push_back(i.data());
        }
        return c;
    }
};

TEST_F(ProgramOptionsTestGroup, Help) {
    std::stringstream ss;
    auto interceptedBuf = std::cout.rdbuf();
    std::cout.rdbuf(ss.rdbuf());

    std::vector<std::string> options = {"", "--help"};

    auto t = cmd(options);
    programOptions.Parse(options.size(), t.data());
    std::cout.rdbuf(interceptedBuf);
    
    auto interceptedData = ss.str();
    ASSERT_TRUE(interceptedData.find("--input") != std::string::npos);
    ASSERT_TRUE(interceptedData.find("--output") != std::string::npos);
    ASSERT_TRUE(interceptedData.find("--command") != std::string::npos);
    ASSERT_TRUE(interceptedData.find("encrypt") != std::string::npos);
    ASSERT_TRUE(interceptedData.find("dummy string") == std::string::npos);
    ASSERT_TRUE(programOptions.GetInputFile().empty());
    ASSERT_TRUE(programOptions.GetOutputFile().empty());
    ASSERT_TRUE(programOptions.GetPassword().empty());
    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::HELP, programOptions.GetCommand());
}

TEST_F(ProgramOptionsTestGroup, Input) {
    std::string expectedFile = "./secretFile";
    std::vector<std::string> options = {"", "--input", expectedFile};

    programOptions.Parse(options.size(), cmd(options).data());
    auto inputFile = programOptions.GetInputFile();

    ASSERT_EQ(expectedFile, inputFile);
    ASSERT_TRUE(programOptions.GetOutputFile().empty());
    ASSERT_TRUE(programOptions.GetOutputFile().empty());
    ASSERT_TRUE(programOptions.GetPassword().empty());
    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::INDEFINITE, programOptions.GetCommand());
    ///
    ///
    ///
    programOptions.reset();

    options[1] = "-i";

    programOptions.Parse(options.size(), cmd(options).data());
    inputFile = programOptions.GetInputFile();
    ASSERT_EQ(expectedFile, inputFile);
    ASSERT_TRUE(programOptions.GetOutputFile().empty());
    ASSERT_TRUE(programOptions.GetPassword().empty());
    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::INDEFINITE, programOptions.GetCommand());
}

TEST_F(ProgramOptionsTestGroup, Output) {
    std::string expectedFile = "./secretFile";
    std::vector<std::string> options = {"", "--output", expectedFile};

    programOptions.Parse(options.size(), cmd(options).data());
    auto outputFile = programOptions.GetOutputFile();

    ASSERT_EQ(expectedFile, outputFile);
    ASSERT_TRUE(programOptions.GetInputFile().empty());
    ASSERT_TRUE(programOptions.GetPassword().empty());
    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::INDEFINITE, programOptions.GetCommand());
    ///
    ///
    ///
    programOptions.reset();
    options[1] = "-o";

    programOptions.Parse(options.size(), cmd(options).data());
    outputFile = programOptions.GetOutputFile();

    ASSERT_EQ(expectedFile, outputFile);
    ASSERT_TRUE(programOptions.GetInputFile().empty());
    ASSERT_TRUE(programOptions.GetPassword().empty());
    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::INDEFINITE, programOptions.GetCommand());
}

TEST_F(ProgramOptionsTestGroup, Password) {
    std::string expectedPassword = "12345-54321";
    std::vector<std::string> options = {"", "--password", expectedPassword};

    programOptions.Parse(options.size(), cmd(options).data());
    auto password = programOptions.GetPassword();

    ASSERT_EQ(expectedPassword, password);
    ASSERT_TRUE(programOptions.GetInputFile().empty());
    ASSERT_TRUE(programOptions.GetOutputFile().empty());
    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::INDEFINITE, programOptions.GetCommand());
    ///
    ///
    ///
    programOptions.reset();
    options[1] = "-p";

    programOptions.Parse(options.size(), cmd(options).data());
    password = programOptions.GetPassword();

    ASSERT_EQ(expectedPassword, password);
    ASSERT_TRUE(programOptions.GetInputFile().empty());
    ASSERT_TRUE(programOptions.GetOutputFile().empty());
    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::INDEFINITE, programOptions.GetCommand());
}

TEST_F(ProgramOptionsTestGroup, CommandType) {
    std::vector<std::string> options = {"", "--command", "encrypt"};

    programOptions.Parse(options.size(), cmd(options).data());
    auto c = programOptions.GetCommand();

    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT, c);
    ASSERT_TRUE(programOptions.GetInputFile().empty());
    ASSERT_TRUE(programOptions.GetOutputFile().empty());
    ASSERT_TRUE(programOptions.GetPassword().empty());
    ///
    ///
    ///
    programOptions.reset();
    options[1] = "-c";
    options[2] = "decrypt";

    programOptions.Parse(options.size(), cmd(options).data());
    c = programOptions.GetCommand();

    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT, c);
    ASSERT_TRUE(programOptions.GetInputFile().empty());
    ASSERT_TRUE(programOptions.GetOutputFile().empty());
    ASSERT_TRUE(programOptions.GetPassword().empty());
    ///
    ///
    ///
    programOptions.reset();
    options[2] = "checksum";

    programOptions.Parse(options.size(), cmd(options).data());
    c = programOptions.GetCommand();

    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM, c);
    ASSERT_TRUE(programOptions.GetInputFile().empty());
    ASSERT_TRUE(programOptions.GetOutputFile().empty());
    ASSERT_TRUE(programOptions.GetPassword().empty());
    ///
    ///
    ///
    programOptions.reset();
    options[2] = "non-existent";
    ASSERT_THROW(
        { programOptions.Parse(options.size(), cmd(options).data()); }, 
        std::runtime_error
    );
}

TEST_F(ProgramOptionsTestGroup, Command) {
    std::string file_1 = "./secretFile";
    std::string file_2 = "./nonSecretFile";
    std::vector<std::string> options = {"", "--input", file_1, "-o", file_2, "-p", "7294", "--command", "checksum"};

    programOptions.Parse(options.size(), cmd(options).data());

    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM, programOptions.GetCommand());
    ASSERT_EQ(file_1, programOptions.GetInputFile());
    ASSERT_EQ(file_2, programOptions.GetOutputFile());
    ASSERT_EQ("7294", programOptions.GetPassword());
    ///
    ///
    ///
    programOptions.reset();
    options[2] = file_2;
    options[4] = file_1;
    options.back() = "encrypt";

    programOptions.Parse(options.size(), cmd(options).data());
        ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT, programOptions.GetCommand());
    ASSERT_EQ(file_2, programOptions.GetInputFile());
    ASSERT_EQ(file_1, programOptions.GetOutputFile());
    ASSERT_EQ("7294", programOptions.GetPassword());
    ///
    ///
    ///
    /// Corrupt --input to see what happens
    programOptions.reset();
    options[1] = "++input";

    programOptions.Parse(options.size(), cmd(options).data());
    ASSERT_EQ(CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT, programOptions.GetCommand());
    ASSERT_TRUE(programOptions.GetInputFile().empty());
    ASSERT_EQ(file_1, programOptions.GetOutputFile());
    ASSERT_EQ("7294", programOptions.GetPassword());
}