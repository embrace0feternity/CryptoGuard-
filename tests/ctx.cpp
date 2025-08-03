#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>

class CtxTestGroup : public testing::Test {
protected:
    CryptoGuard::ProgramOptions programOptions;
    CryptoGuard::CryptoGuardCtx ctx;
};

TEST_F(CtxTestGroup, EncryptDecrypt) {
    std::string data = "secret data";
    std::stringstream in (data);
    std::stringstream encrypted;
    std::stringstream decrypted;
    std::string password = "gohpfoghpslf";

    ASSERT_NO_THROW({ ctx.EncryptFile(in, encrypted, password); });
    std::string encryptedData = encrypted.str();
    ASSERT_TRUE(encryptedData.size() > 0);

    ASSERT_NO_THROW({ ctx.DecryptFile(encrypted, decrypted, password); });
    std::string decryptedData = decrypted.str();
    std::cout << "decrypted " << decryptedData << std::endl;
    ASSERT_EQ(data, decryptedData);
}

TEST_F(CtxTestGroup, EncryptEmpty) {
    std::string data = "";
    std::stringstream in (data);
    std::stringstream encrypted;
    std::stringstream decrypted;
    std::string password = "";

    ASSERT_NO_THROW({ ctx.EncryptFile(in, encrypted, password); });
    std::string encryptedData = encrypted.str();
    ASSERT_TRUE(encryptedData.size() > 0);

    ASSERT_NO_THROW({ ctx.DecryptFile(encrypted, decrypted, password); });
    std::string decryptedData = decrypted.str();
    ASSERT_EQ(data, decryptedData);
}

TEST_F(CtxTestGroup, EncryptDifferentPassword) {
    std::string data = "secret data";
    std::stringstream in (data);
    std::stringstream encrypted;
    std::stringstream decrypted;

    ASSERT_NO_THROW({ ctx.EncryptFile(in, encrypted, "password"); });
    std::string encryptedData_1 = encrypted.str();
    ASSERT_TRUE(encryptedData_1.size() > 0);

    ASSERT_NO_THROW({ ctx.EncryptFile(in, encrypted, "pAsSwOrD"); });
    std::string encryptedData_2 = encrypted.str();
    ASSERT_TRUE(encryptedData_2.size() > 0);
    ASSERT_NE(encryptedData_1, encryptedData_2);
}

///
///
///

TEST_F(CtxTestGroup, DecryptCorruptedPassword) {
    std::string data = "mkfedp  pfdg543gdh   4       [;ewrfdssombmg fdsdsff7r5gefhv3]";
    std::stringstream in (data);
    std::stringstream encrypted;
    std::stringstream decrypted;
    std::string password = "qwer";

    ASSERT_NO_THROW({ ctx.EncryptFile(in, encrypted, password); });
    std::string encryptedData = encrypted.str();
    ASSERT_TRUE(encryptedData.size() > 0);

    password.back() = 'R';
    ASSERT_THROW({ ctx.DecryptFile(encrypted, decrypted, password); }, std::runtime_error);
    std::string decryptedData = decrypted.str();
    ASSERT_NE(data, decryptedData);
}

TEST_F(CtxTestGroup, DecryptCorruptedData) {
    std::string data (100'000, 'Q');
    std::stringstream in (data);
    std::stringstream encrypted;
    std::stringstream decrypted;
    std::string password = "qwer";

    ASSERT_NO_THROW({ ctx.EncryptFile(in, encrypted, password); });
    std::string encryptedData = encrypted.str();
    ASSERT_TRUE(encryptedData.size() > 0);
    auto lastChar = encryptedData.back();
    if (lastChar == 255) {
        lastChar = 0;
    } else {
        lastChar += 1;
    }
    encryptedData.back() = lastChar;
    encrypted.clear();
    encrypted << encryptedData;

    ASSERT_THROW({ ctx.DecryptFile(encrypted, decrypted, password); }, std::runtime_error);
}

TEST_F(CtxTestGroup, DecryptChoppedData) {
    std::string data = "ofdg hbkgfh od54om  fds10";
    std::stringstream in (data);
    std::stringstream encrypted;
    std::stringstream decrypted;
    std::string password = "qwer";

    ASSERT_NO_THROW({ ctx.EncryptFile(in, encrypted, password); });
    std::string encryptedData = encrypted.str();
    ASSERT_TRUE(encryptedData.size() > 0);

    encryptedData.pop_back();
    encryptedData.pop_back();
    encryptedData.pop_back();
    encryptedData.pop_back();
    encrypted.clear();
    encrypted << encryptedData;

    ASSERT_THROW({ ctx.DecryptFile(encrypted, decrypted, password); }, std::runtime_error);
}

///
///
///

TEST_F(CtxTestGroup, Checksum) {
    std::string data = "data";
    std::stringstream in (data);

    ASSERT_NO_THROW({ ctx.CalculateChecksum(in); });
    auto cs = ctx.CalculateChecksum(in);
    ASSERT_TRUE(cs.size() > 0);
}

TEST_F(CtxTestGroup, ChecksumDifferentInputs) {
    std::string data = "data";
    std::stringstream in (data);

    auto cs_1 = ctx.CalculateChecksum(in);
    ASSERT_TRUE(cs_1.size() > 0);

    data.back() = 'A';
    in.clear();
    in << data;

    auto cs_2 = ctx.CalculateChecksum(in);
    ASSERT_TRUE(cs_2.size() > 0);
    ASSERT_FALSE(cs_2 == cs_1);
}

TEST_F(CtxTestGroup, ChecksumEmptyInput) {
    std::string data = "";
    std::stringstream in (data);

    auto cs_1 = ctx.CalculateChecksum(in);
    ASSERT_TRUE(cs_1.size() > 0);

    auto cs_2 = ctx.CalculateChecksum(in);
    ASSERT_TRUE(cs_2.size() > 0);
    ASSERT_TRUE(cs_2 == cs_1);
}