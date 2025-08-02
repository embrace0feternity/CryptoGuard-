#include "crypto_guard_ctx.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <array>
#include <vector>

namespace CryptoGuard {

    namespace detail {    

        struct AesCipherParams {
            static const size_t KEY_SIZE = 32;             // AES-256 key size
            static const size_t IV_SIZE = 16;              // AES block size (IV length)
            const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

            int encrypt;                              // 1 for encryption, 0 for decryption
            std::array<unsigned char, KEY_SIZE> key;  // Encryption key
            std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
        };

    }

    ///
    ///
    ///

    class CryptoGuardCtx::Impl {

        /// Returst only last error
        std::string GetEvpError() noexcept {
            auto errorCode = ERR_peek_last_error();
            return ERR_reason_error_string(errorCode);
        }

        detail::AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
            detail::AesCipherParams params;
            constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

            int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                        reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                        params.key.data(), params.iv.data());

            if (result == 0) {
                throw std::runtime_error{"Failed to create a key from password. " + GetEvpError()};
            }

            return params;
        }

        void DoCrypt(std::iostream &inStream, std::iostream &outStream, std::string_view password, int direction) {
            std::string input(
                (std::istreambuf_iterator<char>(inStream)),
                std::istreambuf_iterator<char>()
            );

            auto params = CreateChiperParamsFromPassword(password);
            params.encrypt = direction;

            auto ctx = std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX *)>(
                EVP_CIPHER_CTX_new(),
                [](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); }
            );

            if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
                throw std::runtime_error("Encryption/decryption initialization failed. " + GetEvpError());
            }

            std::vector<uint8_t> outbuf(input.size() + EVP_CIPHER_CTX_block_size(ctx.get()));
            int outlen = 0;
            int finallen = 0;

            if (!EVP_CipherUpdate(ctx.get(), outbuf.data(), &outlen, 
                    reinterpret_cast<const uint8_t*>(input.data()), input.size())) 
                    {
                throw std::runtime_error("Encryption/decryption update failed. " + GetEvpError());
            }

            outStream << reinterpret_cast<char*>(outbuf.data());

            if (!EVP_CipherFinal_ex(ctx.get(), outbuf.data() + outlen, &finallen)) {
                throw std::runtime_error("Encryption/decryption final failed. " + GetEvpError());
            }

            outStream << reinterpret_cast<char*>(outbuf.data() + outlen);
        }

    public:

        Impl() {
            OpenSSL_add_all_algorithms();
        }

        ~Impl() {
            EVP_cleanup();
        }


        void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
            DoCrypt(inStream, outStream, password, 1);            
        }

        void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
            DoCrypt(inStream, outStream, password, 0); 
        }

        std::string CalculateChecksum(std::iostream &inStream) { return "NOT IMPLEMENT"; }
    };

    ///
    ///
    ///

    CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
    CryptoGuardCtx::~CryptoGuardCtx() = default;
    CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
    CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

    void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        pImpl_->EncryptFile(inStream, outStream, password);
    }
    void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        pImpl_->DecryptFile(inStream, outStream, password);
    }
        
    std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }
}  // namespace CryptoGuard
