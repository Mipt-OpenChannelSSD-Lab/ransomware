#include <string>
#include <iostream>
#include <cstdlib>

#include <cxxopts.hpp>
#include <fmt/format.h>

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

    std::cout << fmt::format("Root directory for encryption: {}\n", result["root"].as<std::string>());

    return 0;
}
