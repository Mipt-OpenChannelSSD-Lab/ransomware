cmake_minimum_required(VERSION 3.16)
project(ransomware)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_subdirectory(src/third-party/cxxopts)
add_subdirectory(src/third-party/fmt)

add_executable(ransomware
        src/main.cpp
        src/ransomware.cpp
        )
target_include_directories(ransomware PRIVATE include ${OPENSSL_INCLUDE_DIR})

target_link_libraries(ransomware PRIVATE cxxopts::cxxopts)
target_link_libraries(ransomware PRIVATE fmt)
target_link_libraries(ransomware PRIVATE stdc++fs)
target_link_libraries(ransomware PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(ransomware PRIVATE ${OPENSSL_SSL_LIBRARY})
