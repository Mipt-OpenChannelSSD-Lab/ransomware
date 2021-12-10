cmake_minimum_required(VERSION 3.21)
project(ransomware)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(src/third-party/cxxopts)
add_subdirectory(src/third-party/fmt)

add_executable(ransomware
    src/main.cpp
    src/ransomware.cpp
)
target_include_directories(ransomware PRIVATE include)

target_link_libraries(ransomware PRIVATE cxxopts::cxxopts)
target_link_libraries(ransomware PRIVATE fmt)
target_link_libraries(ransomware PRIVATE stdc++fs)
