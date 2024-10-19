cmake_minimum_required(VERSION 3.10)

project(encryption_tool)
set(CMAKE_C_STANDARD 99)

find_package(OpenSSL REQUIRED)

add_executable(encryption_tool main.c encrdecr.c keygeneration.c)

target_link_libraries(encryption_tool OpenSSL::SSL OpenSSL::Crypto)
