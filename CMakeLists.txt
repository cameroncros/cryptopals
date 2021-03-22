cmake_minimum_required(VERSION 3.15)
project(cryptopals C)

set(CMAKE_C_STANDARD 99)

add_executable(cryptopals main.c base64.c hex.c validate.c xor.c)
target_link_libraries(cryptopals m ssl crypto)