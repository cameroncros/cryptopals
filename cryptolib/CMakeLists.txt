cmake_minimum_required(VERSION 3.15)
project(cryptopals C)

set(CMAKE_C_STANDARD 99)
file(GLOB sources "*.c")
add_library(cryptopals ${sources})
target_link_libraries(cryptopals m ssl crypto)