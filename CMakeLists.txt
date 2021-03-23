project(cryptopals)
cmake_minimum_required(VERSION 3.15)

add_subdirectory(cryptolib)

enable_testing()
add_subdirectory(tests)