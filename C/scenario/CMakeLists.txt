cmake_minimum_required(VERSION 3.15)
project(scenario C)

set(CMAKE_C_STANDARD 99)
file(GLOB sources "*.c")
add_library(scenario ${sources} 11.c 11.h 12.c 12.h 14.c 14.h 16.c 16.h)
target_link_libraries(cryptopals)