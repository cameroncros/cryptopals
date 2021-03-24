file(GLOB sources "*.cpp")
add_executable(cryptopals_tests ${sources})
target_link_libraries(cryptopals_tests cryptopals gtest gtest_main)
file(GLOB test_sources "*.txt")
foreach(test_src ${test_sources})
    file(COPY ${test_src}
            DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endforeach()
add_test(cryptopals_tests cryptopals_tests)