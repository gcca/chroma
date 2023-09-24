cmake_minimum_required(VERSION 3.27)

project(chroma VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

find_package(GTest REQUIRED)
enable_testing()

add_executable(chroma-playground chroma_playground.cc)
target_link_libraries(chroma-playground GTest::gtest_main gmp)

include(GoogleTest)
gtest_discover_tests(chroma-playground)
