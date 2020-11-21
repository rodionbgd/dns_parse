cmake_minimum_required(VERSION 3.1)
project(test_dns)

set(CMAKE_CXX_STANDARD 17)

include_directories(../src)
set(SOURCE_FILES main.cpp catch2/catch.hpp)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} dns_parse)