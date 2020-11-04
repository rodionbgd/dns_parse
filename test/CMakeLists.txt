cmake_minimum_required(VERSION 3.14)
project(test_dns)

set(CMAKE_CXX_STANDARD 17)

include_directories(../src)
link_directories(..)
set(SOURCE_FILES main.cpp catch.hpp)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} dns_parse)